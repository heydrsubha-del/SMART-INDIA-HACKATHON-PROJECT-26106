"""
SIH26106 - Real ClamAV antivirus scanning via the clamd daemon.

Talks directly to a running clamd daemon over TCP using clamd's native
INSTREAM protocol, so attachments are scanned in memory - no temp files, and
no extra pip dependency (pyclamd). Just the standard-library `socket` module.

If your clamd isn't on the default host/port, set:
    SIH26106_CLAMD_HOST (default 127.0.0.1)
    SIH26106_CLAMD_PORT (default 3310)

Every function fails soft (returns a dict with "ok": False, or False, or [])
instead of raising, so a stopped or unreachable clamd daemon never breaks
the rest of the app - the UI falls back to the existing risky-extension
heuristic when this is unavailable.
"""
import os
import socket

CLAMD_HOST = os.getenv("SIH26106_CLAMD_HOST", "127.0.0.1")
CLAMD_PORT = int(os.getenv("SIH26106_CLAMD_PORT", "3310"))
CLAMD_TIMEOUT = 15


def _connect(timeout=CLAMD_TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((CLAMD_HOST, CLAMD_PORT))
    return sock


def clamd_available(timeout=2):
    """True only when the clamd daemon answers PING with PONG."""
    try:
        sock = _connect(timeout=timeout)
        sock.sendall(b"PING\0")
        response = sock.recv(64)
        sock.close()
        return b"PONG" in response
    except Exception:
        return False


def clamd_version():
    """Return clamd's raw VERSION reply (engine + signature DB build date),
    or None if the daemon can't be reached. Never raises."""
    try:
        sock = _connect(timeout=3)
        sock.sendall(b"VERSION\0")
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()
        text = b"".join(chunks).decode("utf-8", errors="replace").strip().strip("\0")
        return text or None
    except Exception:
        return None


def scan_bytes(data, timeout=CLAMD_TIMEOUT):
    """Scan raw bytes in memory using clamd's zINSTREAM command.

    Returns {"ok": True, "infected": bool, "signature": str|None, "raw": str}
    or {"ok": False, "error": ...}. Never raises.
    """
    if not data:
        return {"ok": True, "infected": False, "signature": None, "raw": "empty"}
    try:
        sock = _connect(timeout=timeout)
        sock.sendall(b"zINSTREAM\0")

        # clamd wants <4-byte big-endian length><chunk> frames, ending with
        # a zero-length frame.
        chunk_size = 8192
        for offset in range(0, len(data), chunk_size):
            chunk = data[offset:offset + chunk_size]
            sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
        sock.sendall((0).to_bytes(4, "big"))

        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()

        reply = b"".join(chunks).decode("utf-8", errors="replace").strip().strip("\0")
        if reply.endswith("OK"):
            return {"ok": True, "infected": False, "signature": None, "raw": reply}
        if "FOUND" in reply:
            signature = reply.split(":", 1)[-1].replace("FOUND", "").strip()
            return {"ok": True, "infected": True, "signature": signature, "raw": reply}
        return {"ok": False, "error": reply or "Unrecognised clamd response."}
    except ConnectionRefusedError:
        return {"ok": False, "error": "Could not connect to clamd. Is the ClamAV daemon running?"}
    except socket.timeout:
        return {"ok": False, "error": "ClamAV scan timed out."}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def scan_attachments(parsed):
    """Scan every attachment on a parsed email via clamd.

    Returns a list of {filename, size, infected, signature, error} dicts,
    one per attachment, so the UI still shows partial results if clamd
    fails on one attachment but not another.
    """
    results = []
    for att in (parsed.get("attachments") or []):
        data = att.get("data") or b""
        outcome = scan_bytes(data)
        results.append({
            "filename": att.get("filename", "-"),
            "size": att.get("size", 0),
            "infected": outcome.get("infected", False),
            "signature": outcome.get("signature"),
            "error": None if outcome.get("ok") else outcome.get("error"),
        })
    return results