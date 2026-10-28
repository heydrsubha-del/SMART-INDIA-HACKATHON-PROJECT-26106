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
import hashlib
import io
import os
import socket
import time
import zipfile

import requests

from cloud_backend import BackendError, is_usable, resolve_backend

CLAMD_HOST = os.getenv("SIH26106_CLAMD_HOST", "127.0.0.1")
CLAMD_PORT = int(os.getenv("SIH26106_CLAMD_PORT", "3310"))
CLAMD_TIMEOUT = 15

VT_API_KEY_VAR = "SIH26106_VT_API_KEY"
VT_BASE = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 30
# Bounded polling for freshly-uploaded files: VirusTotal's own engines can
# take anywhere from a few seconds to a couple of minutes. If the analysis
# is still queued when we give up, we return ok: False (never a false
# "clean") so the caller's existing fallback-of-a-fallback still applies.
VT_POLL_INTERVAL = 3
VT_POLL_MAX_ATTEMPTS = 20


def _env_int(name, default):
    try:
        return max(1, int(os.getenv(name, default)))
    except (TypeError, ValueError):
        return default


# Scanning limits (clamd's own StreamMaxLength defaults to 25 MB; VirusTotal's direct upload limit is 32 MB).
MAX_SCAN_BYTES = _env_int("SIH26106_MAX_SCAN_BYTES", 25 * 1024 * 1024)
MAX_SCAN_FILES = _env_int("SIH26106_MAX_SCAN_FILES", 25)
MAX_SCAN_TOTAL_BYTES = _env_int("SIH26106_MAX_SCAN_TOTAL_BYTES", 40 * 1024 * 1024)
CLAMD_TOTAL_DEADLINE = 60                    # wall-clock cap for one clamd stream
# ZIP-bomb guards (central directory is inspected only; nothing is ever extracted).
ZIP_MAX_ENTRIES = 1000
ZIP_MAX_UNCOMPRESSED = 1024 * 1024 * 1024    # 1 GiB declared
ZIP_MAX_RATIO = 200                          # declared uncompressed / compressed


def inspect_zip(data):
    """Return a reason string if `data` is a ZIP that looks like a bomb, else None. Metadata only; never raises."""
    if not data or data[:2] != b"PK":
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > ZIP_MAX_ENTRIES:
                return "ZIP has too many entries (%d)" % len(infos)
            total = sum(i.file_size for i in infos)
            packed = max(sum(i.compress_size for i in infos), 1)
            if total > ZIP_MAX_UNCOMPRESSED:
                return "ZIP declares an excessive uncompressed size"
            if total / packed > ZIP_MAX_RATIO and total > 10 * 1024 * 1024:
                return "ZIP compression ratio is suspiciously high"
            for i in infos:                  # nested archives are the classic recursive bomb
                if i.filename.lower().endswith((".zip", ".7z", ".rar", ".gz", ".bz2", ".xz")) and i.file_size > 10 * 1024 * 1024:
                    return "ZIP contains a large nested archive"
    except (zipfile.BadZipFile, RuntimeError, ValueError, NotImplementedError, OSError):
        return None                          # not a readable ZIP: let the scanner decide
    except Exception:
        return None
    return None


def _blocked_reason(data):
    if len(data) > MAX_SCAN_BYTES:
        return "File exceeds the %d MB scan limit; not scanned." % (MAX_SCAN_BYTES // (1024 * 1024))
    bomb = inspect_zip(data)
    if bomb:
        return "Not scanned (possible archive bomb): %s." % bomb
    return None


def _connect(timeout=CLAMD_TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((CLAMD_HOST, CLAMD_PORT))
    return sock


def clamd_available(timeout=2):
    """True only when the clamd daemon answers PING with PONG.
    Local-only probe -- for UI gates, use antivirus_usable() instead,
    which also accounts for the cloud fallback."""
    try:
        sock = _connect(timeout=timeout)
        sock.sendall(b"PING\0")
        response = sock.recv(64)
        sock.close()
        return b"PONG" in response
    except Exception:
        return False


def antivirus_usable():
    """True if scan_bytes() would actually be able to scan right now,
    whether via local clamd or the VirusTotal cloud fallback. Use this
    (not the local-only clamd_available()) for any UI gate that decides
    whether to run a live scan or fall back to the risky-extension
    heuristic -- otherwise a deployment with no local clamd can never
    reach the cloud fallback at all."""
    return is_usable(clamd_available(), VT_API_KEY_VAR)


def antivirus_backend():
    """Which backend scan_bytes() would use right now: 'local', 'cloud',
    or None if neither is usable. For UI status messages only."""
    try:
        backend, _ = resolve_backend(clamd_available(), VT_API_KEY_VAR, "antivirus scanning")
        return backend
    except BackendError:
        return None


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
    """Scan raw bytes in memory. Dispatches to local clamd (default,
    unchanged behaviour) or VirusTotal's cloud API, per SIH26106_AI_BACKEND
    and clamd's own reachability -- see cloud_backend.resolve_backend().

    Returns {"ok": True, "infected": bool, "signature": str|None, "raw": str}
    or {"ok": False, "error": ...}. Never raises.
    """
    if not data:
        return {"ok": True, "infected": False, "signature": None, "raw": "empty"}

    blocked = _blocked_reason(data)
    if blocked:                               # ok False -> never reported as "clean"
        return {"ok": False, "error": blocked}

    try:
        backend, api_key = resolve_backend(
            local_available=clamd_available(),
            env_var=VT_API_KEY_VAR,
            service_label="antivirus scanning",
        )
    except BackendError as exc:
        return {"ok": False, "error": str(exc)}

    if backend == "cloud":
        return _scan_bytes_virustotal(data, api_key)
    return _scan_bytes_clamd(data, timeout=timeout)


def _scan_bytes_clamd(data, timeout=CLAMD_TIMEOUT):
    """Original local clamd INSTREAM scan -- unmoved."""
    try:
        sock = _connect(timeout=timeout)
        sock.sendall(b"zINSTREAM\0")

        # clamd wants <4-byte big-endian length><chunk> frames, ending with
        # a zero-length frame.
        chunk_size = 8192
        deadline = time.monotonic() + CLAMD_TOTAL_DEADLINE
        for offset in range(0, len(data), chunk_size):
            if time.monotonic() > deadline:
                sock.close()
                return {"ok": False, "error": "ClamAV scan timed out."}
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


def _vt_headers(api_key):
    return {"x-apikey": api_key}


def _vt_verdict_from_analysis_stats(stats):
    """VirusTotal's own multi-engine verdict: infected iff any engine
    flags it malicious."""
    malicious = int((stats or {}).get("malicious", 0) or 0)
    return malicious > 0


def _vt_signature_from_results(results):
    """Best-effort signature name: the first engine's own label, if any
    engine actually flagged this file. Purely cosmetic -- infected/clean
    is decided by the malicious count, not by whether we found a name."""
    for engine in (results or {}).values():
        if (engine or {}).get("category") == "malicious" and engine.get("result"):
            return engine["result"]
    return None


def _scan_bytes_virustotal(data, api_key):
    """Cloud fallback: VirusTotal file scan.

    Hashes first and checks GET /files/{sha256} -- if VirusTotal has
    already seen this exact file, that's an instant verdict with no
    upload needed. Only genuinely new files get uploaded and polled.
    """
    sha256 = hashlib.sha256(data).hexdigest()
    try:
        lookup = requests.get(
            f"{VT_BASE}/files/{sha256}",
            headers=_vt_headers(api_key),
            timeout=VT_TIMEOUT,
        )
        if lookup.status_code == 200:
            attrs = lookup.json().get("data", {}).get("attributes", {}) or {}
            stats = attrs.get("last_analysis_stats", {}) or {}
            results = attrs.get("last_analysis_results", {}) or {}
            infected = _vt_verdict_from_analysis_stats(stats)
            return {
                "ok": True,
                "infected": infected,
                "signature": _vt_signature_from_results(results) if infected else None,
                "raw": f"VirusTotal (cached): malicious={stats.get('malicious', 0)}",
            }
        if lookup.status_code not in (404,):
            lookup.raise_for_status()

        # Not seen before -- upload and poll the analysis.
        upload = requests.post(
            f"{VT_BASE}/files",
            headers=_vt_headers(api_key),
            files={"file": ("scan_target", data)},
            timeout=VT_TIMEOUT,
        )
        upload.raise_for_status()
        analysis_id = upload.json().get("data", {}).get("id")
        if not analysis_id:
            return {"ok": False, "error": "VirusTotal upload did not return an analysis id."}

        for _ in range(VT_POLL_MAX_ATTEMPTS):
            poll = requests.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=_vt_headers(api_key),
                timeout=VT_TIMEOUT,
            )
            poll.raise_for_status()
            attrs = poll.json().get("data", {}).get("attributes", {}) or {}
            status = attrs.get("status")
            if status == "completed":
                stats = attrs.get("stats", {}) or {}
                results = attrs.get("results", {}) or {}
                infected = _vt_verdict_from_analysis_stats(stats)
                return {
                    "ok": True,
                    "infected": infected,
                    "signature": _vt_signature_from_results(results) if infected else None,
                    "raw": f"VirusTotal: malicious={stats.get('malicious', 0)}",
                }
            time.sleep(VT_POLL_INTERVAL)

        # Still queued after bounded polling -- ok: False, never a false
        # "clean". The UI's existing risky-extension fallback handles this.
        return {"ok": False, "error": "VirusTotal analysis is still queued after the polling window."}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": "Could not reach VirusTotal."}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "VirusTotal request timed out."}
    except requests.exceptions.HTTPError as exc:
        return {"ok": False, "error": f"VirusTotal HTTP error: {exc}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def scan_attachments(parsed):
    """Scan every attachment on a parsed email via clamd.

    Returns a list of {filename, size, infected, signature, error} dicts,
    one per attachment, so the UI still shows partial results if clamd
    fails on one attachment but not another.
    """
    results = []
    count, total = 0, 0
    for att in (parsed.get("attachments") or []):
        data = att.get("data") or b""
        count += 1
        total += len(data)
        if att.get("skipped"):
            outcome = {"ok": False, "error": "Not scanned: %s." % att["skipped"]}
        elif count > MAX_SCAN_FILES or total > MAX_SCAN_TOTAL_BYTES:
            outcome = {"ok": False, "error": "Not scanned: per-message scan limit reached."}
        else:
            outcome = scan_bytes(data)
        results.append({
            "filename": att.get("filename", "-"),
            "size": att.get("size", 0),
            "infected": outcome.get("infected", False),
            "signature": outcome.get("signature"),
            "error": None if outcome.get("ok") else outcome.get("error"),
        })
    return results