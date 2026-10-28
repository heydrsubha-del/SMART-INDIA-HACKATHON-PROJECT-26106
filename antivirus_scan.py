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
VT_TOTAL_DEADLINE = 120                     # wall-clock cap across lookup + upload + polling


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


ZIP_MAX_ENTRY_BYTES = 512 * 1024 * 1024      # declared size of any single entry
ZIP_MAX_NESTED = 5                           # nested archives per ZIP
_ARCHIVE_EXT = (".zip", ".jar", ".apk", ".7z", ".rar", ".gz", ".tgz", ".bz2", ".xz", ".tar", ".cab", ".iso")
_EOCD = b"PK\x05\x06"


def _looks_like_zip(data):
    """True if a ZIP signature appears at the start, a local header appears early (prefixed/self-extracting
    archives), or an end-of-central-directory record sits in the tail (where zipfile itself looks)."""
    return (data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
            or b"PK\x03\x04" in data[:1024 * 1024]
            or _EOCD in data[-(65535 + 22):])


def inspect_zip(data):
    """Return a reason string if `data` is (or hides) a ZIP that is unsafe to scan, else None.
    Reads the central directory only, never extracts. Fails CLOSED: an unreadable ZIP structure or any
    unexpected error returns a reason, so the file is reported as not scanned rather than clean."""
    if not data:
        return None
    try:
        if not _looks_like_zip(data):
            return None
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))      # tolerates data prepended to the archive
        except zipfile.BadZipFile:
            if _EOCD in data[-(65535 + 22):]:
                return "malformed ZIP structure"
            return None                                   # stray 'PK' bytes in a non-ZIP file
        with zf:
            infos = zf.infolist()
            if len(infos) > ZIP_MAX_ENTRIES:
                return "ZIP has too many entries (%d)" % len(infos)
            total = sum(i.file_size for i in infos)
            packed = max(sum(i.compress_size for i in infos), 1)
            if total > ZIP_MAX_UNCOMPRESSED:
                return "ZIP declares an excessive uncompressed size"
            if total > 10 * 1024 * 1024 and total / packed > ZIP_MAX_RATIO:
                return "ZIP compression ratio is suspiciously high"
            nested = 0
            for i in infos:
                if i.file_size > ZIP_MAX_ENTRY_BYTES:
                    return "ZIP contains an oversized entry"
                if i.file_size > 10 * 1024 * 1024 and i.file_size / max(i.compress_size, 1) > ZIP_MAX_RATIO:
                    return "ZIP entry compression ratio is suspiciously high"
                if i.filename.lower().endswith(_ARCHIVE_EXT):
                    nested += 1
                    if nested > ZIP_MAX_NESTED:
                        return "ZIP contains too many nested archives"
                    if i.file_size > 10 * 1024 * 1024:
                        return "ZIP contains a large nested archive"
    except Exception:
        return "ZIP could not be inspected safely"
    return None


def _blocked_reason(data):
    if len(data) > MAX_SCAN_BYTES:
        return "File exceeds the %d MB scan limit; not scanned." % (MAX_SCAN_BYTES // (1024 * 1024))
    try:
        bomb = inspect_zip(data)
    except Exception:
        bomb = "inspection failed"
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

    try:
        if backend == "cloud":
            return _scan_bytes_virustotal(data, api_key)
        return _scan_bytes_clamd(data, timeout=timeout)
    except Exception as exc:                  # unexpected scanner failure is "not scanned", never "clean"
        return {"ok": False, "error": "Scanner error: %s" % type(exc).__name__}


def _scan_bytes_clamd(data, timeout=CLAMD_TIMEOUT):
    """Local clamd INSTREAM scan under ONE wall-clock deadline covering connect, send and receive."""
    sock = None
    deadline = time.monotonic() + CLAMD_TOTAL_DEADLINE

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout("overall deadline")
        sock.settimeout(min(left, timeout))
        return left

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(min(timeout, CLAMD_TOTAL_DEADLINE))
        sock.connect((CLAMD_HOST, CLAMD_PORT))
        remaining()
        sock.sendall(b"zINSTREAM\0")

        # clamd wants <4-byte big-endian length><chunk> frames, ending with a zero-length frame.
        chunk_size = 8192
        for offset in range(0, len(data), chunk_size):
            remaining()
            chunk = data[offset:offset + chunk_size]
            sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
        remaining()
        sock.sendall((0).to_bytes(4, "big"))

        chunks, got = [], 0
        while True:
            remaining()                       # a trickling server cannot extend the scan past the deadline
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
            if got > 65536:
                return {"ok": False, "error": "Unexpected oversized clamd response."}

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
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


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

        vt_deadline = time.monotonic() + VT_TOTAL_DEADLINE
        for _ in range(VT_POLL_MAX_ATTEMPTS):
            if time.monotonic() > vt_deadline:
                break
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
            try:
                outcome = scan_bytes(data)
            except Exception as exc:
                outcome = {"ok": False, "error": "Scanner error: %s" % type(exc).__name__}
        results.append({
            "filename": att.get("filename", "-"),
            "size": att.get("size", 0),
            "infected": bool(outcome.get("ok") and outcome.get("infected", False)),
            "scanned": bool(outcome.get("ok")),
            "signature": outcome.get("signature"),
            "error": None if outcome.get("ok") else outcome.get("error"),
        })
    return results


_SKIP_REASONS = {
    "attachment_too_large": "attachment exceeds the per-file size limit",
    "aggregate_size_limit": "message attachment total exceeds the size limit",
    "attachment_count_limit": "too many attachments in the message",
    "decode_error": "attachment content could not be decoded",
}

# Row categories used by the UI metrics.
CAT_DETECTED, CAT_CLEAN, CAT_RISKY_EXT, CAT_NOT_SCANNED, CAT_ERROR = (
    "detected", "clean", "risky_extension", "not_scanned", "scan_error")


def attachment_status(att, outcome=None):
    """Display status for one attachment -> (status, detail, category). Pure; never raises.

    `outcome` is a scan_bytes()-style dict, or None when no antivirus backend is available.
    "Clean" is returned ONLY for a successful scan that found nothing. An extension match is a heuristic
    ("Potentially risky extension"), never a detection."""
    att = att if isinstance(att, dict) else {}
    risky = bool(att.get("risky"))
    skipped = att.get("skipped")
    if skipped:
        reason = _SKIP_REASONS.get(str(skipped), str(skipped))
        note = "; extension is potentially risky" if risky else ""
        return "Not scanned", "Skipped: %s%s" % (reason, note), CAT_NOT_SCANNED
    if outcome is None:
        if risky:
            return ("Potentially risky extension",
                    "Heuristic only (file type by name); not scanned, not a malware verdict", CAT_RISKY_EXT)
        return "Not scanned", "No antivirus backend available", CAT_NOT_SCANNED
    if not isinstance(outcome, dict) or not outcome.get("ok"):
        err = str((outcome or {}).get("error") or "scan failed") if isinstance(outcome, dict) else "scan failed"
        cat = CAT_NOT_SCANNED if err.startswith("Not scanned") else CAT_ERROR
        return ("Not scanned" if cat == CAT_NOT_SCANNED else "Scan error"), err, cat
    if outcome.get("infected"):
        return "INFECTED", outcome.get("signature") or "-", CAT_DETECTED
    return "Clean", "-", CAT_CLEAN
