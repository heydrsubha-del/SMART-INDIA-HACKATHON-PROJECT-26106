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
import json
import os
import socket
import struct
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


_LFH = b"PK\x03\x04"
_ZIP_METHODS = {0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 18, 19, 93, 95, 96, 97, 98, 99}


def _plausible_lfh(data, i):
    """True if a ZIP local-file-header at offset i has sane fields (rules out stray 'PK\\x03\\x04' bytes)."""
    if len(data) < i + 30:
        return False
    if data[i + 4] > 100:                                   # version needed (low byte)
        return False
    if int.from_bytes(data[i + 8:i + 10], "little") not in _ZIP_METHODS:
        return False
    n = int.from_bytes(data[i + 26:i + 28], "little")
    if n > 4096 or len(data) < i + 30 + n:
        return False
    return all(b >= 0x20 and b != 0x7F for b in data[i + 30:i + 30 + n])


LFH_SIGNATURE_BUDGET = 4096        # candidate local-header signatures examined before failing closed
_ECD = "<4sHHHHIIH"                 # end of central directory record (22 bytes)
_ECD64 = "<4sQHHIIQQQQ"             # ZIP64 end of central directory record (56 bytes, no extensible data)
_CDH_LEN = 46


def _truncated_zip_reason(data):
    """Called only when no end-of-central-directory record exists. Returns a rejection reason if the blob
    claims to be a ZIP (starts with a local-file-header signature, or contains a plausible local header
    ANYWHERE, e.g. a prefixed/self-extracting archive that was truncated), else None. Exhausting the
    signature budget never proves 'not a ZIP': it fails closed."""
    if data[:4] == _LFH:
        return "truncated or malformed ZIP (no valid central directory)"
    examined = 0
    i = data.find(_LFH, 1)
    while i != -1:
        if _plausible_lfh(data, i):
            return "truncated or malformed ZIP (no valid central directory)"
        examined += 1
        if examined >= LFH_SIGNATURE_BUDGET:
            return "too many ZIP signatures to verify safely"
        i = data.find(_LFH, i + 1)
    return None


def _find_eocd(data):
    """Offset of the end-of-central-directory record, searched the way zipfile does, else None."""
    if len(data) >= 22 and data[-22:-18] == _EOCD:
        return len(data) - 22
    i = data.rfind(_EOCD, max(len(data) - (65535 + 22), 0))
    return None if i == -1 else i


def _zip64_values(extra):
    """u64 values of the ZIP64 extended-information extra field (id 0x0001), in order; [] if absent."""
    i = 0
    while i + 4 <= len(extra):
        tag = int.from_bytes(extra[i:i + 2], "little")
        size = int.from_bytes(extra[i + 2:i + 4], "little")
        body = extra[i + 4:i + 4 + size]
        if tag == 1:
            return [int.from_bytes(body[j:j + 8], "little") for j in range(0, len(body) - len(body) % 8, 8)]
        i += 4 + size
    return []


def _hidden_zip_reason(region, where):
    """Reject archive content hidden in bytes the selected end record would otherwise let us ignore."""
    reason = _truncated_zip_reason(region) if region else None
    if reason is None:
        return None
    if reason.startswith("too many"):
        return reason
    return "hidden ZIP content in %s (ambiguous structure)" % where


_DD_SIG = b"PK\x07\x08"


def _descriptor_length(data, at, crc, csize, usize):
    """Exact length of the data descriptor at `at`, or None. Candidates (signed/unsigned x 32/64-bit) are accepted
    only if their CRC and BOTH sizes equal the central-directory values; zero or several matches of different
    lengths are ambiguous/malformed and are never guessed."""
    cands = (
        (16, _DD_SIG + crc.to_bytes(4, "little") + csize.to_bytes(4, "little") + usize.to_bytes(4, "little"), csize < 2**32 and usize < 2**32),
        (12, crc.to_bytes(4, "little") + csize.to_bytes(4, "little") + usize.to_bytes(4, "little"), csize < 2**32 and usize < 2**32),
        (24, _DD_SIG + crc.to_bytes(4, "little") + csize.to_bytes(8, "little") + usize.to_bytes(8, "little"), True),
        (20, crc.to_bytes(4, "little") + csize.to_bytes(8, "little") + usize.to_bytes(8, "little"), True),
    )
    hits = {n for n, expected, ok in cands if ok and data[at:at + n] == expected}
    return hits.pop() if len(hits) == 1 else None


def _layout_reason(data, recs, concat, cd_start, eocd):
    """Validate the relation between end record, central directory and local file headers, and refuse any
    archive structure hidden in the prefix, gaps between entries, the tail before the directory, or after the
    end record. Every directory entry must point at a real local header whose flags, method and sizes agree
    with the directory; entries with a data descriptor must have an exact, directory-matching descriptor (no
    blind allowance: its length is determined, never guessed); entries may not overlap; every byte the
    directory does not account for must contain no plausible ZIP local header. Bounded by the entry limit
    already enforced by the caller. Nothing is extracted or decompressed."""
    extents = []
    for pos, name_len, extra_len in recs:
        flags = int.from_bytes(data[pos + 8:pos + 10], "little")
        method = int.from_bytes(data[pos + 10:pos + 12], "little")
        crc = int.from_bytes(data[pos + 16:pos + 20], "little")
        csize = int.from_bytes(data[pos + 20:pos + 24], "little")
        usize = int.from_bytes(data[pos + 24:pos + 28], "little")
        lho = int.from_bytes(data[pos + 42:pos + 46], "little")
        cd_sentinel = 0xFFFFFFFF in (csize, usize)
        if 0xFFFFFFFF in (csize, usize, lho):
            vals = _zip64_values(data[pos + _CDH_LEN + name_len:pos + _CDH_LEN + name_len + extra_len])
            k = 0
            try:
                if usize == 0xFFFFFFFF:
                    usize = vals[k]
                    k += 1
                if csize == 0xFFFFFFFF:
                    csize = vals[k]
                    k += 1
                if lho == 0xFFFFFFFF:
                    lho = vals[k]
            except IndexError:
                return "malformed ZIP structure (missing ZIP64 entry values)"
        phys = lho + concat
        if phys + 30 > cd_start or data[phys:phys + 4] != _LFH:
            return "malformed ZIP structure (directory entry does not point at a local file header)"
        l_flags = int.from_bytes(data[phys + 6:phys + 8], "little")
        l_method = int.from_bytes(data[phys + 8:phys + 10], "little")
        if (l_flags ^ flags) & 0x08 or l_method != method:
            return "malformed ZIP structure (local header and directory disagree on flags or method)"
        local_name = int.from_bytes(data[phys + 26:phys + 28], "little")
        local_extra = int.from_bytes(data[phys + 28:phys + 30], "little")
        end = phys + 30 + local_name + local_extra + csize
        if end > cd_start:
            return "malformed ZIP structure (entry data overruns the central directory)"
        if flags & 0x08:                                      # sizes live in a data descriptor after the data
            n = _descriptor_length(data, end, crc, csize, usize)
            if n is None or end + n > cd_start:
                return "malformed ZIP structure (data descriptor missing, ambiguous or inconsistent with the directory)"
            end += n
        else:                                                 # no descriptor: local header must agree with the directory
            l_crc = int.from_bytes(data[phys + 14:phys + 18], "little")
            l_csize = int.from_bytes(data[phys + 18:phys + 22], "little")
            l_usize = int.from_bytes(data[phys + 22:phys + 26], "little")
            if l_crc != crc or (0xFFFFFFFF not in (l_csize, l_usize) and not cd_sentinel
                                and (l_csize != csize or l_usize != usize)):
                return "malformed ZIP structure (local header and directory disagree on CRC or sizes)"
        extents.append((phys, end))
    extents.sort()
    first = extents[0][0] if extents else cd_start
    reason = _hidden_zip_reason(data[:first], "the prefix")
    if reason:
        return reason
    for (_, prev_end), (phys, _) in zip(extents, extents[1:]):
        if phys < prev_end:
            return "malformed ZIP structure (overlapping entries)"
        if phys > prev_end:
            reason = _hidden_zip_reason(data[prev_end:phys], "a gap between entries")
            if reason:
                return reason
    if extents:
        last_end = max(e[1] for e in extents)
        reason = _hidden_zip_reason(data[last_end:cd_start], "the data before the central directory")
        if reason:
            return reason
    return _hidden_zip_reason(data[eocd + 22:], "the end record comment or trailing data")


def _cd_preflight(data, eocd):
    """Bounded central-directory check BEFORE zipfile.ZipFile is constructed. Reads only fixed-size records,
    never extracts, never trusts the declared entry count: it walks the real records and stops as soon as the
    limit is exceeded. Handles prefixed archives (physical offsets) and ZIP64. Returns a reason or None."""
    rec = data[eocd:eocd + 22]
    if len(rec) < 22:
        return "malformed ZIP structure (short end record)"
    _, disk, cd_disk, n_disk, n_total, cd_size, cd_off, _clen = struct.unpack(_ECD, rec)
    cd_end = eocd
    loc = eocd - 20
    if loc >= 0 and data[loc:loc + 4] == b"PK\x06\x07":              # ZIP64 locator
        pos64 = loc - 56
        if pos64 < 0 or data[pos64:pos64 + 4] != b"PK\x06\x06" or len(data) < pos64 + 56:
            return "malformed ZIP structure (bad ZIP64 record)"
        (_, _, _, _, disk, cd_disk, n_disk, n_total, cd_size, cd_off) = struct.unpack(_ECD64, data[pos64:pos64 + 56])
        cd_end = pos64
    if disk or cd_disk or n_disk != n_total:
        return "malformed ZIP structure (multi-disk or inconsistent counts)"
    if n_total > ZIP_MAX_ENTRIES:
        return "ZIP has too many entries (declared %d)" % n_total
    if cd_size > cd_end:
        return "malformed ZIP structure (central directory size out of range)"
    cd_start = cd_end - cd_size
    concat = cd_start - cd_off                    # bytes prepended before the archive (0 for a plain ZIP)
    if concat < 0:
        return "malformed ZIP structure (central directory offset out of range)"
    pos, count, recs = cd_start, 0, []
    while pos < cd_end:
        if pos + _CDH_LEN > cd_end or data[pos:pos + 4] != b"PK\x01\x02":
            return "malformed ZIP structure (bad central directory record)"
        name_len = int.from_bytes(data[pos + 28:pos + 30], "little")
        extra_len = int.from_bytes(data[pos + 30:pos + 32], "little")
        comment_len = int.from_bytes(data[pos + 32:pos + 34], "little")
        lho = int.from_bytes(data[pos + 42:pos + 46], "little")
        nxt = pos + _CDH_LEN + name_len + extra_len + comment_len
        if nxt > cd_end:
            return "malformed ZIP structure (central directory record overruns)"
        if lho != 0xFFFFFFFF and lho + concat + 30 > cd_start:
            return "malformed ZIP structure (local header offset out of range)"
        count += 1
        if count > ZIP_MAX_ENTRIES:
            return "ZIP has too many entries (%d+)" % count
        recs.append((pos, name_len, extra_len))
        pos = nxt
    if count != n_total:
        return "malformed ZIP structure (declared entry count does not match records)"
    return _layout_reason(data, recs, concat, cd_start, eocd)


def inspect_zip(data):
    """Return a reason string if `data` is (or hides) a ZIP that is unsafe to scan, else None.
    Reads the central directory only, never extracts. Fails CLOSED: an unreadable ZIP structure or any
    unexpected error returns a reason, so the file is reported as not scanned rather than clean."""
    if not data:
        return None
    try:
        eocd = _find_eocd(data)
        if eocd is None:
            return _truncated_zip_reason(data)           # None for ordinary files with stray 'PK' bytes
        reason = _cd_preflight(data, eocd)               # bounded; runs before the full parser
        if reason:
            return reason
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))      # tolerates data prepended to the archive
        except zipfile.BadZipFile:
            return "malformed ZIP structure"
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
    if not data:          # nothing to scan: no backend ran, so this must never read as "clean"
        return {"ok": False, "error": "Not scanned: attachment is empty (0 bytes)."}

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


class _VTDeadline(Exception):
    pass


VT_CONNECT_TIMEOUT = 10
VT_MAX_BODY_BYTES = 2 * 1024 * 1024


def _vt_stats_ok(stats):
    """A verdict needs real engine counts; empty/malformed stats must never read as 'clean'."""
    if not isinstance(stats, dict):
        return False
    try:
        return sum(int(v) for v in stats.values() if not isinstance(v, bool)) > 0 and "malicious" in stats
    except (TypeError, ValueError):
        return False


def _scan_bytes_virustotal(data, api_key):
    """Cloud fallback: VirusTotal file scan, bounded by ONE overall deadline (VT_TOTAL_DEADLINE).

    The deadline starts before the first request. Each request gets a (connect, read) timeout capped by the
    remaining budget, response bodies are read in chunks with a deadline check, the deadline is re-checked after
    every network call and sleeps never exceed it. LIMITATION: `requests` timeouts are per socket operation, so
    a single request that keeps trickling bytes can overrun by up to one timeout interval, and the upload body
    is sent in one call (send time is bounded only per socket write). This is a best-effort bound, not a strict
    wall-clock guarantee.
    """
    deadline = time.monotonic() + VT_TOTAL_DEADLINE
    headers = _vt_headers(api_key)

    def left():
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise _VTDeadline()
        return rem

    def timeouts():
        rem = left()
        return (min(VT_CONNECT_TIMEOUT, rem), min(VT_TIMEOUT, rem))

    def body_json(resp):
        try:
            chunks, size = [], 0
            for chunk in resp.iter_content(chunk_size=65536):
                left()
                size += len(chunk)
                if size > VT_MAX_BODY_BYTES:
                    raise ValueError("VirusTotal response too large")
                chunks.append(chunk)
            return json.loads(b"".join(chunks).decode("utf-8"))
        finally:
            try:
                resp.close()
            except Exception:
                pass

    try:
        sha256 = hashlib.sha256(data).hexdigest()
        lookup = requests.get(f"{VT_BASE}/files/{sha256}", headers=headers, timeout=timeouts(), stream=True)
        left()
        if lookup.status_code == 200:
            attrs = ((body_json(lookup) or {}).get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats")
            if _vt_stats_ok(stats):
                results = attrs.get("last_analysis_results", {}) or {}
                infected = _vt_verdict_from_analysis_stats(stats)
                return {
                    "ok": True,
                    "infected": infected,
                    "signature": _vt_signature_from_results(results) if infected else None,
                    "raw": f"VirusTotal (cached): malicious={stats.get('malicious', 0)}",
                }
            # known file without usable analysis stats: fall through to a fresh upload
        else:
            try:
                if lookup.status_code != 404:
                    lookup.raise_for_status()
            finally:
                try:
                    lookup.close()
                except Exception:
                    pass

        upload = requests.post(f"{VT_BASE}/files", headers=headers, files={"file": ("scan_target", data)},
                               timeout=timeouts(), stream=True)
        left()
        try:
            upload.raise_for_status()
            analysis_id = ((body_json(upload) or {}).get("data") or {}).get("id")
        finally:
            try:
                upload.close()
            except Exception:
                pass
        left()
        if not analysis_id:
            return {"ok": False, "error": "VirusTotal upload did not return an analysis id."}

        for _ in range(VT_POLL_MAX_ATTEMPTS):
            poll = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=timeouts(), stream=True)
            left()
            try:
                poll.raise_for_status()
                attrs = ((body_json(poll) or {}).get("data") or {}).get("attributes") or {}
            finally:
                try:
                    poll.close()
                except Exception:
                    pass
            if attrs.get("status") == "completed":
                stats = attrs.get("stats")
                if not _vt_stats_ok(stats):
                    return {"ok": False, "error": "VirusTotal returned an incomplete analysis."}
                results = attrs.get("results", {}) or {}
                infected = _vt_verdict_from_analysis_stats(stats)
                return {
                    "ok": True,
                    "infected": infected,
                    "signature": _vt_signature_from_results(results) if infected else None,
                    "raw": f"VirusTotal: malicious={stats.get('malicious', 0)}",
                }
            rem = left()
            time.sleep(min(VT_POLL_INTERVAL, rem))
            left()

        # Still queued after bounded polling -- ok: False, never a false "clean".
        return {"ok": False, "error": "VirusTotal analysis is still queued after the polling window."}
    except _VTDeadline:
        return {"ok": False, "error": "VirusTotal scan exceeded the overall time limit."}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": "Could not reach VirusTotal."}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "VirusTotal request timed out."}
    except requests.exceptions.HTTPError as exc:
        return {"ok": False, "error": f"VirusTotal HTTP error: {exc}"}
    except Exception as exc:
        return {"ok": False, "error": "VirusTotal scan failed: %s" % type(exc).__name__}


def _verdict(outcome):
    """'clean' / 'infected' only for a well-formed success (ok is True and infected is a real bool); else None."""
    if not isinstance(outcome, dict) or outcome.get("ok") is not True:
        return None
    inf = outcome.get("infected")
    if inf is True:
        return "infected"
    if inf is False:
        return "clean"
    return None


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
        if not isinstance(outcome, dict):
            outcome = {"ok": False, "error": "Malformed scan result."}
        results.append({
            "filename": att.get("filename", "-"),
            "size": att.get("size", 0),
            "infected": _verdict(outcome) == "infected",
            "scanned": _verdict(outcome) is not None,
            "signature": outcome.get("signature") if _verdict(outcome) == "infected" else None,
            "error": None if _verdict(outcome) else (outcome.get("error") or "scan failed") if outcome.get("ok") is not True else "Malformed scan result.",
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
    if not att.get("data") and att.get("size") == 0:      # empty content: never Clean, never a risky-extension hit
        note = "; extension is potentially risky" if risky else ""
        return "Not scanned", "Attachment is empty (0 bytes); nothing to scan%s" % note, CAT_NOT_SCANNED
    if outcome is None:
        if risky:
            return ("Potentially risky extension",
                    "Heuristic only (file type by name); not scanned, not a malware verdict", CAT_RISKY_EXT)
        return "Not scanned", "No antivirus backend available", CAT_NOT_SCANNED
    verdict = _verdict(outcome)
    if verdict is None:
        if isinstance(outcome, dict) and outcome.get("ok") is not True:
            err = str(outcome.get("error") or "scan failed")
        else:
            err = "Malformed scan result"
        if err.startswith("Not scanned"):
            return "Not scanned", err, CAT_NOT_SCANNED
        return "Scan error", err, CAT_ERROR
    if verdict == "infected":
        return "INFECTED", outcome.get("signature") or "-", CAT_DETECTED
    return "Clean", "-", CAT_CLEAN


def summarize_categories(cats):
    """Counts for the Antivirus panel metrics. 'clean' counts ONLY successfully scanned, clean files."""
    cats = list(cats)
    return {
        "found": len(cats),
        "detected": cats.count(CAT_DETECTED),
        "clean": cats.count(CAT_CLEAN),
        "risky_extension": cats.count(CAT_RISKY_EXT),
        "not_scanned_or_error": cats.count(CAT_NOT_SCANNED) + cats.count(CAT_ERROR),
    }
