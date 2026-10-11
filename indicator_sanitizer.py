"""Pure-Python sanitizer for indicators that may one day be shared (URLs, domains, public IPs, file hashes).

No network, no storage, no dependencies. Input strings are never modified in place, and the result never
echoes a rejected input (it could contain an address or token). When an indicator cannot be sanitized
confidently it is rejected rather than guessed at.
"""
import ipaddress
import math
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

ACCEPTED, SANITIZED, REJECTED = "accepted", "sanitized", "rejected"

_MAX_LEN = 2048
_MAX_SEGMENT = 64
_EMAIL_RE = re.compile(r"^[^\s@/:?#]+@[^\s@/:?#]+\.[^\s@/:?#]+$")
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_JWT_RE = re.compile(r"^eyJ[\w-]+\.[\w-]+\.[\w-]*$")
_RESERVED_TLDS = {"localhost", "local", "internal", "lan", "home", "corp", "intranet", "invalid", "test", "arpa", "onion"}
# Common two-part public suffixes so the registrable label is not mistaken for a subdomain (no PSL dependency).
_TWO_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "co.jp",
                      "com.br", "com.cn", "co.nz", "co.za", "com.mx", "com.tr", "com.sg", "com.hk"}


@dataclass(frozen=True)
class SanitizeResult:
    status: str                    # accepted | sanitized | rejected
    indicator_type: str = None     # url | domain | ip | hash (None when the type could not be determined)
    value: str = None              # the shareable form; None when rejected
    reason: str = ""               # why it was rejected / short summary
    changes: tuple = field(default_factory=tuple)   # what was removed or altered (never the removed content)

    @property
    def ok(self):
        return self.status != REJECTED


def _reject(kind, reason):
    return SanitizeResult(REJECTED, kind, None, reason, ())


def _entropy(text):
    if not text:
        return 0.0
    n = len(text)
    return -sum((text.count(c) / n) * math.log2(text.count(c) / n) for c in set(text))


def _looks_like_token(seg):
    """True for path segments / subdomain labels that look personalised or random (ids, tokens, hashes)."""
    s = seg.strip()
    if not s:
        return False
    if len(s) > _MAX_SEGMENT or "@" in s or "%40" in s.lower() or "=" in s:
        return True
    if _UUID_RE.match(s) or _JWT_RE.match(s):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{16,}", s) or (s.isdigit() and len(s) >= 8):
        return True
    pieces = [p for p in re.split(r"[-_.]", s) if p]
    if all((p.isalpha() and len(p) <= 14) or (p.isdigit() and len(p) <= 4) for p in pieces):
        return False                                    # readable words, e.g. "reset-password", "step-2"
    letters, digits = sum(c.isalpha() for c in s), sum(c.isdigit() for c in s)
    if len(s) >= 12 and digits >= 3 and letters >= 3:
        return True
    return len(s) >= 16 and _entropy(s) >= 3.7


def _is_global_ip(ip):
    if getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_multicast or ip.is_unspecified)


def _clean_ip(text, kind="ip"):
    try:
        ip = ipaddress.ip_address(text.strip().strip("[]"))
    except ValueError:
        return None, _reject(kind, "malformed IP address")
    if not _is_global_ip(ip):
        return None, _reject(kind, "IP is not a public global address (private, loopback, link-local or reserved)")
    return (ip.ipv4_mapped if getattr(ip, "ipv4_mapped", None) is not None else ip).compressed, None


def _clean_host(host, kind):
    """Returns (normalised host, None) or (None, rejection)."""
    host = host.strip().rstrip(".").lower()
    if not host:
        return None, _reject(kind, "empty host")
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None, _reject(kind, "host cannot be normalised")
    if len(host) > 253:
        return None, _reject(kind, "host too long")
    if re.fullmatch(r"[0-9.]+", host) or ":" in host:
        return None, _reject(kind, "malformed host")
    labels = host.split(".")
    if len(labels) < 2 or any(not _LABEL_RE.match(l) for l in labels):
        return None, _reject(kind, "malformed domain")
    tld = labels[-1]
    if tld in _RESERVED_TLDS or not (tld.startswith("xn--") or (tld.isalpha() and 2 <= len(tld) <= 24)):
        return None, _reject(kind, "reserved or invalid top-level domain")
    keep = 3 if ".".join(labels[-2:]) in _TWO_PART_SUFFIXES else 2
    if any(_looks_like_token(l) for l in labels[:-keep]):
        return None, _reject(kind, "personalised or random-looking subdomain; submit the registrable domain instead")
    return host, None


def _clean_url(text):
    if _EMAIL_RE.match(text) or text.lower().startswith(("mailto:", "javascript:", "data:", "file:")):
        return _reject("url", "not a web URL")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return _reject("url", "malformed URL")
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return _reject("url", "only absolute http(s) URLs are supported")
    changes = []
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        changes.append("removed user information")
    if port is not None:
        changes.append("removed port")
    if parts.query:
        changes.append("removed query string")
    if parts.fragment:
        changes.append("removed fragment")

    raw_host = parts.hostname
    try:
        ipaddress.ip_address(raw_host)
        host, bad = _clean_ip(raw_host, "url")
        if host and ":" in host:
            host = "[%s]" % host
    except ValueError:
        host, bad = _clean_host(raw_host, "url")
    if bad:
        return bad

    safe = []
    for seg in parts.path.split("/"):
        if ";" in seg:
            seg = seg.split(";", 1)[0]
            if "removed path parameters" not in changes:
                changes.append("removed path parameters")
        if not seg:
            continue
        if _looks_like_token(seg):
            changes.append("removed token-like path segment and everything after it")
            break
        safe.append(seg)
    path = "/" + "/".join(safe) if safe else "/"
    value = "%s://%s%s" % (parts.scheme.lower(), host, path)
    if len(value) > 512:
        return _reject("url", "sanitized URL still too long")
    status = ACCEPTED if value == text and not changes else SANITIZED
    return SanitizeResult(status, "url", value, "ok" if status == ACCEPTED else "sanitized", tuple(changes))


def sanitize_indicator(value, kind=None):
    """Sanitize one indicator. kind: 'url' | 'domain' | 'ip' | 'hash' | None (auto-detect).
    Returns a SanitizeResult; never raises and never mutates or echoes the input."""
    if not isinstance(value, str):
        return _reject(kind, "indicator must be text")
    text = value.strip()
    if not text:
        return _reject(kind, "empty indicator")
    if len(text) > _MAX_LEN or any(ord(c) < 32 or ord(c) == 127 for c in text) or re.search(r"\s", text):
        return _reject(kind, "malformed indicator")
    if kind not in (None, "url", "domain", "ip", "hash"):
        return _reject(kind, "unsupported indicator type")

    if kind is None:
        if re.match(r"(?i)^[a-z][a-z0-9+.-]*:", text) and not re.match(r"^\[?[0-9a-fA-F:.]+\]?$", text):
            kind = "url"
        elif _EMAIL_RE.match(text) or "@" in text:
            return _reject(None, "email addresses are never shared")
        elif re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) in _HASH_LENGTHS:
            kind = "hash"
        else:
            try:
                ipaddress.ip_address(text.strip("[]"))
                kind = "ip"
            except ValueError:
                kind = "domain"

    if kind == "url":
        return _clean_url(text)
    if "@" in text:
        return _reject(kind, "email addresses are never shared")
    if kind == "hash":
        if not re.fullmatch(r"[0-9a-fA-F]+", text) or len(text) not in _HASH_LENGTHS:
            return _reject("hash", "not an MD5, SHA-1 or SHA-256 hex digest")
        low = text.lower()
        return SanitizeResult(ACCEPTED if low == text else SANITIZED, "hash", low, _HASH_LENGTHS[len(text)],
                              () if low == text else ("lower-cased",))
    if kind == "ip":
        ip, bad = _clean_ip(text)
        if bad:
            return bad
        return SanitizeResult(ACCEPTED if ip == text else SANITIZED, "ip", ip, "ok", () if ip == text else ("normalised",))
    # domain
    if re.search(r"[/:?#\\]", text):
        return _reject("domain", "not a bare domain name")
    host, bad = _clean_host(text, "domain")
    if bad:
        return bad
    return SanitizeResult(ACCEPTED if host == text else SANITIZED, "domain", host, "ok", () if host == text else ("normalised",))
