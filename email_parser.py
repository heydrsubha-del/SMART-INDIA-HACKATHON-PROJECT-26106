"""Module 2 (part 1): parse a raw .eml file into structured evidence.

Uses Python's standard-library `email` package, so RFC 5322 edge cases
(folded headers, MIME multipart, encoded words) are handled for us.

The important forensic step is the Received chain: mail servers PREPEND their
Received header, so the LAST one in the file is the oldest hop - closest to the
true sender. We walk it oldest-first and take the first public IP as the origin.

Standalone:  python email_parser.py samples/phishing_credential.eml
"""
import html
import ipaddress
import re
from email import message_from_bytes, policy
from email.utils import getaddresses, parseaddr

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TAG_RE = re.compile(r"<[^>]+>")
SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b.*?</\1>", re.S | re.I)


def is_public_ip(text):
    """True only for globally routable IPv4 - filters out internal relay hops."""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def domain_of(addr):
    """'Bob <b@Example.COM>' -> 'example.com'; '' when there is no domain."""
    email_addr = parseaddr(addr or "")[1]
    return email_addr.rsplit("@", 1)[-1].strip().lower() if "@" in email_addr else ""


def _html_to_text(raw):
    """Crude but dependency-free HTML -> text for body analysis."""
    txt = SCRIPT_STYLE_RE.sub(" ", raw)
    txt = re.sub(r"<br\s*/?>|</p>|</div>|</tr>", "\n", txt, flags=re.I)
    txt = TAG_RE.sub(" ", txt)
    return re.sub(r"[ \t]{2,}", " ", html.unescape(txt))


def _extract_body(msg):
    """Best-effort plain text of the message, whatever the MIME shape."""
    try:
        part = msg.get_body(preferencelist=("plain", "html"))
        if part is not None:
            content = part.get_content()
            if part.get_content_subtype() == "html":
                return _html_to_text(content)
            return content
    except Exception:
        pass

    # Fallback for malformed messages the modern API refuses to walk.
    chunks = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        if part.get_content_maintype() != "text":
            continue
        try:
            payload = part.get_payload(decode=True)
            text = (payload.decode(part.get_content_charset() or "utf-8",
                                   errors="replace")
                    if payload else str(part.get_payload()))
            chunks.append(_html_to_text(text)
                          if part.get_content_subtype() == "html" else text)
        except Exception:
            continue
    return "\n".join(chunks)


def _attachments(msg):
    """Filenames + sizes of attached parts, flagging risky extensions."""
    risky = (".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd", ".com",
             ".pif", ".hta", ".iso", ".lnk", ".docm", ".xlsm", ".zip", ".rar")
    out = []
    if not msg.is_multipart():
        return out
    for part in msg.walk():
        name = part.get_filename()
        if not name:
            continue
        try:
            size = len(part.get_payload(decode=True) or b"")
        except Exception:
            size = 0
        out.append({
            "filename": name,
            "size": size,
            "risky": name.lower().endswith(risky),
        })
    return out


def parse_eml(data):
    """Parse raw .eml bytes/str into a dict of forensic fields."""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    msg = message_from_bytes(data, policy=policy.default)

    def head(name):
        try:
            value = msg.get(name, "")
            return str(value).strip() if value else ""
        except Exception:
            return ""

    from_raw = head("From")
    reply_to = head("Reply-To")
    return_path = head("Return-Path")

    # Received headers: file order is newest-first, so reverse for the path.
    try:
        received = [str(v).strip() for v in msg.get_all("Received", [])]
    except Exception:
        received = []
    received_oldest_first = list(reversed(received))

    hops = []
    for hop in received_oldest_first:
        ips, seen_ip = [], set()
        for ip in IP_RE.findall(hop):
            if ip in seen_ip or not is_public_ip(ip):
                continue          # skip repeats and internal/reserved relays
            seen_ip.add(ip)
            ips.append(ip)
        hops.append({"raw": hop, "ips": ips})
    origin_ip = next((h["ips"][0] for h in hops if h["ips"]), "")

    body = _extract_body(msg) or ""

    return {
        "from_display": parseaddr(from_raw)[0],
        "from_addr": parseaddr(from_raw)[1],
        "from_domain": domain_of(from_raw),
        "to": ", ".join(a for _, a in getaddresses([head("To")]) if a),
        "reply_to": parseaddr(reply_to)[1],
        "reply_to_domain": domain_of(reply_to),
        "return_path": parseaddr(return_path)[1],
        "return_path_domain": domain_of(return_path),
        "subject": head("Subject"),
        "date": head("Date"),
        "message_id": head("Message-ID"),
        "auth_results": " ".join(
            filter(None, [head("Authentication-Results"),
                          head("Received-SPF"),
                          head("ARC-Authentication-Results")])
        ),
        "x_mailer": head("X-Mailer") or head("User-Agent"),
        "received_chain": received_oldest_first,
        "hops": hops,
        "origin_ip": origin_ip,
        "body_text": body,
        "full_text": "{} {}".format(head("Subject"), body).strip(),
        "attachments": _attachments(msg),
    }


if __name__ == "__main__":
    import json
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "samples/phishing_credential.eml"
    with open(path, "rb") as fh:
        parsed = parse_eml(fh.read())
    slim = {k: v for k, v in parsed.items()
            if k not in ("body_text", "full_text", "hops", "received_chain")}
    print(json.dumps(slim, indent=2))
    print("\nhops (oldest first):")
    for i, hop in enumerate(parsed["hops"], 1):
        print("  {}. ips={} {}".format(i, hop["ips"], hop["raw"][:90]))
