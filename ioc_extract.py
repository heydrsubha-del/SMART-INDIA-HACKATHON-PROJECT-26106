"""Module 3 (part 1): Indicator-of-Compromise extraction.

Pulls URLs, domains, IPs, emails and crypto wallets out of the body, then judges
each URL offline: shortener, raw-IP host, punycode, look-alike brand domain,
credential-harvesting path, deep subdomain nesting, non-HTTPS.

Look-alike detection uses edit distance against config.KNOWN_BRANDS, so
"paypa1-support.com" and "micros0ft-securelogin.ru" get caught WITHOUT any DNS
or WHOIS lookup - deliberate, because network calls are what break live demos.

Standalone:  python ioc_extract.py samples/phishing_credential.eml
"""
import re
from urllib.parse import urlparse

import config as C

URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'\)\]]+", re.I)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "online",
                   "click", "link", "zip", "mov", "ru", "su", "cn", "work",
                   "support", "rest", "buzz"}
CRED_PATH_WORDS = ("login", "signin", "verify", "secure", "account", "update",
                   "confirm", "auth", "password", "billing", "unlock", "webscr")


def edit_distance(a, b):
    """Levenshtein distance - small inputs, so the simple DP row is plenty."""
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _registrable(host):
    """Rough eTLD+1. Good enough for demo-scale heuristics."""
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    two_level = {"co", "com", "net", "org", "gov", "ac", "edu"}
    if len(parts) >= 3 and parts[-2] in two_level and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _normalise(text):
    """Fold visually confusable characters so homoglyph squats collapse onto
    the brand they imitate: 'paypa1' -> 'paypal', 'arnazon' -> 'amazon'."""
    out = text.lower()
    for fake, real in C.HOMOGLYPHS:
        out = out.replace(fake, real)
    return out


def lookalike_brand(host):
    """(brand, why) if this host mimics a known brand without being it.

    Order matters. The allowlist of genuine brand domains is checked first, so
    real domains are never reported as their own look-alikes.
    """
    host = (host or "").lower().strip(".")
    if not host:
        return None

    reg = _registrable(host)
    if reg in C.BRAND_DOMAINS:
        return None                      # genuinely the brand's own domain

    labels = [p for p in re.split(r"[.\-_]", host) if p]
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    # The TLD itself is not a squat: .sbi and .apple are brand-owned gTLDs.
    body_labels = [p for p in labels if p != tld]

    for brand in C.KNOWN_BRANDS:
        if reg == brand or reg.startswith(brand + "."):
            return None
        if tld == brand:
            return None                  # brand-owned top-level domain

        norm_brand = _normalise(brand)
        for label in body_labels:
            if label == brand:
                # Brand name present, but it does not own the registered domain.
                return brand, ('"{}" appears in the hostname but the registered '
                               "domain is {}".format(brand, reg))

            norm_label = _normalise(label)
            if len(brand) >= 5:
                if norm_label == norm_brand:
                    return brand, ('"{}" imitates "{}" using look-alike '
                                   "characters".format(label, brand))
                if (abs(len(norm_label) - len(norm_brand)) <= 2
                        and 0 < edit_distance(norm_label, norm_brand) <= 1):
                    return brand, ('"{}" is one character away from "{}" '
                                   "(typo-squat)".format(label, brand))
                if (norm_label.startswith(norm_brand)
                        and norm_label[len(norm_brand):] in C.LURE_SUFFIXES):
                    return brand, ('"{}" prefixes the brand "{}" with a '
                                   'credential lure'.format(label, brand))
    return None


def _judge_url(url):
    """Classify one URL. Returns a dict with flags and a 0..1 risk."""
    normalised = url if "://" in url else "http://" + url
    try:
        parsed = urlparse(normalised)
        host = (parsed.hostname or "").lower()
    except Exception:
        host, parsed = "", None

    path = (parsed.path or "") if parsed else ""
    scheme = (parsed.scheme or "") if parsed else ""
    flags, risk = [], 0.0

    if host in C.URL_SHORTENERS:
        flags.append("URL shortener hides the real destination")
        risk = max(risk, 0.75)

    if IPV4_RE.fullmatch(host):
        flags.append("Link points at a raw IP address, not a domain name")
        risk = max(risk, 0.85)

    if "xn--" in host:
        flags.append("Punycode host - may render as look-alike Unicode letters")
        risk = max(risk, 0.85)

    look = lookalike_brand(host)
    if look:
        flags.append("Brand look-alike: {}".format(look[1]))
        risk = max(risk, 0.9)

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append("Low-reputation / high-abuse TLD .{}".format(tld))
        risk = max(risk, 0.55)

    if any(w in path.lower() for w in CRED_PATH_WORDS):
        flags.append("Path suggests a credential-entry page")
        risk = max(risk, 0.5)

    if host.count(".") >= 4:
        flags.append("Deeply nested subdomains disguise the true owner")
        risk = max(risk, 0.5)

    if scheme == "http":
        flags.append("Unencrypted HTTP link")
        risk = max(risk, 0.3)

    return {
        "url": url,
        "host": host,
        "registrable": _registrable(host) if host else "",
        "flags": flags,
        "risk": risk,
        "suspicious": risk >= 0.5,
    }


def extract(parsed):
    """Returns {urls[], domains[], ips[], emails[], wallets[], url_score, ...}."""
    body = parsed.get("body_text", "") or ""
    text = "{}\n{}".format(parsed.get("subject", ""), body)

    seen, urls = set(), []
    for raw in URL_RE.findall(text):
        clean = raw.rstrip(".,);:!?'\"")
        if clean.lower() in seen:
            continue
        seen.add(clean.lower())
        urls.append(_judge_url(clean))

    emails = sorted({e.lower() for e in EMAIL_RE.findall(text)})
    ips = sorted({i for i in IPV4_RE.findall(text)})
    wallets = sorted(set(BTC_RE.findall(text)))
    domains = sorted({u["registrable"] for u in urls if u["registrable"]})

    suspicious = [u for u in urls if u["suspicious"]]
    url_score = max([u["risk"] for u in urls], default=0.0)

    return {
        "urls": urls,
        "suspicious_urls": suspicious,
        "domains": domains,
        "ips": ips,
        "emails": emails,
        "wallets": wallets,
        "url_score": url_score,
        "counts": {"urls": len(urls), "suspicious": len(suspicious),
                   "domains": len(domains), "ips": len(ips),
                   "emails": len(emails), "wallets": len(wallets)},
    }


if __name__ == "__main__":
    import sys

    from email_parser import parse_eml

    path = sys.argv[1] if len(sys.argv) > 1 else "samples/phishing_credential.eml"
    with open(path, "rb") as fh:
        parsed = parse_eml(fh.read())
    iocs = extract(parsed)
    print("counts:", iocs["counts"])
    print("url_score: {:.2f}\n".format(iocs["url_score"]))
    for u in iocs["urls"]:
        mark = "SUSPICIOUS" if u["suspicious"] else "ok"
        print("[{}] {}  (host={})".format(mark, u["url"], u["host"]))
        for f in u["flags"]:
            print("     - {}".format(f))

    # Quick self-check of the look-alike logic.
    print("\nlook-alike spot checks:")
    for host in ["paypa1-support.com", "paypal.com", "micros0ft-securelogin.ru",
                 "accounts.google.com", "hdfc-netbanking.online"]:
        print("  {:32} -> {}".format(host, lookalike_brand(host)))
