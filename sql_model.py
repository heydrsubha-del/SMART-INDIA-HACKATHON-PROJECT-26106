"""PYTHON MODEL of the exported/proposed SQL validators - NOT PostgreSQL. Used only to catch mistakes in expectations offline.
Constants (IP ranges, domain regexes) are parsed from the audit CSVs, not retyped. Regex dialect differences (POSIX vs Python re) are
negligible for these simple patterns but are one reason validation_checks.sql must still be run on the test project."""
import csv, glob, ipaddress, math, os, re

def audit_dir():
    for d in (os.environ.get("AUDIT_DIR"), "security_audit_inputs", "/mnt/user-data/uploads"):
        if d and glob.glob(os.path.join(d, "*.csv")):
            return d
    raise FileNotFoundError("set AUDIT_DIR to the folder with the five CSV exports")

def _all_text():
    out = []
    for f in sorted(glob.glob(os.path.join(audit_dir(), "*.csv"))):
        out.append(open(f, newline="", encoding="utf-8").read().replace("\r", ""))
    return "\n".join(out)

_T = _all_text()
_NETS = [ipaddress.ip_network(x) for x in re.search(r"private\.is_public_ip.*?array\[(.*?)\]::inet\[\]", _T, re.S).group(1).replace("'", "").replace("\n", " ").split(",") if x.strip() for x in [x.strip()]]
_DOM_RE = re.search(r"valid_domain\(p_d text\).*?select p_d ~ '([^']+)'", _T, re.S).group(1)
_RES_RE = re.search(r"p_d !~ '([^']+)'", _T).group(1)
SUFFIXES = {"co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","co.in","co.jp","com.br","com.cn","co.nz","co.za","com.mx","com.tr","com.sg","com.hk"}

def entropy(t):
    n = len(t)
    return -sum((t.count(c)/n) * math.log2(t.count(c)/n) for c in set(t)) if n else 0.0

def looks_like_token(s):                      # port of private.looks_like_token (exported, unchanged by the migration)
    if s is None or s == "": return False
    if len(s) > 64 or re.search("[@=%]", s): return True
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s, re.I) or re.fullmatch(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", s): return True
    if re.fullmatch(r"[0-9a-f]{16,}", s, re.I) or (re.fullmatch(r"[0-9]+", s) and len(s) >= 8): return True
    parts = [p for p in re.split(r"[-_.]", s) if p]
    if all((re.fullmatch(r"[A-Za-z]+", p) and len(p) <= 14) or (re.fullmatch(r"[0-9]+", p) and len(p) <= 4) for p in parts): return False
    letters, digits = len(re.sub(r"[^A-Za-z]", "", s)), len(re.sub(r"[^0-9]", "", s))
    return (len(s) >= 12 and digits >= 3 and letters >= 3) or len(s) >= 16

BIGRAMS = ['th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd', 'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar', 'st', 'to', 'nt', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le', 've', 'co', 'me', 'de', 'hi', 'ri', 'ro', 'ic', 'ne', 'ea', 'ra', 'ce', 'li', 'ch', 'll', 'be', 'ma', 'si', 'om', 'ur', 'ca', 'el', 'ta', 'la', 'ns', 'di', 'fo', 'ho', 'pe', 'ec', 'pr', 'no', 'ct', 'us', 'ac', 'ot', 'il', 'tr', 'ly', 'nc', 'et', 'ut', 'ss', 'so', 'rs', 'un', 'lo', 'wa', 'ge', 'ie', 'wh', 'ee', 'wi', 'em', 'ad', 'ol', 'rt', 'po', 'we', 'na', 'ul', 'ni', 'ts', 'mo', 'ow', 'pa', 'im', 'mi', 'ai', 'sh', 'ir', 'su', 'id', 'os', 'iv', 'ia', 'am', 'fi', 'ci', 'vi', 'pl', 'ig', 'tu', 'ev', 'ld', 'ry', 'mp', 'fe', 'bl', 'ab', 'gh', 'ty', 'op', 'wo', 'sa', 'ay', 'ex', 'ke', 'fr', 'oo', 'av', 'ag', 'if', 'ap', 'gr', 'od', 'bo', 'sp', 'rd', 'do', 'uc', 'bu', 'ei', 'ov', 'by', 'rm', 'ep', 'tt', 'ew', 'ga']
def readable_exception(l):                    # block R of private.valid_host_labels (proposed)
    if not (re.fullmatch("[a-z]+", l) and not re.fullmatch("[a-f]+", l) and 16 <= len(l) <= 24): return False
    hits = sum(l[i:i + 2] in BIGRAMS for i in range(len(l) - 1))
    return hits * 100 >= 65 * (len(l) - 1) and entropy(l) < 3.7

def label_rejected(l):
    return looks_like_token(l) and not readable_exception(l)

def valid_host_labels(d):                     # proposed private.valid_host_labels
    if d is None: return False
    l = d.split("."); n = len(l)
    if n < 2: return False
    keep = 3 if ".".join(l[-2:]) in SUFFIXES else 2
    return not any(label_rejected(x) for x in l[:n - keep])

def valid_domain(d):                          # exported private.valid_domain
    return bool(re.search(_DOM_RE, d)) and len(d) <= 253 and not re.search(_RES_RE, d)

def is_public_ip(p):                          # exported private.is_public_ip
    try:
        if "/" in p: return False
        v = ipaddress.ip_address(p)
    except ValueError:
        return False
    return not any(v.version == n.version and v in n for n in _NETS)

def valid_indicator(kind, v, labels=True):    # labels=False models the CURRENT exported function
    if v is None or not 3 <= len(v) <= 512 or re.search(r"[@?#%\s]", v): return False
    if kind == "hash": return bool(re.fullmatch(r"([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})", v))
    if kind == "ip": return is_public_ip(v)
    dom = lambda h: valid_domain(h) and (valid_host_labels(h) if labels else True)
    if kind == "domain": return dom(v)
    if kind == "url":
        m = re.fullmatch(r"https?://([a-z0-9.-]+)((/[A-Za-z0-9._~-]*)*)", v)
        if not m: return False
        if not (dom(m.group(1)) or (re.fullmatch(r"[0-9.]+", m.group(1)) and is_public_ip(m.group(1)))): return False
        return not any(s != "" and looks_like_token(s) for s in m.group(2).split("/"))
    return False
