"""entity_graph.py -- Phase 4: session-scoped Entity Graph  (Email -> Sender -> Domain -> IP -> URL -> Campaign).

Kept out of correlate.py on purpose: correlate.py imports plotly at module level and the scan path
(analyzer.py) must not depend on a plotting library. correlate.py is unchanged; NetworkX (already a
dependency) is used for the optional graph view via entity_digraph().

Edges are DERIVED from what the scan already produced (parsed headers, IOC extraction, geolocation, the Phase 2
fingerprint/matches) and each edge cites evidence-register ids that really exist in THIS scan's register -- an
edge with no valid evidence is never created. basis = "observed" (scanner output about this message, including
untrusted header claims, whose provenance says so) or "inferred" (the cited evidence is an inference or a
historical comparison). Similarity is never ownership: a "campaign" node is the Attack DNA fingerprint of one
retained scan, not an attributed actor. No model-generated text is ever used.

Storage: table entity_edges in the visitor's own database (tracker.get_connection(shared=False), so per-session
under SIH26106_MULTIUSER; created at runtime like attack_dna's table, no Supabase migration). Entity ids are
HMAC-SHA256 of the normalised value under a random per-session key kept in entity_meta of the same database.
Sender addresses are never stored; only domains, public IPs, URL hosts and opaque scan ids carry a readable label.
No email text is stored. The key is never silently regenerated while edges that depend on it exist.
Nothing here is read by risk.py and nothing here changes a score or verdict.

Result statuses (never conflated; see status_message()):
  ok                    edges derived and saved (skipped = relationships left out for lack of evidence, shown to the user)
  no_edges              the evidence register was available and nothing could be linked: a VALID empty graph. Any edges
                        previously saved for this scan are replaced by this empty result (never left behind as stale)
  insufficient_evidence the register is unavailable/incomplete (previous edges for the scan are kept untouched and reported,
                        because a failed evidence run says nothing about them), or relationships exist in the message but none
                        has a supporting evidence entry (previous edges are replaced: the current register cannot back them)
  unavailable           the session database could not be opened or prepared
  key_unavailable       the per-session key is missing/corrupt while edges depend on it: nothing is written or linked
  persistence_failed    edges were derived but could not be saved (save error, or no session storage so nothing would persist)
  error                 an unexpected failure while deriving edges
"""
import hashlib
import hmac
import ipaddress
import json
import re
import secrets

ENTITY_SCHEMA_VERSION = 1
MAX_STORED_EDGES = 20000
MAX_URL_ENTITIES = 20
MAX_SHARED_ENTITIES = 10
MAX_SHARED_SCANS = 5
ENTITY_LIMITATIONS = (
    "Relationships are limited to this session's retained scans; nothing is shared with other sessions.",
    "Observed means reported by a scanner about this message (header values remain untrusted claims); "
    "inferred means derived from an inference or a historical comparison. Neither proves ownership.",
    "A campaign node is the Attack DNA fingerprint of one retained scan; similarity is shared tactics, "
    "not confirmed common authorship.",
    "Entity ids are keyed hashes under a per-session key stored beside them: they hide sender addresses "
    "from casual inspection, not from someone who can read the session database.",
)

_E_SCAN_RE = re.compile(r"^SC-[0-9a-f]{32}$")
_E_EVID_RE = re.compile(r"^S\d{1,4}$")
_E_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
_E_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_E_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_E_NUMERIC_TLD_RE = re.compile(r"^(?:[0-9]+|0x[0-9a-f]*)$")      # decimal/hex last label: an obfuscated IP literal, never a hostname
_E_CLAIM_KEYS = {"from_address": "from_addr", "from_domain": "from_domain",
                 "reply_to_domain": "reply_to_domain", "return_path_domain": "return_path_domain"}
_E_TYPES = ("email", "sender", "domain", "ip", "url", "campaign")
_E_LABELLED = frozenset({"email", "domain", "ip", "url", "campaign"})      # a sender is never given a label
_E_HISTORY_TYPES = ("sender", "domain", "ip", "url")
_E_REL_TEXT = {
    "sent by": "was sent by", "from domain": "has From domain", "at domain": "is at domain", "replies to": "has Reply-To domain",
    "return path": "has Return-Path domain", "links to": "links to", "at host": "is hosted at",
    "originated at": "originated at", "fingerprinted as": "has the Attack DNA fingerprint of",
    "similar tactics to": "shows similar tactics to",
}
_E_PREFIX = {"url": "URL ", "email": "email ", "campaign": "campaign "}


def _e_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _e_unit(v):
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and 0.0 <= v <= 1.0 else None


def _e_routable(ip):
    """True only for an ordinary, publicly routable unicast address. ipaddress reports multicast (ff02::1, 224.0.0.1) as
    'global', which is not a host anyone can be 'at', so it is excluded together with private/reserved/loopback/link-local."""
    return bool(ip.is_global and not ip.is_multicast)


def _e_url_norm(v):
    """Normalised identity of an http(s) URL: scheme://host[:port]/path, or None when it is not safely normalisable.
    Userinfo, query and fragment are dropped (credentials and tokens never enter the identity); the path is kept so URL
    identities stay distinct, but it is never persisted in readable form. The host is a valid DNS name, a global IPv4 or a
    bracketed, canonically compressed global IPv6 literal; scoped or malformed IPv6, unbracketed IPv6, non-global IPs and
    obfuscated numeric hosts are rejected. A non-default port is kept; the default for the scheme (80 / 443) is dropped, so
    an explicit default port and no port give the same identity. A raw backslash in the authority (a browser reads it as a slash,
    so browsers and urlsplit() disagree about the host) and any string that cannot be strictly encoded as UTF-8 (a lone surrogate
    would crash HMAC id generation) are rejected. Never raises."""
    from urllib.parse import urlsplit
    try:
        v.encode("utf-8")                                       # strict: a lone surrogate would later crash HMAC id generation
    except UnicodeEncodeError:
        return None
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in v):
        return None
    try:
        p = urlsplit(v)
        scheme, netloc, path = p.scheme.lower(), p.netloc, p.path
    except ValueError:                                          # e.g. an unclosed IPv6 bracket
        return None
    if "\\" in netloc:                                          # a browser treats a backslash as a slash: its host is not urlsplit()'s
        return None
    if scheme not in ("http", "https") or not netloc:
        return None
    hostport = netloc.rpartition("@")[2]                        # everything before the LAST '@' is userinfo
    port_s = ""
    if hostport.startswith("["):                                # IPv6 literal: must be bracketed
        end = hostport.find("]")
        if end < 0:
            return None
        lit, rest = hostport[1:end], hostport[end + 1:]
        if rest:
            if not rest.startswith(":"):
                return None
            port_s = rest[1:]
        if "%" in lit:
            return None                                         # scoped / zone-id IPv6
        try:
            ip6 = ipaddress.IPv6Address(lit)
        except ValueError:                                      # malformed, or an IPv4 inside brackets
            return None
        if not _e_routable(ip6):
            return None
        host = "[%s]" % ip6.compressed
    else:
        if hostport.count(":") > 1:                             # unbracketed IPv6 is ambiguous with host:port
            return None
        h, _sep, port_s = hostport.partition(":")
        h = h.lower().rstrip(".")
        try:
            ip4 = ipaddress.IPv4Address(h)
        except ValueError:
            ip4 = None
        if ip4 is not None:
            if not _e_routable(ip4):
                return None
            host = str(ip4)
        else:
            host = _e_norm("domain", h)
            if host is None:
                return None
    port = ""
    if port_s:
        if not _E_PORT_RE.match(port_s):                        # ASCII digits only (no signs, spaces or Unicode digits)
            return None
        n = int(port_s)
        if not 1 <= n <= 65535:                                 # 0 and out-of-range are invalid endpoints
            return None
        if not ((scheme == "http" and n == 80) or (scheme == "https" and n == 443)):
            port = ":%d" % n
    return "%s://%s%s%s" % (scheme, host, port, path or "/")


def _e_host_type(host):
    """'ip' for an IPv4/IPv6 literal, otherwise 'domain' -- decided by parsing, never by the domain pattern."""
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"


def _e_host_key(text):
    """Canonical comparison key of a host given as text (brackets and IPv6 spelling ignored), or None."""
    if not isinstance(text, str):
        return None
    h = text.strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if not h or "%" in h:
        return None
    try:
        return ipaddress.ip_address(h).compressed
    except ValueError:
        return h


def _e_norm(typ, value):
    """Normalised identity of an entity, or None when the value is not a valid member of its type."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or len(v) > 2048:
        return None
    if typ == "sender":
        from email.utils import parseaddr
        addr = parseaddr(v)[1].strip().lower()
        return addr if "@" in addr and 3 <= len(addr) <= 254 and " " not in addr else None
    if typ == "domain":
        d = v.lower().rstrip(".")
        if not _E_DOMAIN_RE.match(d) or _E_NUMERIC_TLD_RE.match(d.rsplit(".", 1)[-1]):
            return None                                         # an IPv4 (or decimal/hex IP) literal is never a hostname
        return d
    if typ == "ip":
        if "%" in v:
            return None                                         # scoped IPv6 (fe80::1%eth0): ipaddress accepts it, we do not
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return None
        return ip.compressed if _e_routable(ip) else None      # private/reserved/multicast addresses would falsely correlate
    if typ == "url":
        return _e_url_norm(v)
    if typ in ("email", "campaign"):
        return v if _E_SCAN_RE.match(v) else None
    return None


def _e_label(typ, norm):
    if typ not in _E_LABELLED:
        return None
    if typ == "url":
        from urllib.parse import urlsplit
        return urlsplit(norm).hostname
    return norm


def _e_id(key, typ, norm):
    mac = hmac.new(key, ("%s\x00%s" % (typ, norm)).encode("utf-8"), hashlib.sha256).hexdigest()
    return "%s:%s" % (typ, mac[:32])


def _e_ensure(conn):
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS entity_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            schema_version INTEGER NOT NULL,
            scan_id TEXT NOT NULL,
            src_id TEXT NOT NULL, src_type TEXT NOT NULL, src_label TEXT,
            rel TEXT NOT NULL,
            dst_id TEXT NOT NULL, dst_type TEXT NOT NULL, dst_label TEXT,
            basis TEXT NOT NULL CHECK (basis IN ('observed', 'inferred')),
            evidence_json TEXT NOT NULL,
            evidence_note TEXT,
            provenance TEXT NOT NULL,
            confidence REAL, score REAL, detail TEXT,
            ref TEXT NOT NULL DEFAULT '',
            observed_at TEXT NOT NULL,
            UNIQUE (scan_id, src_id, rel, dst_id, ref)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_entity_edges_src ON entity_edges(src_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_entity_edges_dst ON entity_edges(dst_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_entity_edges_scan ON entity_edges(scan_id)")
    c.execute("CREATE TABLE IF NOT EXISTS entity_meta (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.commit()


def _e_session_key(conn):
    """The per-session HMAC key (32 random bytes), created once. Returns None -- never a new key -- when a stored
    key is missing or corrupt while edges that depend on it exist: regenerating would orphan or mis-link them."""
    c = conn.cursor()
    row = c.execute("SELECT value FROM entity_meta WHERE name = 'hmac_key'").fetchone()
    if row and isinstance(row[0], str) and _E_KEY_RE.match(row[0]):
        return bytes.fromhex(row[0])
    if c.execute("SELECT 1 FROM entity_edges LIMIT 1").fetchone() is not None:
        return None
    if row:
        c.execute("UPDATE entity_meta SET value = ? WHERE name = 'hmac_key'", (secrets.token_hex(32),))
    else:
        c.execute("INSERT OR IGNORE INTO entity_meta (name, value) VALUES ('hmac_key', ?)", (secrets.token_hex(32),))
    conn.commit()
    row = c.execute("SELECT value FROM entity_meta WHERE name = 'hmac_key'").fetchone()
    return bytes.fromhex(row[0]) if row and isinstance(row[0], str) and _E_KEY_RE.match(row[0]) else None


def derive_entity_edges(result, key, now=None):
    """PURE. -> (edges, skipped). One edge per relationship that has at least one valid evidence id from THIS scan's
    register; anything else is counted in `skipped`, never invented. Does not mutate `result`."""
    r = result if isinstance(result, dict) else {}
    sid = r.get("scan_id") if isinstance(r.get("scan_id"), str) and _E_SCAN_RE.match(r.get("scan_id")) else None
    skipped = {"no_evidence": 0, "invalid_entity": 0}
    if not sid:
        return [], dict(skipped, reason="no_scan_id")
    reg = [e for e in (r.get("evidence_register") or []) if isinstance(e, dict) and isinstance(e.get("id"), str)
           and _E_EVID_RE.match(e["id"]) and e.get("scan_id") == sid] if isinstance(r.get("evidence_register"), list) else []
    if not reg:
        return [], dict(skipped, reason="no_evidence_register")
    by_id = {e["id"]: e for e in reg}
    now = now or _e_now()
    edges, seen = [], set()

    def find(typ, source, ref, origin=None, contains=None):
        for e in reg:
            if (e.get("type") == typ and e.get("source") == source and e.get("source_reference") == ref
                    and e.get("status") in ("ok", "partial") and (origin is None or e.get("origin") == origin)
                    and (contains is None or contains in str(e.get("observation") or ""))):
                return e["id"]
        return None

    def claim(kind, domain_norm):
        """The id of THE evidence entry for exactly this claim and value (never a neighbouring header entry): type, source,
        provenance (an untrusted claim stays an untrusted claim -- any other origin is rejected, never upgraded), status, source
        reference, claim kind and the recorded domain must all agree with the value the edge is about."""
        ref = "result.parsed." + _E_CLAIM_KEYS[kind]
        for e in reg:
            m = e.get("metadata")
            if (e.get("type") == "header" and e.get("source") == "email_parser" and e.get("origin") == "untrusted_claim"
                    and e.get("status") == "ok" and e.get("source_reference") == ref and isinstance(m, dict)
                    and m.get("claim") == kind and m.get("domain") == domain_norm):
                return e["id"]
        return None

    def ent(typ, value):
        n = _e_norm(typ, value)
        return None if n is None else {"id": _e_id(key, typ, n), "type": typ, "label": _e_label(typ, n)}

    def link(src, rel, dst, ev_ids, ref="", score=None, confidence=None, detail=None):
        if src is None or dst is None:
            skipped["invalid_entity"] += 1
            return
        ids = [i for i in dict.fromkeys(ev_ids) if i in by_id]
        if not ids or len(ids) != len([i for i in ev_ids if i]):
            skipped["no_evidence"] += 1
            return
        k = (src["id"], rel, dst["id"], ref)
        if k in seen:
            return
        seen.add(k)
        cited = [by_id[i] for i in ids]
        basis = "inferred" if any(e.get("origin") in ("inference", "historical") for e in cited) else "observed"
        conf = confidence if confidence is not None else _e_unit(cited[0].get("confidence"))
        edges.append({
            "scan_id": sid, "src": src, "rel": rel, "dst": dst, "basis": basis, "evidence": ids,
            "evidence_note": str(cited[0].get("observation") or "")[:300],
            "provenance": "; ".join(sorted({"%s:%s" % (e.get("source"), e.get("origin")) for e in cited}))[:200],
            "confidence": conf, "score": score, "detail": detail, "ref": ref, "observed_at": now})

    parsed = r.get("parsed") if isinstance(r.get("parsed"), dict) else {}
    iocs = r.get("iocs") if isinstance(r.get("iocs"), dict) else {}
    geo = r.get("geo") if isinstance(r.get("geo"), dict) else {}
    email = ent("email", sid)

    # Each relationship cites its OWN claim entry (see claim()); the combined 'sender identity' entry is never reused.
    sender_n = _e_norm("sender", parsed.get("from_addr"))
    if sender_n:
        addr_dom_n = _e_norm("domain", sender_n.rsplit("@", 1)[1])
        sender = ent("sender", parsed.get("from_addr"))
        c = claim("from_address", addr_dom_n) if addr_dom_n else None
        link(email, "sent by", sender, [c] if c else [])
        link(sender, "at domain", ent("domain", addr_dom_n) if addr_dom_n else None, [c] if c else [])
    for rel, kind, k in (("from domain", "from_domain", "from_domain"), ("replies to", "reply_to_domain", "reply_to_domain"),
                         ("return path", "return_path_domain", "return_path_domain")):
        if parsed.get(k):
            dn = _e_norm("domain", parsed.get(k))
            c = claim(kind, dn) if dn else None
            link(email, rel, ent("domain", parsed.get(k)), [c] if c else [])

    # URL relationships need an EXACT per-item evidence entry (source reference result.iocs.urls[<index>]) whose recorded host
    # equals the host of the URL itself. The aggregate "N URL(s) extracted" entry records counts, not the identity of any URL, so
    # it is never used here; a URL without its own entry (unflagged, or beyond the register's per-item limit) is skipped and counted.
    def url_evidence(n, norm_url):
        want = _e_host_key(_e_label("url", norm_url))       # the URL's own normalised host -- not the extractor's separate 'host' field
        for e in reg:
            m = e.get("metadata")
            if (e.get("type") == "URL" and e.get("source") == "ioc_extract" and e.get("origin") == "direct_machine"
                    and e.get("status") == "ok" and e.get("source_reference") == "result.iocs.urls[%d]" % n and isinstance(m, dict)
                    and want is not None and _e_host_key(m.get("host")) == want):
                return e["id"]
        return None

    urls = iocs.get("urls") if isinstance(iocs.get("urls"), list) else []
    for n, u in enumerate(urls[:MAX_URL_ENTITIES]):
        if not isinstance(u, dict):
            continue
        url_n = _e_norm("url", u.get("url"))
        ev_id = url_evidence(n, url_n) if url_n else None
        url = ent("url", u.get("url"))
        link(email, "links to", url, [ev_id] if ev_id else [])
        if url:
            host_v = _e_label("url", url_n)
            host = ent(_e_host_type(host_v), host_v)           # an IP literal is an ip node, a DNS name a domain node
            link(url, "at host", host, [ev_id] if ev_id else [])

    def geo_evidence(ip_norm):
        """The GeoIP entry for exactly THIS origin IP: scanner type/source, provenance 'inference' (never upgraded), ok/partial
        status, the exact source reference, and a STRUCTURED metadata IP that parses to the same address as the one the graph
        uses. The observation text is never read for this, and another IP's entry is never substituted."""
        for e in reg:
            m = e.get("metadata")
            if (e.get("type") == "GeoIP" and e.get("source") == "geolocate" and e.get("origin") == "inference"
                    and e.get("status") in ("ok", "partial") and e.get("source_reference") == "result.geo.origin"
                    and isinstance(m, dict) and _e_norm("ip", m.get("ip")) == ip_norm):
                return e["id"]
        return None

    origin = geo.get("origin") if isinstance(geo.get("origin"), dict) else {}
    if origin.get("ip"):
        ip_n = _e_norm("ip", origin.get("ip"))
        g = geo_evidence(ip_n) if ip_n else None
        link(email, "originated at", ent("ip", origin.get("ip")), [g] if g else [])

    fp_ev = find("campaign fingerprint", "attack_dna", "result.campaign_fingerprint", origin="direct_machine")
    if isinstance(r.get("campaign_fingerprint"), dict) and fp_ev:
        me = ent("campaign", sid)
        link(email, "fingerprinted as", me, [fp_ev])
        cm = r.get("campaign_matches") if isinstance(r.get("campaign_matches"), dict) else {}
        import attack_dna
        import campaign_intel
        for m in [x for x in (cm.get("matches") or []) if isinstance(x, dict)][:campaign_intel.MAX_RELATIONSHIPS] if cm.get("status") == "ok" else []:
            mid = m.get("scan_id")
            cls = m.get("classification")
            if cls not in ("strong", "weak") or not isinstance(mid, str) or not _E_SCAN_RE.match(mid) or mid == sid:
                continue
            hist = find("campaign fingerprint", "attack_dna", "result.campaign_matches", origin="historical", contains="(scan %s)" % mid)
            fams = sorted(f for f in (m.get("matched_families") or {}) if isinstance(f, str) and f in attack_dna.FAMILY_WEIGHTS) \
                if isinstance(m.get("matched_families"), dict) else []
            link(me, "similar tactics to", ent("campaign", mid), [fp_ev, hist] if hist else [],
                 ref=mid, score=_e_unit(m.get("score")), confidence=_e_unit(m.get("confidence")),
                 detail="%s; families: %s" % (cls, ", ".join(fams) or "none"))
    return edges, skipped


def _e_disp(side):
    if side.get("label"):
        return _E_PREFIX.get(side.get("type"), "") + str(side["label"])
    return "%s #%s" % (side.get("type"), str(side.get("id", ":")).split(":", 1)[-1][:6])


def explain_edge(edge):
    """Plain-language reason built ONLY from the edge's own stored fields (relationship, basis, provenance, cited
    evidence ids and note, preserved score). No model output; nothing is added that the evidence does not say."""
    if not isinstance(edge, dict) or not isinstance(edge.get("src"), dict) or not isinstance(edge.get("dst"), dict):
        return ""
    ev_ids = ", ".join(str(i) for i in (edge.get("evidence") or []))
    rel = _E_REL_TEXT.get(edge.get("rel"), str(edge.get("rel")))
    head = "%s %s %s" % (_e_disp(edge["src"]), rel, _e_disp(edge["dst"]))
    if edge.get("rel") == "similar tactics to":
        sc = edge.get("score")
        return ("Inferred, not observed: %s. Attack DNA reported %s (Phase 2 score %s) between the two retained scans; "
                "evidence %s. This is shared tactics, not confirmed common authorship." % (
                    head, edge.get("detail") or "a structural similarity", "%.2f" % sc if isinstance(sc, float) else "n/a", ev_ids))
    kind = "Observed in this scan" if edge.get("basis") == "observed" else "Inferred (approximate), not directly observed"
    return "%s: %s. Evidence %s (%s): %s" % (kind, head, ev_ids, edge.get("provenance"), edge.get("evidence_note") or "no note")


def edge_title(edge):
    """Short 'source --relationship--> target' label for tables (labels only; a sender shows as an opaque tag)."""
    if not isinstance(edge, dict) or not isinstance(edge.get("src"), dict) or not isinstance(edge.get("dst"), dict):
        return ""
    return "%s \u2014 %s \u2192 %s" % (_e_disp(edge["src"]), edge.get("rel"), _e_disp(edge["dst"]))


def _e_public(edge):
    out = dict(edge)
    out["explanation"] = explain_edge(edge)
    return out


def _e_save(conn, scan_id, edges):
    c = conn.cursor()
    try:
        c.execute("DELETE FROM entity_edges WHERE scan_id = ?", (scan_id,))
        for e in edges:
            c.execute("""INSERT OR REPLACE INTO entity_edges
                (schema_version, scan_id, src_id, src_type, src_label, rel, dst_id, dst_type, dst_label, basis,
                 evidence_json, evidence_note, provenance, confidence, score, detail, ref, observed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (ENTITY_SCHEMA_VERSION, scan_id, e["src"]["id"], e["src"]["type"], e["src"]["label"], e["rel"],
                       e["dst"]["id"], e["dst"]["type"], e["dst"]["label"], e["basis"], json.dumps(e["evidence"]),
                       e["evidence_note"], e["provenance"], e["confidence"], e["score"], e["detail"], e["ref"], e["observed_at"]))
        c.execute("DELETE FROM entity_edges WHERE id NOT IN (SELECT id FROM entity_edges ORDER BY id DESC LIMIT ?)",
                  (MAX_STORED_EDGES,))
        conn.commit()
        return True
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return False


def _e_shared(conn, edges, scan_id):
    """Entities of this scan (sender/domain/ip/url) that ALSO appear in other retained scans of this session."""
    mine = {}
    for e in edges:
        for side in (e["src"], e["dst"]):
            if side["type"] in _E_HISTORY_TYPES:
                mine[side["id"]] = side
    if not mine:
        return []
    ids = sorted(mine)
    q = ",".join("?" * len(ids))
    rows = conn.cursor().execute(
        "SELECT scan_id, src_id, rel, dst_id, evidence_json, observed_at FROM entity_edges "
        "WHERE scan_id != ? AND (src_id IN (%s) OR dst_id IN (%s)) ORDER BY observed_at DESC, id DESC LIMIT 200" % (q, q),
        [scan_id] + ids + ids).fetchall()
    grouped = {}
    for sc, src_id, rel, dst_id, ev_json, seen_at in rows:
        try:
            ev = [str(i) for i in json.loads(ev_json) if _E_EVID_RE.match(str(i))]
        except Exception:
            ev = []
        for role, eid in (("source", src_id), ("target", dst_id)):
            if eid in mine:
                lst = grouped.setdefault(eid, [])
                if len(lst) < MAX_SHARED_SCANS and not any(x["scan_id"] == sc and x["rel"] == rel for x in lst):
                    lst.append({"scan_id": sc, "rel": rel, "role": role, "observed_at": seen_at,
                                "evidence": ["%s:%s" % (sc, i) for i in ev]})
    order = sorted(grouped, key=lambda i: (-len(grouped[i]), i))[:MAX_SHARED_ENTITIES]
    return [{"entity": mine[i], "scans": grouped[i]} for i in order]


def _e_evidence_state(r):
    """(usable, reason). 'Usable' means this scan has a register to derive from. An evidence-GENERATION failure (builder
    error, missing/empty/foreign register, no scan id) is not the same thing as a valid empty graph and is reported apart."""
    sid = r.get("scan_id")
    if not (isinstance(sid, str) and _E_SCAN_RE.match(sid)):
        return False, "no_scan_id"
    if r.get("evidence_error"):
        return False, "evidence_unavailable"
    reg = r.get("evidence_register")
    if not isinstance(reg, list) or not any(isinstance(e, dict) and e.get("scan_id") == sid for e in reg):
        return False, "evidence_unavailable"
    return True, None


def _e_ephemeral(conn):
    """True when the connection is an in-memory/temporary database (e.g. multi-user mode with no identifiable session):
    anything written would vanish on close, so it must not be reported as saved."""
    try:
        return not any(row[2] for row in conn.execute("PRAGMA database_list").fetchall() if row[1] == "main")
    except Exception:
        return False


def build_entity_graph(result):
    """result["entity_graph"]. Never raises, never mutates `result`, never touches a score or verdict; every problem is a
    distinct status (see the module docstring), never an exception and never a silent 'no relationships'."""
    r = result if isinstance(result, dict) else {}
    base = {"schema_version": ENTITY_SCHEMA_VERSION, "status": None, "reason": None, "edges": [], "shared_entities": [],
            "stored": False, "skipped": {"no_evidence": 0, "invalid_entity": 0}, "retained_previous_edges": 0,
            "limitations": list(ENTITY_LIMITATIONS)}
    usable, why = _e_evidence_state(r)
    conn = None
    try:
        import tracker
        try:
            conn = tracker.get_connection(shared=False)
            _e_ensure(conn)
            key = _e_session_key(conn) if usable else b""
        except Exception:
            return dict(base, status="unavailable", reason="database_error")
        sid = r.get("scan_id") if isinstance(r.get("scan_id"), str) and _E_SCAN_RE.match(r.get("scan_id")) else None
        if not usable:
            out = dict(base, status="insufficient_evidence", reason=why)
            if sid:
                try:                                   # previous edges are NOT touched: a failed evidence run proves nothing about them
                    out["retained_previous_edges"] = conn.execute("SELECT COUNT(*) FROM entity_edges WHERE scan_id = ?", (sid,)).fetchone()[0]
                except Exception:
                    pass
            return out
        if key is None:
            return dict(base, status="key_unavailable", reason="session_key_missing")
        try:
            edges, skipped = derive_entity_edges(r, key)
        except Exception:
            return dict(base, status="error", reason="derivation_failed")
        out = dict(base, skipped={"no_evidence": skipped.get("no_evidence", 0), "invalid_entity": skipped.get("invalid_entity", 0)})
        out["edges"] = [_e_public(e) for e in edges]
        ephemeral = _e_ephemeral(conn)
        # Replace this scan's edges with what the CURRENT register supports -- including an empty set -- so nothing outdated stays.
        out["stored"] = (not ephemeral) and _e_save(conn, sid, edges)
        if not out["stored"]:
            return dict(out, status="persistence_failed", reason="no_session_storage" if ephemeral else "save_failed")
        if edges:
            out["shared_entities"] = _e_shared(conn, edges, sid)
            return dict(out, status="ok")
        if out["skipped"]["no_evidence"] > 0:
            return dict(out, status="insufficient_evidence", reason="relationships_unsupported")
        return dict(out, status="no_edges")
    except Exception:
        return dict(base, status="error", reason="unexpected")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def status_message(eg):
    """(level, text) for the UI and the report -- ONE place, so a failed or incomplete graph is never presented as 'no
    relationships detected'. level: 'ok' (nothing to say), 'info', 'warning', 'error'."""
    if not isinstance(eg, dict):
        return "warning", ("The entity graph could not be computed for this scan. This is not a finding that no relationships exist.")
    st, why = eg.get("status"), eg.get("reason")
    sk = eg.get("skipped") if isinstance(eg.get("skipped"), dict) else {}
    n_skip = sk.get("no_evidence") if isinstance(sk.get("no_evidence"), int) else 0
    if st == "ok":
        return ("info", "%d possible relationship(s) were left out because no supporting evidence entry exists for them." % n_skip) if n_skip else ("ok", "")
    if st == "no_edges":
        return "info", ("No relationships were detected for this scan: its evidence was available and no sender, domain, IP, URL or "
                        "campaign link could be formed. Any earlier relationships saved for this scan were replaced by this result.")
    if st == "insufficient_evidence":
        if why == "relationships_unsupported":
            return "warning", ("%d possible relationship(s) were found in the message but none has a supporting evidence entry, so none "
                               "is shown. This is not a clean result." % n_skip)
        kept = eg.get("retained_previous_edges") if isinstance(eg.get("retained_previous_edges"), int) else 0
        return "warning", ("Relationships could not be established because this scan's evidence register is %s. This is not a finding "
                           "that no relationships exist.%s" % (
                               "missing its scan identity" if why == "no_scan_id" else "unavailable or incomplete",
                               " %d relationship(s) saved earlier for this scan were kept unchanged and may be out of date." % kept if kept else ""))
    if st == "unavailable":
        return "error", "The session database was unavailable, so no entity graph was produced or saved. This is not a finding that no relationships exist."
    if st == "key_unavailable":
        return "error", ("The session's hashing key is missing while saved relationships depend on it, so the graph was withheld instead of "
                         "risking wrong links. Nothing was written.")
    if st == "persistence_failed":
        return "warning", ("Relationships were derived but could not be saved (%s). They are shown for this scan only; history across "
                           "scans is unavailable until saving works." % (
                               "no session storage is available" if why == "no_session_storage" else "the database rejected the write"))
    if st == "error":
        return "error", "An unexpected error stopped the entity graph from being built. This is not a finding that no relationships exist."
    return "warning", "The entity graph is in an unrecognised state and was not used."


_E_VIS_KIND = {"email": "case", "sender": "email", "domain": "domain", "ip": "ip", "url": "infra", "campaign": "semantic"}
_E_SHORT_RE = re.compile(r"SC-([0-9a-f]{8})[0-9a-f]{24}")


def to_correlation_graph(entity_graph):
    """Adapter: the edges of result["entity_graph"] (plus the other retained scans that share an entity) as a plain NetworkX
    DiGraph in the shape correlate.graph_figure() already draws -- node 'kind' limited to its NODE_STYLE kinds, one edge per
    node pair (parallel relationships merged into one label), observed vs inferred in the label, the Phase 2 score as
    'similarity'. correlate.py is not touched and plotly is not imported here, so this runs wherever the scan path does."""
    import networkx as nx
    G = nx.DiGraph()
    if not isinstance(entity_graph, dict):
        return G

    def short(t):
        return _E_SHORT_RE.sub(lambda m: "SC-%s\u2026" % m.group(1), str(t))

    def node(side):
        if isinstance(side, dict) and side.get("id") not in G:
            G.add_node(side.get("id"), kind=_E_VIS_KIND.get(side.get("type"), "semantic"), label=short(_e_disp(side)))

    def add_edge(u, v, rel, similarity=None):
        if G.has_edge(u, v):
            if rel not in G[u][v]["rel"].split(" / "):
                G[u][v]["rel"] += " / " + rel
        else:
            G.add_edge(u, v, rel=rel)
        if isinstance(similarity, float):
            G[u][v]["similarity"] = similarity

    for e in (entity_graph.get("edges") or []):
        if isinstance(e, dict) and isinstance(e.get("src"), dict) and isinstance(e.get("dst"), dict):
            node(e["src"])
            node(e["dst"])
            add_edge(e["src"]["id"], e["dst"]["id"], "%s%s" % (e.get("rel"), " (inferred)" if e.get("basis") == "inferred" else ""),
                     e.get("score") if e.get("rel") == "similar tactics to" else None)
    for s in (entity_graph.get("shared_entities") or []):
        if isinstance(s, dict) and isinstance(s.get("entity"), dict) and s["entity"].get("id") in G:
            for sc in [x for x in (s.get("scans") or []) if isinstance(x, dict) and _E_SCAN_RE.match(str(x.get("scan_id")))]:
                nid = "scan:" + sc["scan_id"]
                if nid not in G:
                    G.add_node(nid, kind="case", label=short("scan " + sc["scan_id"]))
                add_edge(nid, s["entity"]["id"], "also seen (%s)" % sc.get("rel"))
    return G


def entity_digraph(entity_graph):
    """The (validated) edges of result["entity_graph"] as a NetworkX MultiDiGraph, reusing the engine already used above."""
    import networkx as nx
    G = nx.MultiDiGraph()   # several relationships may join the same two entities
    for e in (entity_graph.get("edges") if isinstance(entity_graph, dict) else None) or []:
        if not isinstance(e, dict) or not isinstance(e.get("src"), dict) or not isinstance(e.get("dst"), dict):
            continue
        for side in (e["src"], e["dst"]):
            if side.get("id") not in G:
                G.add_node(side.get("id"), kind=side.get("type"), label=_e_disp(side))
        G.add_edge(e["src"]["id"], e["dst"]["id"], rel=e.get("rel"), basis=e.get("basis"),
                   evidence=list(e.get("evidence") or []), confidence=e.get("confidence"), score=e.get("score"))
    return G


