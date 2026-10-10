"""Module 2 (part 2): SPF / DKIM / DMARC verdicts and spoofing anomalies.

We READ the authentication results that the receiving mail server already
computed and stamped into the headers. That is what real forensic tooling does
for a message captured after the fact - re-running SPF live would need DNS and
would give a different answer than at delivery time.

On top of that we look for structural giveaways: envelope/header domain
mismatches, a Reply-To pointing somewhere else, a display name claiming a brand
it does not own, and the classic BEC pattern.

Standalone:  python header_analysis.py samples/phishing_bec.eml
"""
import os
import re

import config as C

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

try:                                    # reuse the app's registrable-domain helper
    from domain_intel import registrable as _registrable
except Exception:                       # keep this module usable on its own
    def _registrable(domain):
        parts = (domain or "").split(".")
        return ".".join(parts[-2:]) if len(parts) > 2 else domain


def org_domain(domain):
    """Organisational (registrable) domain: 'scoutcamp.bounces.google.com' -> 'google.com'.
    Hosts under a shared-hosting parent (github.io, blogspot.com, ...) are different
    organisations, so for those the tenant label is kept: 'a.github.io'."""
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return ""
    for suffix in getattr(C, "SHARED_HOSTING_SUFFIXES", ()):
        if d == suffix or d.endswith("." + suffix):
            return ".".join(d.split(".")[-(len(suffix.split(".")) + 1):])
    return _registrable(d)


def same_org(a, b):
    return bool(a and b and org_domain(a) == org_domain(b))


def _domains_after(auth_text, key):
    """Domains named by `key=` in the auth header (smtp.mailfrom=, header.d=, header.i=)."""
    out = []
    for value in re.findall(r"\b{}\s*=\s*\"?([^\s;()\"<>]+)".format(re.escape(key)), auth_text or "", re.I):
        dom = value.rsplit("@", 1)[-1].strip().lower().rstrip(".")
        if dom and dom not in out:
            out.append(dom)
    return out


_FAILISH = ("fail", "softfail", "permerror", "temperror", "policy")
_MECHS = ("spf", "dkim", "dmarc")


def trusted_authservs(override=None):
    """authserv-ids whose Authentication-Results this deployment trusts."""
    ids = set(override) if override is not None else set(getattr(C, "TRUSTED_AUTHSERV_IDS", ()) or ())
    if override is None:
        ids |= {x.strip() for x in os.environ.get("ALGORITHMISTIC_TRUSTED_AUTHSERV", "").split(",") if x.strip()}
    return {str(i).strip().lower().rstrip(".") for i in ids if str(i).strip()}


def _authserv_id(value):
    first = (value or "").split(";", 1)[0].split()
    return first[0].strip().lower().rstrip(".") if first else ""


def _find(value, mech):
    m = re.search(r"\b{}\s*=\s*([a-z]+)".format(mech), value or "", re.I)
    return m.group(1).lower() if m else None


def _boundary_problem(h, parsed):
    """None when the header sits in the receiving server's own block, else why not.
    Receivers PREPEND their headers, so headers the sender wrote are below every
    receiver-added Received header. A trusted result must be above the second Received
    header (or above the only one)."""
    idx, recv = h.get("index"), parsed.get("received_positions") or []
    if idx is None or not recv:
        return "header position / Received chain unavailable, so the receiving boundary cannot be established"
    limit = recv[1] if len(recv) > 1 else recv[0]
    return None if idx < limit else "header sits below the receiving server's block (could have been written by the sender)"


def _auth_headers(parsed):
    hs = parsed.get("auth_headers")
    if hs is not None:
        return hs
    legacy = parsed.get("auth_results", "")      # flattened input with no provenance
    return [{"name": "Authentication-Results", "value": legacy, "index": None}] if legacy else []


def _rank(r):
    return 2 if r in _FAILISH else (0 if r == "pass" else 1)


def collect_auth_evidence(parsed, trusted=None):
    """Per mechanism: {result, provenance: verified|unverified|unknown, confidence, source, note}.
    A result is 'verified' only if its Authentication-Results header (1) names a configured
    trusted authserv-id, (2) is the topmost header with that id (lower duplicates are not
    evidence: a compliant receiver strips pre-existing ones), and (3) lies in the receiving
    server's own header block. Received-SPF and ARC headers carry no authserv-id and are never
    verified. Parsing alone cannot prove a header was not forged; this is the safest rule
    available without the provider's own configuration."""
    trusted = trusted_authservs() if trusted is None else {str(t).lower() for t in trusted}
    claims = {m: [] for m in _MECHS}
    seen = set()
    verified_text = []
    for h in _auth_headers(parsed):
        name, value = (h.get("name") or "").lower(), h.get("value") or ""
        sid, ok, why = "", False, ""
        if name == "authentication-results":
            sid = _authserv_id(value)
            first = sid not in seen
            seen.add(sid)
            if not sid:
                why = "no authserv-id"
            elif sid not in trusted:
                why = "authserv-id '{}' is not a configured trusted server".format(sid)
            elif not first:
                why = "not the topmost header for '{}'".format(sid)
            else:
                why = _boundary_problem(h, parsed) or ""
                ok = not why
        elif name == "received-spf":
            why = "Received-SPF carries no authserv-id"
        else:
            why = "ARC header is not a receiving-server verdict"
        src = "{}{}".format(h.get("name") or "header", " ({})".format(sid) if sid else "")
        if ok:
            verified_text.append(value)
        for m in _MECHS:
            if name == "received-spf":
                r = None
                if m == "spf":
                    w = re.match(r"\s*([a-z]+)", value, re.I)
                    r = w.group(1).lower() if w else None
            else:
                r = _find(value, m)
            if r:
                claims[m].append({"result": r, "verified": ok, "source": src, "why": why})
    out = {}
    for m in _MECHS:
        cl = claims[m]
        ver = [c for c in cl if c["verified"]]
        if ver:
            c = ver[0]
            clash = any(x is not c and x["result"] != c["result"] for x in cl)
            out[m] = {"result": c["result"], "provenance": "verified", "confidence": "high", "source": c["source"],
                      "note": "stamped by a trusted receiving server" + ("; conflicting lower claims ignored" if clash else "")}
        elif cl:
            c = max(cl, key=lambda x: _rank(x["result"]))
            clash = len({x["result"] for x in cl}) > 1
            out[m] = {"result": c["result"], "provenance": "unverified", "confidence": "low", "source": c["source"],
                      "note": "claimed in a header; " + c["why"] + ("; claims conflict, worst one shown" if clash else "")}
        else:
            out[m] = {"result": "none", "provenance": "unknown", "confidence": "none", "source": "-",
                      "note": "no result present"}
    out["_verified_text"] = " ".join(verified_text)
    return out


def alignment_evidence(parsed, spf, dkim, dmarc, auth_text=None):
    """What the receiving server's own verdicts prove about From / envelope alignment.
    Nothing here is assumed from a shared parent domain: SPF counts as aligned only on an
    SPF pass whose envelope domain is in From's organisation, DKIM only on a DKIM pass signed
    by a domain in From's organisation."""
    auth = (auth_text if auth_text is not None else parsed.get("auth_results", "")) or ""
    from_d = parsed.get("from_domain", "") or ""
    mailfrom = _domains_after(auth, "smtp.mailfrom") or ([parsed.get("return_path_domain")] if parsed.get("return_path_domain") else [])
    signers = _domains_after(auth, "header.d") + _domains_after(auth, "header.i")
    return {
        "dmarc_pass": dmarc == "pass",
        "spf_aligned": spf == "pass" and any(same_org(from_d, m) for m in mailfrom),
        "dkim_aligned": dkim == "pass" and any(same_org(from_d, s) for s in signers),
        "mailfrom": mailfrom, "signers": signers,
    }


def _verdict(auth_text, mechanism):
    """Pull 'spf=pass' / 'dkim=fail' style results out of the auth header."""
    if not auth_text:
        return "none"
    match = re.search(r"\b{}\s*=\s*([a-z]+)".format(mechanism), auth_text, re.I)
    if match:
        return match.group(1).lower()
    # Received-SPF uses a bare leading word: "Received-SPF: fail (...)"
    if mechanism == "spf":
        bare = re.search(r"received-spf:\s*([a-z]+)", auth_text, re.I)
        if bare:
            return bare.group(1).lower()
    return "none"


def _contains_any(text, words):
    low = (text or "").lower()
    return [w for w in words if w in low]


def analyze(parsed, trusted=None):
    """Returns {spf, dkim, dmarc, auth_evidence, auth_trust, auth_fail_score, anomalies[], bec{}}.
    spf/dkim/dmarc are the outcome; auth_evidence[mech] separately records provenance and confidence."""
    evid = collect_auth_evidence(parsed, trusted_authservs(trusted))
    spf, dkim, dmarc = (evid[m]["result"] for m in _MECHS)
    # Only VERIFIED results may prove alignment or downgrade a mismatch finding.
    v_spf, v_dkim, v_dmarc = (evid[m]["result"] if evid[m]["provenance"] == "verified" else "none"
                              for m in _MECHS)
    verified_text = evid.pop("_verified_text")

    # Score 0..1 - an outright fail is worse than a missing result.
    score = 0.0
    for value, weight in ((spf, 0.35), (dkim, 0.35), (dmarc, 0.30)):
        if value in ("fail", "softfail", "permerror", "temperror", "policy"):
            score += weight
        elif value == "none":
            score += weight * 0.4
    auth_fail_score = min(1.0, score)

    anomalies = []

    def flag(severity, title, detail):
        anomalies.append({"severity": severity, "title": title, "detail": detail})

    from_domain = parsed.get("from_domain", "")
    return_domain = parsed.get("return_path_domain", "")
    reply_domain = parsed.get("reply_to_domain", "")
    display = parsed.get("from_display", "")

    for mech, value in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)):
        if value in ("fail", "softfail", "permerror", "temperror"):
            flag("high", "{} {}".format(mech, value),
                 "The receiving server could not validate the sender against "
                 "the domain's published {} policy.{}".format(
                     mech, "" if evid[mech.lower()]["provenance"] == "verified"
                     else " (This failure is an unverified claim in the headers.)"))
        elif value == "none":
            flag("low", "{} result absent".format(mech),
                 "No {} verdict was stamped on this message.".format(mech))

    ev = alignment_evidence(parsed, v_spf, v_dkim, v_dmarc, auth_text=verified_text)
    results = "SPF {}, DKIM {}, DMARC {}".format(spf, dkim, dmarc)
    unverified = [m.upper() for m in _MECHS if evid[m]["provenance"] == "unverified"]
    if unverified:
        flag("info", "Authentication results unverified",
             "{} result(s) appear in the headers but their origin could not be established as a trusted "
             "receiving server, so they are treated as claims: they cannot prove alignment or clear a "
             "spoofing finding. This is not itself evidence of malice.".format(", ".join(unverified)))

    if from_domain and return_domain and from_domain != return_domain:
        if same_org(from_domain, return_domain):
            org = org_domain(from_domain)
            if ev["dmarc_pass"] and ev["spf_aligned"]:
                flag("info", "Envelope sender on a related subdomain (authenticated)",
                     "From is @{} and the envelope Return-Path is @{}: different hosts of the same "
                     "organisational domain ({}). The receiving server reported SPF pass for the envelope "
                     "domain and DMARC pass for From, so the relationship is verified by authentication, "
                     "not assumed from the shared parent. Routine for mail sent through a provider's bounce "
                     "domain.".format(from_domain, return_domain, org))
            else:
                flag("low", "Envelope sender on a related subdomain (not proven)",
                     "From is @{} and the envelope Return-Path is @{}: the same organisational domain ({}), "
                     "but the authentication results ({}) do not prove the two are aligned. A shared parent "
                     "alone is not trusted.".format(from_domain, return_domain, org, results))
        elif ev["dmarc_pass"] and ev["dkim_aligned"]:
            flag("low", "Envelope sender on a third-party domain (DKIM-aligned)",
                 "From is @{} but the envelope Return-Path is @{}, a different organisation. DMARC passed "
                 "through a DKIM signature by the From organisation, which authenticates the From domain. "
                 "Typical of third-party mail services; confirm the provider is expected.".format(
                     from_domain, return_domain))
        else:
            flag("high", "Envelope / header sender mismatch",
                 "From is @{} but the envelope Return-Path is @{}. Legitimate bulk "
                 "senders usually align these.".format(from_domain, return_domain))

    if reply_domain and from_domain and reply_domain != from_domain:
        if same_org(from_domain, reply_domain):
            sev = "info" if ev["dmarc_pass"] else "low"
            flag(sev, "Reply-To on a related subdomain",
                 "Replies go to @{} instead of @{}: the same organisational domain ({}). {} Reply-To itself "
                 "is not authenticated by SPF or DKIM.".format(
                     reply_domain, from_domain, org_domain(from_domain),
                     "DMARC passed for the From domain." if ev["dmarc_pass"]
                     else "The From domain was not confirmed by DMARC ({}).".format(results)))
        else:
            flag("high", "Reply-To redirects elsewhere",
                 "Replies would go to @{} instead of @{} - a classic way to "
                 "capture a victim's response.".format(reply_domain, from_domain))

    # Display name claims a brand the sending domain does not belong to.
    display_low = display.lower()
    for brand in C.KNOWN_BRANDS:
        if brand in display_low and brand not in from_domain:
            flag("high", "Display-name brand impersonation",
                 'The display name says "{}" but the message was sent from '
                 "@{}.".format(display, from_domain or "(unknown)"))
            break

    if from_domain in C.FREEMAIL_DOMAINS and any(
        role in display_low for role in C.EXEC_WORDS
    ):
        flag("high", "Executive identity on a free mail account",
             'Display name "{}" claims an executive role but the account is a '
             "consumer mailbox at {}.".format(display, from_domain))

    if not parsed.get("received_chain"):
        flag("medium", "No Received chain",
             "The message carries no routing headers, so its path cannot be "
             "independently verified.")

    for att in parsed.get("attachments", []):
        if att.get("risky"):
            flag("high", "Dangerous attachment type",
                 "{} can execute code or hide a payload.".format(att["filename"]))

    # --- BEC detection ------------------------------------------------------
    text = parsed.get("full_text", "")
    urgency = _contains_any(text, C.URGENCY_WORDS)
    payment = _contains_any(text, C.PAYMENT_WORDS)
    exec_claim = bool(_contains_any(display_low, C.EXEC_WORDS)
                      or _contains_any(text, C.EXEC_WORDS))
    freemail = from_domain in C.FREEMAIL_DOMAINS
    no_links = "http" not in (parsed.get("body_text", "") or "").lower()

    hits = sum([bool(urgency), bool(payment), exec_claim, freemail, no_links])
    bec_score = 0.0
    if payment and hits >= 3:
        bec_score = min(1.0, 0.45 + 0.18 * (hits - 3) + 0.2 * bool(freemail))
        flag("high", "Business Email Compromise pattern",
             "Payment instruction combined with urgency and an authority claim, "
             "with no link or attachment to scan - this is how BEC evades "
             "conventional filters.")

    bec = {
        "score": bec_score,
        "is_bec": bec_score > 0,
        "urgency_words": urgency,
        "payment_words": payment,
        "exec_claim": exec_claim,
        "freemail_sender": freemail,
        "no_links": no_links,
    }

    anomalies.sort(key=lambda a: SEV_ORDER.get(a["severity"], 9))
    high = sum(1 for a in anomalies if a["severity"] == "high")
    medium = sum(1 for a in anomalies if a["severity"] == "medium")

    return {
        "spf": spf, "dkim": dkim, "dmarc": dmarc,
        "auth_evidence": evid,
        "auth_trust": {
            "trusted_authservs": sorted(trusted_authservs(trusted)),
            "any_verified": any(e["provenance"] == "verified" for e in evid.values()),
            "limitation": "Header parsing cannot prove an Authentication-Results header is genuine. Results "
                          "are verified only when stamped under a configured trusted authserv-id inside the "
                          "receiving server's header block.",
        },
        "auth_fail_score": auth_fail_score,
        "anomalies": anomalies,
        "anomaly_score": min(1.0, 0.34 * high + 0.15 * medium),
        "bec": bec,
    }


if __name__ == "__main__":
    import sys

    from email_parser import parse_eml

    path = sys.argv[1] if len(sys.argv) > 1 else "samples/phishing_bec.eml"
    with open(path, "rb") as fh:
        parsed = parse_eml(fh.read())
    result = analyze(parsed)
    print("SPF={spf}  DKIM={dkim}  DMARC={dmarc}".format(**result))
    print("auth_fail_score = {:.2f}".format(result["auth_fail_score"]))
    print("BEC score       = {:.2f}".format(result["bec"]["score"]))
    print("\nanomalies:")
    for a in result["anomalies"]:
        print("  [{}] {} - {}".format(a["severity"].upper(), a["title"],
                                      a["detail"]))