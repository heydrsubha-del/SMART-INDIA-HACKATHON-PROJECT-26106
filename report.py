"""Module 5 (part 2): the exportable forensic report.

Produces an investigator-facing Markdown document: verdict, scoring breakdown,
header evidence, routing chain, IOCs, and an explicit limitations section.

That last part matters. A report that overstates certainty is useless as
evidence, so we state plainly what is proven, what is inferred, and what would
need a subpoena or a live lookup to confirm.

Standalone:  python report.py > report.md
"""
import hashlib
import math
import re
from datetime import datetime, timezone

from md_export import md_cell, group_urls
import extortion_detection as _ED

SEVERITY_MARK = {"high": "[HIGH]", "medium": "[MED] ", "low": "[LOW] ",
                 "info": "[INFO]"}


def evidence_hash(raw):
    """SHA-256 of the original bytes - the integrity anchor for the exhibit."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def extortion_block(result):
    """The validated extortion block of a result. Key genuinely absent -> {} (legacy result). Key present but None,
    empty or malformed -> an InvalidDetectorOutput error result (manual review), never a clean outcome."""
    return _ED.from_result(result)


_extortion = extortion_block


def partial_scan_note():
    """Disclosure shown wherever a truncated extortion scan is reported."""
    return ("Only part of this message was scanned for extortion language (the first {:,} and last {:,} "
            "characters; the middle was skipped because the message exceeded {:,} characters). "
            "The result is NOT a complete assessment of the whole message.".format(
                _ED._HEAD_CHARS, _ED._TAIL_CHARS, _ED.MAX_SCAN_CHARS))


def _risk_input_issue(result):
    """Why the risk-input validation record is NOT clean ("" when it is). Never raises on a malformed verdict."""
    verdict = result.get("verdict") if isinstance(result, dict) else None
    if not isinstance(verdict, dict):
        return ""
    bad = verdict.get("malformed_inputs")
    if isinstance(bad, list) and bad:
        names = ", ".join("{} ({})".format(b.get("input"), b.get("problem")) for b in bad if isinstance(b, dict))
        return "invalid risk input(s) treated as 0: " + (names or "details not recorded")
    if bad or verdict.get("input_validation_failed"):      # truthy but not a usable list: fail safe, say so
        return "invalid risk input(s) recorded (validation record unreadable)"
    return ""


def validation_issues(result):
    """Reasons this scan is NOT a complete, fully validated assessment. An empty list means complete."""
    issues = []
    ext = extortion_block(result)
    if ext.get("error") and not ext.get("detected"):
        issues.append("extortion detector failed ({})".format(str(ext.get("error"))[:60]))
    if ext.get("truncated"):
        issues.append("partial scan (only the first {:,} and last {:,} characters were scanned)".format(
            _ED._HEAD_CHARS, _ED._TAIL_CHARS))
    risk_issue = _risk_input_issue(result)
    if risk_issue:
        issues.append(risk_issue)
    return issues


def scan_validation_status(result):
    """One-line scan-integrity status for tables/exports, kept SEPARATE from the extortion finding."""
    issues = validation_issues(result)
    if not issues:
        return "Complete - no validation problems recorded"
    return "INCOMPLETE - " + "; ".join(issues) + ". Manual review required; NOT a clean result"


def extortion_status(result):
    """One-line extortion status for tables/exports. Never reads as clean when the scan failed or was partial."""
    ext = _extortion(result)
    if not ext:
        return "Not recorded in this result"
    partial = " [PARTIAL SCAN - only part of the message was scanned]" if ext.get("truncated") else ""
    if ext.get("error") and not ext.get("detected"):
        return "Detector failed ({}) - manual review required; NOT a clean result".format(str(ext.get("error"))[:60])
    if ext.get("detected"):
        head = "Suspected sextortion" if ext.get("category") == "suspected_sextortion" else "Suspected extortion"
        if ext.get("needs_review"):
            return "{} - manual review required{}".format(head, partial)
        return "{} detected ({} severity){}".format(head, ext.get("severity", "unknown"), partial)
    if ext.get("truncated"):
        return "No finding in the scanned portion - PARTIAL SCAN; not a complete assessment"
    if _risk_input_issue(result):
        # The detector itself found nothing, but the scan had invalid inputs: say so instead of reading as clean.
        return ("No extortion pattern matched, but the scan had invalid risk inputs (see Scan Validation) "
                "- NOT a clean result; manual review required")
    return "No extortion pattern found"


def campaign_intel_md(result):
    """Markdown for the precomputed result["campaign_intel"] ([] when absent / no related observations). NEVER raises.
    Read-only: no database access. Similarity is shared tactics, never attribution."""
    try:
        import campaign_intel as _ci_mod
        ci = result.get("campaign_intel") if isinstance(result, dict) else None
        rels = [x for x in (ci.get("relationships") or []) if isinstance(x, dict)] if isinstance(ci, dict) else []
        if not rels:
            return []
        out = ["### Campaign intelligence (Phase 3)", "", "_%s_" % md_cell(ci.get("timeline_basis")), "",
               "| Observation | Stored | Attack DNA class | Specific families | Context only | Infra class | Country | Tactic changes |",
               "|---|---|---|---|---|---|---|---|"]
        for x in rels[:5]:
            inf = x.get("infrastructure") if isinstance(x.get("infrastructure"), dict) else {}
            g = lambda k: md_cell((inf.get(k) or {}).get("status") if isinstance(inf.get(k), dict) else "unavailable")
            out.append("| `%s` | %s | %s | %s | %s | %s | %s | %s |" % (
                md_cell(x.get("observation_ref")), md_cell(x.get("observed_at") or "unknown"), md_cell(x.get("classification")),
                md_cell(", ".join(map(str, x.get("supporting_families") or [])) or "none"),
                md_cell(", ".join(map(str, x.get("context_only_families") or [])) or "none"), g("infra_class"), g("country"),
                md_cell(_ci_mod.tactic_summary(x))))
        out += ["", "**Limitations:** " + " ".join(md_cell(s) for s in (ci.get("limitations") or [])[:5]), ""]
        return out
    except Exception:
        return []


def entity_graph_md(result):
    """Markdown for the precomputed result["entity_graph"]. NEVER raises. Read-only: no database access. A result with no
    "entity_graph" key at all (older scans) yields nothing; a present-but-failed/incomplete graph states WHY, so it can never
    be read as "no relationships detected". Every relationship cites evidence ids of this scan; similarity is never ownership."""
    try:
        import entity_graph as _eg_mod
        if not isinstance(result, dict) or "entity_graph" not in result:
            return []
        eg = result.get("entity_graph")
        level, text = _eg_mod.status_message(eg)
        out = ["### Entity graph (Phase 4)", ""]
        if text:
            out += ["> **%s:** %s" % ({"error": "Entity graph unavailable", "warning": "Entity graph incomplete"}.get(level, "Entity graph note"), md_cell(text)), ""]
        edges = [x for x in (eg.get("edges") or []) if isinstance(x, dict)] if isinstance(eg, dict) else []
        if not edges:
            return out
        out += ["_Evidence-linked relationships from this session only. Observed = reported by a scanner about this message "
                "(header values stay untrusted claims); inferred = derived from an inference or a historical comparison._", "",
                "| Relationship | Basis | Evidence | Confidence | Why |", "|---|---|---|---|---|"]
        # Identical relationships are shown once (see aggregate_edges); distinct observations stay separate rows.
        for r in aggregate_edges(edges, _eg_mod.edge_title)[:30]:
            out.append("| %s | %s | %s | %s | %s |" % (md_cell(r["title"]), md_cell(r["basis"]), md_cell(", ".join(r["evidence"])), md_cell(r["confidence"]), md_cell(r["why"])))
        shared = [s for s in (eg.get("shared_entities") or []) if isinstance(s, dict) and isinstance(s.get("entity"), dict)]
        if shared:
            # Counts only: another scan's id/evidence is never copied into this scan's report (the app panel shows the references).
            out += ["", "**Entities also seen in other retained scans of this session**", "", "| Entity | Other retained scans | Relationships | Last seen |", "|---|---|---|---|"]
            for s in shared[:10]:
                scs = [y for y in (s.get("scans") or []) if isinstance(y, dict)]
                out.append("| %s | %d | %s | %s |" % (
                    md_cell("%s %s" % (s["entity"].get("type"), _eg_mod._e_disp(s["entity"]))), len(scs),
                    md_cell(", ".join(sorted({str(y.get("rel")) for y in scs}))), md_cell(max([str(y.get("observed_at")) for y in scs] or ["-"]))))
        out += ["", "**Limitations:** " + " ".join(md_cell(s) for s in (eg.get("limitations") or [])[:4]), ""]
        return out
    except Exception:
        return ["### Entity graph (Phase 4)", "", "> **Entity graph unavailable:** it could not be rendered. This is not a finding that no relationships exist.", ""]


# ---- presentation-only helpers (never change scores, verdicts or stored evidence) -----------------------------------
_TRACK_SUFFIX = ("awstrack.me", "sendgrid.net", "list-manage.com", "mailchi.mp", "mandrillapp.com", "sparkpostmail.com", "mailgun.org",
                 "hubspotlinks.com", "rs6.net", "safelinks.protection.outlook.com", "urldefense.com")
_TRACK_PREFIX = ("click.", "clicks.", "track.", "trk.", "links.", "link.")


def norm_host(h):
    """Canonical host for grouping: trimmed, lower-case, no trailing dot, IDNA (punycode) where it can be encoded."""
    h = str(h or "").strip().lower().rstrip(".")
    try:
        return h.encode("idna").decode("ascii") if h and not h.isascii() else h
    except Exception:
        return h


def tracking_infra(host):
    """'' | label. Name-based only: shared tracking/redirect infrastructure is NOT evidence of malice by itself."""
    h = norm_host(host)
    if any(h == t or h.endswith("." + t) for t in _TRACK_SUFFIX):
        return "known email tracking/redirect service"
    if h.startswith(_TRACK_PREFIX):
        return "host name suggests tracking/redirect (name pattern only)"
    return ""


def redact_url(u):
    """Presentation copy of a URL: query values and long opaque path tokens are hidden. The original stays in the evidence."""
    t = re.sub(r"([?&][^=&#\s]*)=[^&#\s]*", r"\1=[redacted]", str(u or ""))
    return re.sub(r"(?<=/)[A-Za-z0-9_\-]{24,}(?=[/?#]|$)", "[token]", t)


def mask_recipient(addr):
    a = str(addr or "")
    return a[:1] + "***@" + a.split("@", 1)[1] if "@" in a and a.split("@", 1)[0] else a


_RECIP_ROLE = re.compile(r"\b(to|cc|bcc|recipient|delivered-to|envelope[- ]to)\b", re.I)
_URL_IN_TEXT = re.compile(r"https?://[^\s`|<>\"')]+", re.I)


def recipients_of(*results):
    """Recipient addresses recorded by the scanner (roles containing to/cc/bcc/recipient). Read-only."""
    out = set()
    for r in results:
        d = ((r or {}).get("iocs") or {}).get("email_details") if isinstance(r, dict) else None
        for x in d if isinstance(d, list) else []:
            if isinstance(x, dict) and isinstance(x.get("address"), str) and _RECIP_ROLE.search(", ".join(map(str, x.get("roles") or []))):
                out.add(x["address"])
    return out


def redact_md(md, results=None):
    """Display redaction for any exported Markdown (HTML/Word/PDF exports are rendered from it): recipient addresses are masked and
    URL query values / long tokens hidden. Pure and idempotent; never touches raw evidence, hashes or the stored result."""
    if not isinstance(md, str):
        return md
    rs = results if isinstance(results, (list, tuple)) else [results]
    for a in sorted(recipients_of(*rs), key=len, reverse=True):
        md = md.replace(a, mask_recipient(a))
    return _URL_IN_TEXT.sub(lambda m: redact_url(m.group(0)), md)


def url_host_groups_md(urls):
    """One row per canonical host. Individual URLs stay in the table above; nothing is removed, and flags are the UNION of those raised."""
    g = {}
    for u in urls or []:
        if isinstance(u, dict):
            e = g.setdefault(norm_host(u.get("host")) or "-", {"urls": set(), "occ": 0, "flags": set()})
            e["urls"].add(str(u.get("url") or ""))
            c = u.get("count")
            e["occ"] += c if isinstance(c, int) and not isinstance(c, bool) and c > 0 else 1
            e["flags"].update(str(f) for f in (u.get("flags") or []))
    if not g:
        return []
    out = ["**URL hosts (grouped)**", "", "| Host | Distinct URLs | Occurrences | Infrastructure | Indicators raised on this host |", "| --- | --- | --- | --- | --- |"]
    for h in sorted(g):
        e = g[h]
        out.append("| `%s` | %d | %d | %s | %s |" % (md_cell(h), len(e["urls"]), e["occ"], md_cell(tracking_infra(h) or "-"), md_cell("; ".join(sorted(e["flags"])) or "none")))
    return out + ["", "_Grouping is for readability only: every URL keeps its own row and indicators above. Tracking or redirect infrastructure shared by many senders "
                  "is not malicious by itself, and sharing a host never removes an indicator. URL query values and long tokens are redacted in this display; "
                  "the unredacted indicators remain in the protected evidence._", ""]


def valid_conf(c):
    """A usable confidence: a real int/float that is finite. Booleans, NaN and infinity are rejected (never shown as a value)."""
    return isinstance(c, (int, float)) and not isinstance(c, bool) and math.isfinite(c)


def _side(x):
    return (str(x.get("type")), str(x.get("id") if x.get("id") is not None else x.get("label"))) if isinstance(x, dict) else ("?", repr(x))


def aggregate_edges(edges, title_fn=None):
    """Merge only genuinely identical relationships: same source entity, target entity (direction preserved), relationship, basis,
    provenance and explanation. Evidence IDs are unioned (none dropped); confidences are reported as the range of valid values only.
    Distinct observations stay separate. Deterministic order."""
    grp = {}
    for x in edges or []:
        if not isinstance(x, dict):
            continue
        k = (_side(x.get("src")), str(x.get("rel")), _side(x.get("dst")), str(x.get("basis")), str(x.get("provenance") or ""), str(x.get("explanation") or ""))
        g = grp.setdefault(k, {"edge": x, "ev": set(), "conf": set()})
        g["ev"].update(str(i) for i in (x.get("evidence") or []) if isinstance(i, (str, int)) and not isinstance(i, bool))
        if valid_conf(x.get("confidence")):
            g["conf"].add(float(x["confidence"]))
    rows = []
    for k in sorted(grp):
        g, cs = grp[k], sorted(grp[k]["conf"])
        rows.append({"title": (title_fn(g["edge"]) if title_fn else "") or "%s %s %s" % (k[0], k[1], k[2]), "basis": k[3], "evidence": sorted(g["ev"]),
                     "confidence": "n/a" if not cs else "%.2f" % cs[0] if len(cs) == 1 else "%.2f-%.2f" % (cs[0], cs[-1]), "why": k[5]})
    return rows


def _auth_state(headers):
    """Per-mechanism: verified (stamped by a trusted receiving server) and result. Alignment only if header analysis computed it."""
    ev = (headers or {}).get("auth_evidence") or {}
    st = {m: ((ev.get(m) or {}).get("provenance") == "verified", str((headers or {}).get(m, "none")).lower()) for m in ("spf", "dkim", "dmarc")}
    al = (headers or {}).get("alignment")
    return st, (al if isinstance(al, dict) else None)


def ses_note(parsed, headers):
    rp = norm_host((parsed or {}).get("return_path_domain"))
    if not (rp == "amazonses.com" or rp.endswith(".amazonses.com")):
        return []
    st, al = _auth_state(headers)
    frm = norm_host((parsed or {}).get("from_domain")) or "unknown"
    if al is None:
        al_txt = "alignment was not computed for this scan, so it is unknown"
    else:
        al_txt = "verified DMARC pass: %s; SPF aligned with From: %s; DKIM aligned with From (signers: %s): %s" % (
            "yes" if al.get("dmarc_pass") else "no", "yes" if al.get("spf_aligned") else "no",
            md_cell(", ".join(map(str, al.get("signers") or [])) or "none recorded"), "yes" if al.get("dkim_aligned") else "no")
    unver = [m.upper() for m, (v, _) in st.items() if not v]
    return ["> **Amazon SES sending infrastructure.** Envelope sender (Return-Path) `%s`; visible From domain `%s`. An Amazon SES bounce domain is normal for SES customers "
            "and not suspicious by itself, and an SPF pass on it authenticates the SES domain, not the From domain. Alignment: %s. %s" % (
                md_cell(rp), md_cell(frm), al_txt,
                ("Results not verified as stamped by a trusted receiving server (treated as claims): %s." % ", ".join(unver)) if unver else
                "All three results were stamped by a trusted receiving server."), ""]


def attribution_md(result):
    """Three separate questions with separate confidence; none of them is proof of who or where the sender is."""
    try:
        geo, headers = result.get("geo") or {}, result.get("headers") or {}
        origin = geo.get("origin") or {}
        st, al = _auth_state(headers)
        if not geo.get("hops"):
            infra = ("Not established", "No public relay hop was found in the headers.")
        elif geo.get("anonymised") or origin.get("tor_exit_confirmed"):
            infra = ("Low", "The earliest hop is anonymising/relay infrastructure; it identifies the relay, not the operator.")
        else:
            infra = ("Moderate", "Observed in Received headers (machine observation). Hops before the first trusted server are sender-controlled and can be forged.")
        if al and st["dmarc"][0] and al.get("dmarc_pass") and (al.get("spf_aligned") or al.get("dkim_aligned")):
            ident = ("Moderate", "A DMARC pass stamped by a trusted receiving server, with aligned %s, supports that the From domain authorised the message; it does not identify the person." % (
                " and ".join(n for n, k in (("SPF", "spf_aligned"), ("DKIM", "dkim_aligned")) if al.get(k))))
        else:
            why = []
            if not any(v for v, _ in st.values()):
                why.append("no authentication result is verified as stamped by a trusted receiving server")
            if al is None:
                why.append("alignment is unknown")
            elif not (al.get("spf_aligned") or al.get("dkim_aligned")):
                why.append("neither SPF nor DKIM is shown aligned with the From domain")
            ident = ("Not established", ("; ".join(why) or "DMARC pass with alignment is not verified") + ". An SPF pass alone does not establish the sender's identity; missing or unverified evidence stays unknown.")
        return ["**Attribution confidence (three separate questions)**", "", "| Question | Confidence | Basis |", "| --- | --- | --- |",
                "| Which mail-server infrastructure handled the message? | %s | %s |" % infra,
                "| How confident is the sender-domain identity? | %s | %s |" % ident,
                "| Where is the sender physically? | Not established | GeoIP is approximate: it places an IP address's network registration, not a person or device. "
                "VPNs, relays and cloud hosting make it unreliable; it is not proof of physical location. |", ""]
    except Exception:
        return []


_AV_LABELS = (("direct_machine", "extracted or derived locally by a scanner"), ("trusted_external", "returned by an external service (not independently corroborated here)"),
              ("untrusted_claim", "header claims (sender-controlled, unverified)"), ("historical", "historical sightings"), ("inference", "inferences (derived or approximate)"))


def availability_md(reg):
    """Counts are deterministic. 'Completed' means the check ran; it never means confirmed, verified or corroborated."""
    items = reg if isinstance(reg, list) else []
    rows = [e for e in items if isinstance(e, dict)]
    if not items:
        return []
    bad = [e for e in rows if e.get("status") != "ok"]
    by = {k: 0 for k, _ in _AV_LABELS}
    other = 0
    for e in rows:
        if isinstance(e.get("origin"), str) and e.get("origin") in by:
            by[e["origin"]] += 1
        else:
            other += 1
    out = ["", "### Intelligence availability", "", "- %d of %d evidence item(s) completed; %d malformed entr%s ignored." % (
        len(rows) - len(bad), len(rows), len(items) - len(rows), "y" if len(items) - len(rows) == 1 else "ies"),
        "- By origin: %s%s." % ("; ".join("%d %s" % (by[k], t) for k, t in _AV_LABELS), "; %d with unrecognised origin" % other if other else ""),
        "- Independent corroboration between sources is not assessed in this summary; a completed check is an observation, not verified attribution."]
    out += ["- **Not completed (%s):** %s. A gap in the investigation, **not** a negative finding." % (
        md_cell(e.get("status")), md_cell("%s %s/%s" % (e.get("id"), e.get("type"), e.get("source")))) for e in bad[:20]] or ["- No failed or unavailable checks were recorded."]
    return out + [""]


def scan_evidence_md(result):
    """Markdown lines for the scanner evidence register and machine findings ([] for a result without a register).
    Evidence is defined once here; other sections reference IDs. NEVER raises: a malformed register is reported as such and
    rendered from its well-formed parts only, so a bad register cannot break (or hide) the rest of a report."""
    if not isinstance(result, dict) or "evidence_register" not in result:
        return []
    head = ["## 9. Evidence register (scanner)", ""]
    try:
        import investigation_agent as ia
        reg, fnd = result.get("evidence_register"), result.get("scan_findings")
        reg, fnd = (reg if isinstance(reg, list) else []), (fnd if isinstance(fnd, list) else [])
        out = head + ["_Scan ID `%s`. Machine findings cite the evidence IDs below; the register is generated from detector output only "
                      "and never changes the score or verdict._" % md_cell(result.get("scan_id") if isinstance(result.get("scan_id"), str) else "not recorded"), ""]
        if result.get("evidence_error"):
            out += ["> **Evidence register unavailable** (%s). The scan itself is unaffected; absence of evidence here is not a clean result." %
                    md_cell(result["evidence_error"]), ""]
        problems = ia.validate_scan_register(result)
        if problems:
            out += ["> **Evidence register failed validation:** %s. Treat these references as unverified." % md_cell("; ".join(problems[:5])), ""]
        out += ["### Machine findings", ""] + (ia.findings_table_md(fnd, reg) if fnd else ["_No structured machine findings were recorded._"])
        out += ["", "### Evidence", ""] + (ia.evidence_table_md(reg) if reg else ["_No evidence was recorded for this scan._"])
        out += ["", ia.EVIDENCE_LEGEND, ""] + availability_md(reg)
        return out + campaign_intel_md(result) + entity_graph_md(result)
    except Exception as exc:
        return head + ["> **Evidence register could not be rendered** (%s). It is unverified; scores and verdicts are unaffected." % type(exc).__name__, ""]


def build_report(result, raw=None, analyst="SIH26106 automated triage"):
    """Render one analysis result as a Markdown forensic report."""
    parsed = result["parsed"]
    headers = result["headers"]
    iocs = result["iocs"]
    geo = result["geo"]
    verdict = result["verdict"]
    origin = geo.get("origin", {})

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []
    add = lines.append

    add("# Email Threat Forensic Report")
    add("")
    add("**Exhibit:** `{}`".format(result.get("name", "unknown")))
    add("**Generated:** {}".format(generated))
    add("**Analyst:** {}".format(analyst))
    if raw is not None:
        add("**SHA-256 of source file:** `{}`".format(evidence_hash(raw)))
    add("")
    add("---")
    add("")

    # --- 1. Verdict ---------------------------------------------------------
    add("## 1. Verdict")
    add("")
    add("| Field | Value |")
    add("| --- | --- |")
    add("| Risk score | **{:.0f} / 100** |".format(result["score"]))
    add("| Classification | **{}** |".format(result["level"]))
    add("| Primary driver | {} |".format(md_cell(verdict.get("top_driver", "-"))))
    add("| ML phishing probability | {:.1%} |".format(result["ml"]["prob"]))
    _scan_issues = validation_issues(result)
    if _scan_issues:      # only when something is wrong: valid reports keep their existing wording
        add("| Scan validation | **INCOMPLETE** - {} |".format(md_cell("; ".join(_scan_issues))))
    add("")
    add("### How the score was reached")
    add("")
    add("| Signal | Strength | Weight | Points |")
    add("| --- | --- | --- | --- |")
    for c in verdict["contributions"]:
        add("| {} | {:.0%} | {} | {:.1f} |".format(
            md_cell(c["label"]), c["strength"], c["weight"], c["points"]))
    add("| | | **Total** | **{:.1f}** |".format(result["score"]))
    add("")
    if verdict.get("malformed_inputs"):
        add("> **Input validation:** malformed risk input(s) were treated as 0, which is NOT evidence that the "
            "message is safe: {}. Manual review required.".format(
                ", ".join("{} ({})".format(b.get("input"), b.get("problem"))
                          for b in verdict["malformed_inputs"] if isinstance(b, dict))))
        add("")

    # --- 2. Message identity ------------------------------------------------
    add("## 2. Message identity")
    add("")
    add("| Header | Value |")
    add("| --- | --- |")
    for label, value in (
        ("From (display)", parsed.get("from_display")),
        ("From (address)", parsed.get("from_addr")),
        ("Reply-To", parsed.get("reply_to")),
        ("Return-Path", parsed.get("return_path")),
        ("To", parsed.get("to")),
        ("Subject", parsed.get("subject")),
        ("Date", parsed.get("date")),
        ("Message-ID", parsed.get("message_id")),
        ("X-Mailer", parsed.get("x_mailer")),
    ):
        add("| {} | `{}` |".format(label, md_cell(value or "(absent)")))
    add("")

    # --- 3. Authentication --------------------------------------------------
    add("## 3. Authentication results")
    add("")
    add("| Mechanism | Result | Evidence provenance | Confidence |")
    add("| --- | --- | --- | --- |")
    evid = headers.get("auth_evidence") or {}
    for mech in ("spf", "dkim", "dmarc"):
        e = evid.get(mech) or {"provenance": "unknown", "confidence": "none"}
        add("| {} | **{}** | {} | {} |".format(
            mech.upper(), headers.get(mech, "none").upper(),
            e["provenance"], e["confidence"]))
    add("")
    if any((evid.get(m) or {}).get("provenance") == "verified" for m in ("spf", "dkim", "dmarc")):
        add("> Rows marked *verified* were stamped by a configured trusted receiving "
            "server and re-read, not re-computed. Rows marked *unverified* are claims "
            "found in the headers; they do not prove the message authentic.")
    else:
        add("> No authentication result could be verified as coming from a trusted "
            "receiving server. Any values above are claims found in the message "
            "headers, which a sender can forge; they neither clear nor condemn the message.")
    add("")
    for _ln in ses_note(parsed, headers):
        add(_ln)

    add("### Anomalies detected")
    add("")
    if headers["anomalies"]:
        for a in headers["anomalies"]:
            add("- {} **{}** - {}".format(
                SEVERITY_MARK.get(a["severity"], ""), a["title"], a["detail"]))
    else:
        add("None. Sender identity is internally consistent.")
    add("")

    if headers["bec"]["is_bec"]:
        bec = headers["bec"]
        add("### Business Email Compromise assessment")
        add("")
        add("Pattern score **{:.0%}**. Contributing observations:".format(
            bec["score"]))
        add("")
        add("- Payment-related language: {}".format(
            ", ".join("`{}`".format(w) for w in bec["payment_words"]) or "none"))
        add("- Urgency language: {}".format(
            ", ".join("`{}`".format(w) for w in bec["urgency_words"]) or "none"))
        add("- Claims an executive identity: {}".format(
            "yes" if bec["exec_claim"] else "no"))
        add("- Sent from a consumer mailbox: {}".format(
            "yes" if bec["freemail_sender"] else "no"))
        add("- Contains no links or attachments to scan: {}".format(
            "yes" if bec["no_links"] else "no"))
        add("")
        add("> BEC carries no malicious payload, so signature and URL scanning "
            "cannot see it. Detection depends on identity and intent, which is "
            "why authentication passing does not clear a message.")
        add("")

    extortion = extortion_block(result)
    if extortion.get("detected"):
        add("### Extortion / sextortion assessment (deterministic, independent of the ML score)")
        add("")
        _review_note = ""
        if extortion.get("needs_review"):
            _reason = extortion.get("review_reason")
            if _reason == "no_explicit_payment_demand":
                _review_note = " *(flagged for human review - no explicit payment demand was matched)*"
            elif _reason == "quoted_context":
                _review_note = " *(flagged for human review - also contains advisory/educational phrasing)*"
            else:   # reason missing/unknown: say nothing about WHY rather than guess
                _review_note = " *(flagged for human review)*"
        try:
            _conf = "{:.0%}".format(float(extortion.get("confidence") or 0.0))
        except (TypeError, ValueError):
            _conf = "n/a"
        add("**{}** - severity **{}**, rule confidence **{}**.{}".format(
            "Suspected sextortion" if extortion.get("category") == "suspected_sextortion"
            else "Suspected extortion",
            extortion.get("severity", "unknown"), _conf, _review_note))
        add("")
        add(str(extortion.get("explanation", "")))
        add("")
        add("Evidence phrases found in the message (exact text, not interpreted):")
        add("")
        for cat, phrases in (extortion.get("evidence") or {}).items():
            label = str(cat).replace("_", " ")
            add("- **{}**: {}".format(label, ", ".join(
                "`{}`".format(str(p).replace("`", "'").replace("\n", " ")) for p in (phrases or []))))
        _pids = extortion.get("pattern_ids") or {}
        if _pids:
            add("")
            add("Matched pattern IDs: " + "; ".join("{}: {}".format(
                str(_c).replace("_", " "), ", ".join("`{}`".format(str(_i)) for _i in (_ids or [])))
                for _c, _ids in _pids.items()))
        add("")
        add("> This finding describes what the message text claims and threatens. It "
            "does NOT confirm the sender actually possesses any material - that cannot "
            "be established from the email alone.")
        add("")
        if extortion.get("recommended_action"):
            add("**Recommended action:** {}".format(extortion.get("recommended_action")))
            add("")
        if extortion.get("truncated"):
            add("> **Partial scan.** " + partial_scan_note())
            add("")
    elif extortion.get("error"):
        # The detector failed internally: say so. An absent finding here is NOT a clean result.
        add("### Extortion / sextortion assessment")
        add("")
        add("The extortion detector could not complete on this message (`{}`), so no extortion "
            "assessment is available. This is NOT a clean result - **manual review required**."
            .format(str(extortion.get("error"))[:80]))
        add("")
    elif extortion.get("truncated"):
        add("### Extortion / sextortion assessment")
        add("")
        add("No extortion pattern was found in the scanned portion. **Partial scan.** " + partial_scan_note()
            + " Review the unscanned middle of the message manually.")
        add("")

    # --- 4. Routing ---------------------------------------------------------
    add("## 4. Origin and routing")
    add("")
    add(geo.get("summary", "No routing information available."))
    add("")
    for _ln in attribution_md(result):
        add(_ln)
    if geo.get("hops"):
        add("| # | IP | Location | Network | Infrastructure | Tor Exit |")
        add("| --- | --- | --- | --- | --- | --- |")
        for hop in geo["hops"]:
            where = ", ".join(p for p in [hop.get("city"), hop.get("country")] if p)
            add("| {} | `{}` | {} | {} | {} | {} |".format(
                hop.get("hop_index", "?"), md_cell(hop["ip"]), md_cell(where or "Unknown"),
                md_cell(hop.get("isp") or "-"), md_cell(hop.get("infra_label", "-")),
                "Confirmed" if hop.get("tor_exit_confirmed") else "-"))
        add("")
        add("Routing order is oldest hop first, reconstructed by reversing the "
            "`Received` headers. Mail servers prepend these, so the last header "
            "in the file is the earliest hop and therefore closest to the sender.")
        add("")
    if geo.get("anonymised"):
        add("> **Attribution caution:** the earliest hop is anonymising "
            "infrastructure ({}). The location above identifies the relay, not "
            "the operator. Identifying the person behind it requires relay logs, "
            "which Tor by design does not retain.".format(
                origin.get("infra_label", "anonymiser")))
        add("")

    if origin.get("tor_exit_confirmed"):
        tor_sources = origin.get("tor_exit_sources") or []
        cited = " and ".join("the **{}**".format(s) for s in tor_sources) or \
            "a published Tor exit-node list"
        add("> **Tor exit node - confirmed, not inferred.** The origin IP "
            "`{}` is listed by {} at time of analysis. This is a direct "
            "lookup against a published exit-node directory, independent of "
            "the ISP/org-name infrastructure classification above. {}".format(
                origin.get("ip", "unknown"), cited,
                "It corroborates the anonymising-infrastructure finding "
                "above." if geo.get("anonymised") else
                "Note this was **not** flagged by the infrastructure "
                "classification above, which relies on ISP/org naming and "
                "misses exits hosted on generic VPS providers - this "
                "directory lookup catches what that heuristic missed."))
        add("")

    # --- 5. IOCs ------------------------------------------------------------
    add("## 5. Indicators of compromise")
    add("")
    if iocs["urls"]:
        add("| URL | Host | Assessment |")
        add("| --- | --- | --- |")
        for u in group_urls(iocs["urls"]):
            note = "; ".join(u["flags"]) if u["flags"] else "no indicators"
            if u["count"] > 1:
                note += " (appears {} times)".format(u["count"])
            add("| `{}` | `{}` | {} |".format(
                md_cell(redact_url(u["url"])[:90]), md_cell(u["host"] or "-"), md_cell(note)))
        add("")
        for _ln in url_host_groups_md(group_urls(iocs["urls"])):
            add(_ln)
    else:
        _le = iocs.get("link_extraction") or {}
        add(_le["note"] if _le.get("status") == "not_extracted" else "No URLs present in the message body.")
        add("")

    for label, values in (("Domains", iocs["domains"]),
                          ("IP addresses in body", iocs["ips"]),
                          ("Cryptocurrency wallets", iocs["wallets"])):
        if values:
            add("**{}:** {}".format(
                label, ", ".join("`{}`".format(v) for v in values)))
            add("")

    details = iocs.get("email_details")
    if isinstance(details, list) and details:
        add("**Email addresses and their roles** (an address appearing in a message is not, by itself, "
            "evidence of malice):")
        add("")
        add("| Address | Role(s) |")
        add("| --- | --- |")
        for d in details:
            _rl = ", ".join(d["roles"])
            add("| `{}` | {} |".format(md_cell(mask_recipient(d["address"]) if _RECIP_ROLE.search(_rl) else d["address"]), md_cell(_rl)))
        add("")
    elif iocs.get("emails"):
        add("**Email addresses (role not recorded):** {}".format(
            ", ".join("`{}`".format(v) for v in iocs["emails"])))
        add("")

    if parsed.get("attachments"):
        add("**Attachments:**")
        add("")
        for att in parsed["attachments"]:
            add("- `{}` ({} bytes){}".format(
                att["filename"], att["size"],
                " - **dangerous file type**" if att.get("risky") else ""))
        add("")

    # --- 6. ML explanation --------------------------------------------------
    add("## 6. Model explanation")
    add("")
    add("The classifier assigned **{:.1%}** phishing probability.".format(
        result["ml"]["prob"]))
    add("")
    if result["ml"]["top_terms"]:
        add("Terms in this message that pushed the score upward:")
        add("")
        for term, weight in result["ml"]["top_terms"]:
            add("- `{}` (contribution {:.3f})".format(term, weight))
    else:
        add("No individual term contributed positively toward a phishing "
            "classification.")
    add("")

    # --- 7. Recommended action ---------------------------------------------
    add("## 7. Recommended action")
    add("")
    for action in _actions(result):
        add("- {}".format(action))
    add("")

    # --- 8. Limitations -----------------------------------------------------
    add("## 8. Limitations and legal notes")
    add("")
    add("- **Geolocation is approximate.** IP-to-location databases resolve to "
        "a city or country at best, and are wrong for VPN, proxy, Tor and "
        "cloud ranges. It is investigative lead material, not proof of "
        "physical location.")
    add("- **Headers can be forged.** Only hops added by servers under trusted "
        "administrative control are reliable. Headers below the first trusted "
        "hop may have been fabricated by the sender.")
    add("- **The ML score is probabilistic.** It supports a human decision and "
        "should not be the sole basis for blocking or accusing anyone.")
    add("- **Attribution is not identification.** Shared infrastructure links "
        "messages to a campaign; naming a person requires provider records "
        "obtained through lawful process.")
    add("- **Tor exit-list confirmation is a point-in-time snapshot.** It "
        "reflects the published exit list's state when this report was "
        "generated, not necessarily the list's state at the time the "
        "message was actually sent - exit relays join and leave these "
        "lists continuously.")
    add("- **Privacy.** This report contains personal data. Handle it under the "
        "DPDP Act 2023 and your organisation's retention policy, and restrict "
        "access to authorised investigators.")
    add("- Analysis was performed offline on a stored copy; the original "
        "message was not modified. The SHA-256 above lets any reviewer confirm "
        "the exhibit is unaltered.")
    add("")
    add("---")
    add("")
    for _ln in scan_evidence_md(result):        # section 9; absent for results from before the register existed
        add(_ln)
    add("")
    add("---")
    add("")
    add("*Generated by the SIH26106 Email Threat Detection, GeoLocation and "
        "Forensic Intelligence Platform.*")

    return redact_md("\n".join(lines), result)


def _actions(result):
    """Verdict-appropriate steps, plus explicit notes when the extortion scan failed or was partial."""
    ext = _extortion(result)
    notes = []
    if ext.get("error") and not ext.get("detected"):
        notes.append("**Manual review required.** The extortion detector failed on this message (`{}`), so "
                     "there is no extortion assessment. Do not treat this message as legitimate until an "
                     "analyst has reviewed it.".format(str(ext.get("error"))[:80]))
    _verdict = result.get("verdict") if isinstance(result, dict) else None
    _bad = (_verdict or {}).get("malformed_inputs") if isinstance(_verdict, dict) else None
    if _bad:
        notes.append("**Manual review required.** Risk-input validation failed for: {}. These signals were "
                     "treated as 0 and are NOT evidence that the message is safe.".format(
                         ", ".join("{} ({})".format(b.get("input"), b.get("problem")) for b in _bad if isinstance(b, dict))))
    if ext.get("truncated"):
        notes.append("**Partial extortion scan.** " + partial_scan_note()
                     + (" Review the unscanned part manually." if not ext.get("detected") else ""))
    return notes + _actions_core(result, uncertain=bool(notes and not ext.get("detected")))


def _actions_core(result, uncertain=False):
    """Verdict-appropriate response steps."""
    level = result["level"]
    iocs = result["iocs"]
    geo = result["geo"]
    origin_ip = (geo.get("origin") or {}).get("ip")
    extortion = _extortion(result)
    actions = []

    # A detected extortion/sextortion finding - even a needs_review one -
    # must never be reported as "no action required" / "legitimate mail".
    # This check runs BEFORE the normal level-based branches and returns
    # immediately so a Low/Medium weighted score can never mask it.
    if extortion.get("detected") and extortion.get("needs_review"):
        _reason = extortion.get("review_reason")
        if _reason == "no_explicit_payment_demand":
            actions.append("**Manual review required.** This message pairs a claim to "
                           "possess private material with a threat to distribute it, but "
                           "no explicit payment demand was matched, so it was not "
                           "auto-escalated. Do not close this out as legitimate mail "
                           "without an analyst confirming whether it is a live threat.")
        elif _reason == "quoted_context":
            actions.append("**Manual review required.** This message matches the "
                           "extortion/sextortion pattern, but the matched threat "
                           "language appears quoted or attributed (e.g. inside "
                           "quotation marks or introduced as an example) rather "
                           "than stated directly, so it was not auto-escalated. "
                           "Do not close this out as legitimate mail without an "
                           "analyst confirming whether it is a live threat, a "
                           "forwarded threat, or genuine advisory content.")
        else:   # reason missing/unknown: never guess "quoted"
            actions.append("**Manual review required.** This message was flagged for "
                           "human review as a possible extortion/sextortion threat, but "
                           "the reason was not recorded, so it was not auto-escalated. "
                           "Do not close this out as legitimate mail without an analyst "
                           "confirming whether it is a live threat.")
        actions.append("Do not advise the recipient to pay or reply until "
                       "that review is complete.")
        actions.append("Preserve the original `.eml` with its hash for the "
                       "incident record before any remediation.")
        return actions

    # Defensive: a detected (non-needs_review) extortion finding is expected
    # to always carry risk.py's High/Critical override, but if some future
    # change ever left it at Medium/Low, it must still never be reported as
    # requiring no action - treat it like a High-level case rather than
    # falling through to the "legitimate mail" branch below.
    if extortion.get("detected") and not extortion.get("needs_review") and level not in ("Critical", "High"):
        level = "High"

    if level in ("Critical", "High"):
        actions.append("**Quarantine** this message and search the mail store "
                       "for others matching these indicators.")
        if iocs["suspicious_urls"]:
            actions.append("Block these hosts at the web proxy and DNS layer: "
                           + ", ".join("`{}`".format(u["host"])
                                       for u in iocs["suspicious_urls"] if u["host"]))
        if origin_ip:
            actions.append("Add `{}` to the mail-gateway blocklist and review "
                           "other traffic from it.".format(origin_ip))
        actions.append("Identify all recipients and check whether any "
                       "interacted with the message.")
        if extortion.get("detected"):
            actions.append("**Do not pay or reply.** This message matches the "
                           "sextortion/extortion pattern; advise the recipient "
                           "not to engage, preserve the evidence, and report it "
                           "to the referenced platform and to law enforcement / "
                           "a cybercrime reporting authority.")
        if result["headers"]["bec"]["is_bec"]:
            actions.append("**Contact the impersonated executive out of band** "
                           "(phone, not email) and freeze any payment already "
                           "initiated. Verify beneficiary changes against "
                           "records held outside email.")
        if not result["headers"]["bec"]["is_bec"] and not extortion.get("detected"):
            actions.append("Force a password reset for any recipient who "
                           "opened the link, and check for new mail-forwarding "
                           "rules on their mailbox.")
        actions.append("Preserve the original `.eml` with its hash for the "
                       "incident record before any remediation.")
    elif level == "Medium":
        actions.append("Hold for analyst review rather than automatic delivery.")
        actions.append("Warn the recipient not to act on links or payment "
                       "instructions until the sender is verified out of band.")
        actions.append("Re-check the sending domain's reputation before "
                       "releasing the message.")
    elif uncertain:
        actions.append("Hold for analyst review: the extortion assessment is unavailable or incomplete, so "
                       "this message cannot be recorded as legitimate yet.")
        actions.append("Preserve the original `.eml` with its hash for the incident record.")
    else:
        actions.append("No action required. Indicators are consistent with "
                       "legitimate mail.")
        actions.append("Retain the analysis record so this sender contributes "
                       "to the baseline of normal traffic.")
    return actions


if __name__ == "__main__":
    import os

    import config as C
    from analyzer import analyze_email

    path = os.path.join(C.SAMPLE_DIR, "phishing_credential.eml")
    with open(path, "rb") as fh:
        raw = fh.read()
    print(build_report(analyze_email(raw, os.path.basename(path)), raw))