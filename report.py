"""Module 5 (part 2): the exportable forensic report.

Produces an investigator-facing Markdown document: verdict, scoring breakdown,
header evidence, routing chain, IOCs, and an explicit limitations section.

That last part matters. A report that overstates certainty is useless as
evidence, so we state plainly what is proven, what is inferred, and what would
need a subpoena or a live lookup to confirm.

Standalone:  python report.py > report.md
"""
import hashlib
from datetime import datetime, timezone

SEVERITY_MARK = {"high": "[HIGH]", "medium": "[MED] ", "low": "[LOW] ",
                 "info": "[INFO]"}


def evidence_hash(raw):
    """SHA-256 of the original bytes - the integrity anchor for the exhibit."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


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
    add("| Primary driver | {} |".format(verdict.get("top_driver", "-")))
    add("| ML phishing probability | {:.1%} |".format(result["ml"]["prob"]))
    add("")
    add("### How the score was reached")
    add("")
    add("| Signal | Strength | Weight | Points |")
    add("| --- | --- | --- | --- |")
    for c in verdict["contributions"]:
        add("| {} | {:.0%} | {} | {:.1f} |".format(
            c["label"], c["strength"], c["weight"], c["points"]))
    add("| | | **Total** | **{:.1f}** |".format(result["score"]))
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
        add("| {} | `{}` |".format(label, value or "(absent)"))
    add("")

    # --- 3. Authentication --------------------------------------------------
    add("## 3. Authentication results")
    add("")
    add("| Mechanism | Result |")
    add("| --- | --- |")
    for mech in ("spf", "dkim", "dmarc"):
        add("| {} | **{}** |".format(mech.upper(), headers.get(mech, "none").upper()))
    add("")
    add("> These are the verdicts stamped by the receiving mail server at "
        "delivery time. They are re-read, not re-computed, because DNS records "
        "may have changed since delivery.")
    add("")

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

    # --- 4. Routing ---------------------------------------------------------
    add("## 4. Origin and routing")
    add("")
    add(geo.get("summary", "No routing information available."))
    add("")
    if geo.get("hops"):
        add("| # | IP | Location | Network | Infrastructure |")
        add("| --- | --- | --- | --- | --- |")
        for hop in geo["hops"]:
            where = ", ".join(p for p in [hop.get("city"), hop.get("country")] if p)
            add("| {} | `{}` | {} | {} | {} |".format(
                hop.get("hop_index", "?"), hop["ip"], where or "Unknown",
                hop.get("isp") or "-", hop.get("infra_label", "-")))
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

    # --- 5. IOCs ------------------------------------------------------------
    add("## 5. Indicators of compromise")
    add("")
    if iocs["urls"]:
        add("| URL | Host | Assessment |")
        add("| --- | --- | --- |")
        for u in iocs["urls"]:
            add("| `{}` | `{}` | {} |".format(
                u["url"][:70], u["host"] or "-",
                "; ".join(u["flags"]) if u["flags"] else "no indicators"))
        add("")
    else:
        add("No URLs present in the message body.")
        add("")

    for label, values in (("Domains", iocs["domains"]),
                          ("IP addresses in body", iocs["ips"]),
                          ("Email addresses", iocs["emails"]),
                          ("Cryptocurrency wallets", iocs["wallets"])):
        if values:
            add("**{}:** {}".format(
                label, ", ".join("`{}`".format(v) for v in values)))
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
    add("- **Privacy.** This report contains personal data. Handle it under the "
        "DPDP Act 2023 and your organisation's retention policy, and restrict "
        "access to authorised investigators.")
    add("- Analysis was performed offline on a stored copy; the original "
        "message was not modified. The SHA-256 above lets any reviewer confirm "
        "the exhibit is unaltered.")
    add("")
    add("---")
    add("")
    add("*Generated by the SIH26106 Email Threat Detection, GeoLocation and "
        "Forensic Intelligence Platform.*")

    return "\n".join(lines)


def _actions(result):
    """Verdict-appropriate response steps."""
    level = result["level"]
    iocs = result["iocs"]
    geo = result["geo"]
    origin_ip = (geo.get("origin") or {}).get("ip")
    actions = []

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
        if result["headers"]["bec"]["is_bec"]:
            actions.append("**Contact the impersonated executive out of band** "
                           "(phone, not email) and freeze any payment already "
                           "initiated. Verify beneficiary changes against "
                           "records held outside email.")
        else:
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
