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
import re

import config as C

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


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


def analyze(parsed):
    """Returns {spf, dkim, dmarc, auth_fail_score, anomalies[], bec{}}."""
    auth = parsed.get("auth_results", "")
    spf = _verdict(auth, "spf")
    dkim = _verdict(auth, "dkim")
    dmarc = _verdict(auth, "dmarc")

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
                 "the domain's published {} policy.".format(mech))
        elif value == "none":
            flag("low", "{} result absent".format(mech),
                 "No {} verdict was stamped on this message.".format(mech))

    if from_domain and return_domain and from_domain != return_domain:
        flag("high", "Envelope / header sender mismatch",
             "From is @{} but the envelope Return-Path is @{}. Legitimate bulk "
             "senders usually align these.".format(from_domain, return_domain))

    if reply_domain and from_domain and reply_domain != from_domain:
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
