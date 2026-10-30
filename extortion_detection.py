"""Module 2 (part 3): deterministic sextortion / extortion detection.

This is NOT the ML phishing classifier and does not touch its probability.
It is a separate, explainable, rule-based signal: four independent evidence
categories (possession claim, distribution threat, payment demand, coercive
pressure) are matched against the message text with regexes that tolerate
case, punctuation, currency and realistic paraphrase. A real extortion
attempt almost always combines several of these; a single category alone
(a photo mentioned, a bare dollar figure, the word "bitcoin") is common in
completely unrelated, legitimate mail and is NOT enough to fire.

Payment detection is CONTEXTUAL: a currency amount only counts as evidence
of a payment demand when it sits near a payment-indicating verb/noun
("pay", "send", "wire", "transfer", ...) or is itself an inherently
payment-shaped token (bitcoin, gift card, wallet address, ransom). An
invoice that just states "$3,000" with no demand language never counts.

Educational / advisory handling is context-aware rather than a blanket
keyword downgrade: a message only gets routed to needs_review when the
matched threat language is itself quoted or clearly attributed as someone
else's example ("...reads: \"...\"", inside quotation marks, "for example,
scammers write ..."). Simply adding a phrase like "security awareness" to
an otherwise live, directly-addressed threat does NOT downgrade it - that
would be a trivial bypass.

Output never claims the sender actually possesses anything - only that the
message *contains a threat claiming to*. That distinction matters for the
UI and reports: we can be fully confident about what the text says and
still be agnostic about whether the claim is true.

Standalone:  python extortion_detection.py samples/sextortion.eml
"""
import re

# --- Possession claims --------------------------------------------------
# Each entry bundles its compiled pattern together with whether it is
# inherently about intimate/compromising photos or video (imagery=True,
# sextortion) vs. a generic claim used for non-sexual blackmail
# (imagery=False, e.g. documents, device access). Kept as one list of
# dicts so the classification travels with the pattern itself instead of
# depending on two lists staying in the same order.
_POSSESSION_DEFS = [
    {"pattern": r"i(?:'ve| have)?\s+(?:have|got|obtained|downloaded|saved|backed\s+up)\s+(?:your|a)\s+"
                r"(?:private|personal|intimate|compromising|explicit|embarrassing)?\s*"
                r"(?:photo|photos|picture|pictures|pic|pics|video|videos|footage|recording|recordings|clip|clips)",
     "imagery": True},
    {"pattern": r"i(?:'m| am)?\s+in\s+possession\s+of\s+(?:your|a)\s+"
                r"(?:private|personal|intimate|compromising|explicit)?\s*"
                r"(?:photo|photos|picture|video|footage|recording)",
     "imagery": True},
    {"pattern": r"i\s+(?:recorded|filmed|captured|caught)\s+you(?:\s+on\s+(?:cam|camera|webcam))?",
     "imagery": True},
    {"pattern": r"(?:webcam|camera)\s+(?:recording|footage|video)s?\s+of\s+you",
     "imagery": True},
    {"pattern": r"(?:recorded|filmed)\s+(?:you\s+)?(?:through|via|using)\s+your\s+(?:webcam|camera)",
     "imagery": True},
    {"pattern": r"(?:hacked|accessed|took\s+over|gained\s+access\s+to)\s+your\s+(?:webcam|camera)",
     "imagery": True},
    {"pattern": r"screen\s*record(?:er|ing|ed)?\s+(?:of\s+you|while\s+you|your\s+screen)",
     "imagery": True},
    {"pattern": r"(?:nude|naked|explicit|intimate|compromising)\s+(?:photo|photos|picture|pictures|video|"
                r"videos|pic|pics|content)\s+of\s+you",
     "imagery": True},
    {"pattern": r"(?:saw|watched)\s+you\s+(?:on\s+(?:cam|camera|webcam)|through\s+your\s+(?:camera|webcam))",
     "imagery": True},
    {"pattern": r"(?:access|control)\s+(?:to|over)\s+your\s+(?:camera|webcam)",
     "imagery": True},
    {"pattern": r"(?:access|control)\s+(?:to|over)\s+your\s+(?:device|computer|phone|files)",
     "imagery": False},
    {"pattern": r"malware\s+(?:on|installed\s+on)\s+your\s+(?:computer|device|phone|pc)",
     "imagery": False},
    {"pattern": r"i\s+have\s+(?:your|access\s+to\s+your)\s+(?:private|personal|confidential|sensitive)\s+"
                r"(?:documents|files|data|information|messages|chats|records)",
     "imagery": False},
    {"pattern": r"i\s+know\s+(?:about\s+)?your\s+(?:affair|secret|criminal\s+record)",
     "imagery": False},
    {"pattern": r"(?:i'?v?e?\s+)?(?:got|have)\s+(?:some\s+)?(?:private|personal|intimate|compromising|"
                r"explicit)?\s*(?:pics|pictures|photos|footage|clips?|videos?)\s+"
                r"(?:of\s+you\s+)?from\s+your\s+(?:camera|webcam|phone|computer)",
     "imagery": True},
]
for _d in _POSSESSION_DEFS:
    _d["regex"] = re.compile(_d["pattern"], re.I)

DISTRIBUTION_THREAT_PATTERNS = [
    r"send\s+(?:it|them|this|these|a\s+copy|copies)\s+to\s+(?:all\s+)?your\s+contacts",
    r"send\s+(?:it|them|this|these|a\s+copy|copies)\s+to\s+(?:your\s+)?(?:friends|family|colleagues|coworkers|boss|employer)",
    r"forward\s+(?:it|them|this|these)\s+to\s+(?:everyone|all)\s+(?:in\s+)?your\s+contact(?:\s+list)?",
    r"share\s+(?:it|them|this|these)\s+with\s+(?:your\s+)?(?:contacts|friends|family|colleagues|everyone)",
    r"post\s+(?:it|them|this|these)\s+(?:online|publicly|on\s+social\s+media)",
    r"(?:release|leak|publish|distribute|upload)\s+(?:it|them|this|these|the\s+(?:photo|photos|picture|video|videos|footage))",
    r"(?:release|leak|publish|distribute|upload)\s+(?:it|them)\s+publicly",
    r"make\s+(?:it|them|this|these)\s+public",
    r"everyone\s+(?:you\s+know|in\s+your\s+contacts|in\s+your\s+address\s+book)",
    r"all\s+your\s+contacts",
    r"your\s+(?:friends\s+and\s+family|contact\s+list|contacts\s+list|address\s+book)",
    r"expose\s+you",
    r"ruin\s+your\s+(?:life|reputation|career|marriage)",
    r"(?:your\s+)?(?:employer|boss|spouse|wife|husband|family)\s+will\s+(?:see|get|receive|find\s+out)",
    r"(?:it|this|they)\s+(?:will\s+)?go(?:es)?\s+out\s+to\s+(?:everyone|all)",
    r"(?:goes?|go)\s+(?:out\s+)?(?:to\s+)?everyone\s+you\s+know",
    r"you\s+(?:wouldn'?t|don'?t)\s+want\s+your\s+(?:contacts|friends|family|boss|employer)\s+(?:seeing|to\s+see)",
]

# A payment demand requires an amount/method of payment AND a payment verb
# or payment-shaped keyword in context - a bare currency figure never
# counts alone. "method" patterns (bitcoin, gift card, wire transfer, ...)
# are self-contextualising, since nothing legitimate uses them as a noun
# in casual conversation nearly as often as extortion/scam mail does.
_AMOUNT = r"(?:\$\s?[\d,]+(?:\.\d+)?|(?:usd|eur|gbp|inr|rs\.?)\s?[\d,]+(?:\.\d+)?|[\d,]+(?:\.\d+)?\s?(?:usd|dollars|euros|rupees))"
_PAY_VERB = r"(?:pay|paying|paid|send|sending|wire|wiring|transfer|transferring|deposit|depositing|remit|remitting|owe|settle|settling|hand\s+over|cough\s+up)"

PAYMENT_PATTERNS = [
    # verb ... amount, and amount ... verb, within the same clause (no
    # sentence-ending punctuation in between so unrelated numbers elsewhere
    # in the message don't get swept in).
    r"{verb}\w*[^.?!\n]{{0,40}}{amount}".format(verb=_PAY_VERB, amount=_AMOUNT),
    r"{amount}[^.?!\n]{{0,40}}{verb}\w*".format(verb=_PAY_VERB, amount=_AMOUNT),
    r"{amount}\s*(?:worth\s+of\s+)?(?:in\s+)?(?:bitcoin|btc|crypto(?:currency)?|ethereum|monero)".format(amount=_AMOUNT),
    r"\bbitcoin\b", r"\bbtc\b", r"\bcrypto(?:currency)?\b", r"\bwallet\s+address\b",
    r"\bethereum\b", r"\bmonero\b",
    r"gift\s*cards?",
    r"wire\s+(?:transfer|the\s+money|payment)",
    r"\bransom\b",
    r"send\s+(?:the\s+)?(?:payment|money)\b",
    r"settle\s+this\s+with\s+{amount}".format(amount=_AMOUNT),
]

COERCION_PATTERNS = [
    r"\bor\s+(?:i\s+will|i'll|i\s+am\s+going\s+to|im\s+going\s+to|they\s+go)\b",
    r"\bor\s+else\b",
    r"within\s+\d+\s*(?:hours?|days?|minutes?)",
    r"you\s+have\s+\d+\s*(?:hours?|days?|minutes?)",
    r"you\s+have\s+until\s+\w+",
    r"(?:next|coming)\s+\d+\s*(?:hours?|days?)",
    r"\bact\s+now\b",
    r"\bfinal\s+(?:warning|notice)\b",
    r"\bno\s+(?:more|further)\s+warnings?\b",
    r"\blast\s+chance\b",
    r"time\s+is\s+running\s+out",
    r"don'?t\s+(?:try\s+to\s+)?(?:tell|contact)\s+(?:anyone|the\s+police)",
    r"keep\s+this\s+(?:between\s+us|quiet|private)",
    r"\bno\s+negotiations?\b",
]

_CATEGORIES_SIMPLE = {
    "distribution_threat": DISTRIBUTION_THREAT_PATTERNS,
    "payment_demand": PAYMENT_PATTERNS,
    "coercive_pressure": COERCION_PATTERNS,
}
_COMPILED = {cat: [re.compile(p, re.I) for p in pats] for cat, pats in _CATEGORIES_SIMPLE.items()}

# --- Quote / attribution context -------------------------------------------
# Spans of text that are quoted (straight or curly double quotes) or that
# follow a reporting verb colon ("...reads:", "...says:", "example:").
# Evidence matches that fall ENTIRELY inside one of these spans are being
# presented as someone else's words, not stated directly by this message's
# author to this recipient - the hallmark of a security advisory quoting a
# sample scam, or a victim forwarding a threat for advice. A bare keyword
# like "security awareness" sitting next to an otherwise live, unquoted,
# directly-addressed threat does NOT trigger this path.
_DOUBLE_QUOTE_SPAN_RE = re.compile(r'["\u201c]([^"\u201c\u201d]{10,500})["\u201d]')
# Single/curly single quotes are also used for quoted examples, but a bare
# apostrophe is far more often a contraction ("don't", "I'll"). Require at
# least a few words (two internal spaces) so a quoted sentence qualifies
# while "don't" or "I'll" never does.
_SINGLE_QUOTE_SPAN_RE = re.compile(r"'([^']{10,500})'|\u2018([^\u2018\u2019]{10,500})\u2019")
_REPORTING_LEAD_RE = re.compile(
    r"(?:reads?|says?|writes?|states?|looks\s+like\s+this|an?\s+example|for\s+example)\s*"
    r"[:\-]?\s*['\u2018\"\u201c]?\s*([^\n]{10,500})", re.I)


def _quoted_spans(text):
    spans = []
    for m in _DOUBLE_QUOTE_SPAN_RE.finditer(text):
        spans.append((m.start(1), m.end(1)))
    for m in _SINGLE_QUOTE_SPAN_RE.finditer(text):
        g = m.group(1) or m.group(2)
        if g and g.count(" ") >= 2:   # at least a few words, not a contraction
            start = m.start(1) if m.group(1) is not None else m.start(2)
            end = m.end(1) if m.group(1) is not None else m.end(2)
            spans.append((start, end))
    for m in _REPORTING_LEAD_RE.finditer(text):
        spans.append((m.start(1), m.end(1)))
    return spans


def _inside_any(span, containers):
    s, e = span
    return any(cs <= s and e <= ce for cs, ce in containers)


def _findings(text, patterns):
    """Returns list of (phrase, start, end, is_quoted)."""
    out = []
    quote_spans = _quoted_spans(text)
    for pat in patterns:
        for m in pat.finditer(text):
            phrase = m.group(0).strip()
            if not phrase:
                continue
            span = (m.start(), m.end())
            if phrase.lower() in (h[0].lower() for h in out):
                continue
            out.append((phrase, span[0], span[1], _inside_any(span, quote_spans)))
    return out


def _possession_findings(text):
    """Returns list of (phrase, start, end, is_quoted, is_imagery)."""
    out = []
    quote_spans = _quoted_spans(text)
    for d in _POSSESSION_DEFS:
        for m in d["regex"].finditer(text):
            phrase = m.group(0).strip()
            if not phrase:
                continue
            span = (m.start(), m.end())
            if phrase.lower() in (h[0].lower() for h in out):
                continue
            out.append((phrase, span[0], span[1], _inside_any(span, quote_spans), d["imagery"]))
    return out


def analyze(text):
    """Scan message text for the sextortion/extortion threat pattern.

    Returns a dict:
      detected (bool), category, severity ("critical"|"high"|"medium"|"low"|"none"),
      confidence (0..1 rule-strength, NOT the ML probability), strength (0..1,
      the value fed into risk.score), evidence (per-category sanitized phrases),
      explanation (str), recommended_action (str), needs_review (bool),
      quoted_context (bool).
    """
    text = text or ""

    possession = _possession_findings(text)
    found = {"possession_claim": possession}
    for cat, pats in _COMPILED.items():
        found[cat] = _findings(text, pats)

    categories_hit = [cat for cat, hits in found.items() if hits]
    n_categories = len(categories_hit)

    has_possession = bool(possession)
    has_distribution = bool(found["distribution_threat"])
    has_payment = bool(found["payment_demand"])
    has_coercion = bool(found["coercive_pressure"])

    core_hit = has_possession and has_payment and (has_distribution or has_coercion)
    detected = core_hit

    # A finding is "quoted" only if the possession claim AND the payment
    # demand AND whichever of distribution/coercion fired are ALL inside a
    # quoted/attributed span - i.e. the whole threat is being reproduced as
    # someone else's words, not stated live by this message's own author.
    quoted_context = False
    possession_imagery = False
    if detected:
        possession_imagery = any(h[4] for h in possession)
        possession_all_quoted = all(h[3] for h in possession)
        payment_all_quoted = all(h[3] for h in found["payment_demand"])
        closing_hits = found["distribution_threat"] if has_distribution else found["coercive_pressure"]
        closing_all_quoted = all(h[3] for h in closing_hits) if closing_hits else False
        quoted_context = possession_all_quoted and payment_all_quoted and closing_all_quoted

    category = "none"
    if detected:
        category = "suspected_sextortion" if possession_imagery else "suspected_extortion"

    if not detected:
        severity, confidence, strength = "none", 0.0, 0.0
    elif n_categories >= 4:
        severity, confidence, strength = "critical", 0.95, 1.0
    elif n_categories == 3:
        severity, confidence, strength = "high", 0.85, 0.9
    else:  # defensive; core_hit's requirements make this unreachable in practice
        severity, confidence, strength = "medium", 0.6, 0.6

    needs_review = detected and quoted_context
    if needs_review:
        # The threat text itself is quoted/attributed (an advisory quoting a
        # sample, or a forwarded threat) - do not silently drop the finding,
        # but do not assert it with full confidence either. A human decides.
        confidence = min(confidence, 0.5)
        strength = min(strength, 0.5)

    evidence = {cat: [h[0] for h in found[cat]] for cat in categories_hit} if detected else {}

    if detected:
        explanation = (
            "The message combines a claim to possess compromising material, a "
            "contextual monetary demand, and {} - the structural pattern of a "
            "sextortion / extortion attempt. This finding describes what the "
            "TEXT threatens; it does not and cannot confirm that the sender "
            "actually holds any material.".format(
                "an explicit threat to distribute it" if has_distribution
                else "coercive pressure to pay quickly"
            )
        )
        if needs_review:
            explanation += (
                " The matched threat language appears quoted or attributed "
                "(e.g. inside quotation marks, or introduced as an example) "
                "rather than stated directly by this message, so this has "
                "been routed to human review instead of asserted outright."
            )
        recommended_action = (
            "Do not pay or reply. Preserve the original message and headers. "
            "Do not delete the account or device. Report to the platform the "
            "threat references and to local law enforcement / a cybercrime "
            "reporting authority. Treat any purported evidence as unverified."
        )
        if needs_review:
            recommended_action = (
                "Route to an analyst for manual review before acting: the "
                "message matches the extortion/sextortion pattern, but the "
                "matched language appears quoted or attributed rather than "
                "stated directly, so automated escalation alone is not "
                "conclusive. Do not close this out as legitimate without a "
                "human check."
            )
    else:
        explanation = ("No combination of possession claim, a contextual payment demand, and a "
                       "distribution/coercion threat was found.")
        recommended_action = ""

    return {
        "detected": detected,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "strength": strength,
        "evidence": evidence,
        "categories_hit": categories_hit,
        "explanation": explanation,
        "recommended_action": recommended_action,
        "needs_review": needs_review,
        "quoted_context": quoted_context,
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        from email_parser import parse_eml
        with open(sys.argv[1], "rb") as fh:
            parsed = parse_eml(fh.read())
        sample_text = parsed.get("full_text", "")
    else:
        sample_text = ("I have your private pictures from your webcam. Pay $3,000 in "
                        "bitcoin within 24 hours or I will send them to all your contacts.")

    result = analyze(sample_text)
    print("detected   =", result["detected"])
    print("category   =", result["category"])
    print("severity   =", result["severity"])
    print("confidence = {:.2f}".format(result["confidence"]))
    print("strength   = {:.2f}".format(result["strength"]))
    print("needs_review =", result["needs_review"])
    print("evidence   =", result["evidence"])
