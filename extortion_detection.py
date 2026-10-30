"""Module 2 (part 3): deterministic sextortion / extortion detection.

This is NOT the ML phishing classifier and does not touch its probability.
It is a separate, explainable, rule-based signal: four independent evidence
categories (possession claim, distribution threat, payment demand, coercive
pressure) are matched against the message text with regexes that tolerate
case, punctuation, currency and simple wording variation. A real extortion
attempt almost always combines several of these; a single category alone
(a photo mentioned, a dollar figure, the word "bitcoin") is common in
completely unrelated, legitimate mail and is NOT enough to fire.

Output never claims the sender actually possesses anything - only that the
message *contains a threat claiming to*. That distinction matters for the
UI and reports: we can be fully confident about what the text says and
still be agnostic about whether the claim is true.

Standalone:  python extortion_detection.py samples/sextortion.eml
"""
import re

# --- Evidence categories ----------------------------------------------------
# Each pattern list is matched with word boundaries, case-insensitive. Findall
# captures the literal phrase so it can be shown to the analyst as evidence.

# Each entry is (pattern, is_imagery). is_imagery=True means the claim is
# inherently about intimate/compromising photos or video (sextortion, even
# when the matched phrase itself doesn't spell out "photo"/"video" - e.g.
# "I recorded you through your webcam"); is_imagery=False covers generic
# possession claims (documents, data) used for non-sexual blackmail.
POSSESSION_PATTERNS = [
    (r"i\s+have\s+(?:your|a)\s+(?:private|personal|intimate|compromising|explicit)?\s*(?:photo|photos|picture|pictures|pic|pics|video|videos|footage|recording|recordings)", True),
    (r"i\s+(?:recorded|filmed|captured)\s+you", True),
    (r"i\s+(?:got|obtained|downloaded)\s+(?:your|a)\s+(?:private|personal|intimate|compromising|explicit)?\s*(?:photo|photos|picture|video|footage|recording)", True),
    (r"(?:webcam|camera)\s+(?:recording|footage|video)s?\s+of\s+you", True),
    (r"screen\s*record(?:er|ing|ed)?\s+(?:of\s+you|while\s+you)", True),
    (r"(?:nude|naked|explicit|intimate)\s+(?:photo|photos|picture|pictures|video|videos|pic|pics)\s+of\s+you", True),
    (r"(?:access|control)\s+(?:to|over)\s+your\s+(?:camera|webcam)", True),
    (r"(?:access|control)\s+(?:to|over)\s+your\s+(?:device|computer|phone|files|photos)", False),
    (r"malware\s+(?:on|installed\s+on)\s+your\s+(?:computer|device|phone|pc)", False),
    (r"i\s+have\s+(?:your|access\s+to\s+your)\s+(?:private|personal|confidential|sensitive)\s+(?:documents|files|data|information|messages|chats)", False),
]
_POSSESSION_IMAGERY_FLAGS = [imagery for _, imagery in POSSESSION_PATTERNS]
POSSESSION_PATTERNS = [p for p, _ in POSSESSION_PATTERNS]

DISTRIBUTION_THREAT_PATTERNS = [
    r"send\s+(?:it|them|this|these|a\s+copy)\s+to\s+(?:all\s+)?your\s+contacts",
    r"send\s+(?:it|them|this|these)\s+to\s+(?:your\s+)?(?:friends|family|colleagues|coworkers|boss|employer)",
    r"share\s+(?:it|them|this|these)\s+with\s+(?:your\s+)?(?:contacts|friends|family|colleagues|everyone)",
    r"post\s+(?:it|them|this|these)\s+(?:online|publicly|on\s+social\s+media)",
    r"(?:release|leak|publish|distribute)\s+(?:it|them|this|these|the\s+(?:photo|photos|picture|video|videos|footage))",
    r"everyone\s+(?:you\s+know|in\s+your\s+contacts)",
    r"all\s+your\s+contacts",
    r"your\s+(?:friends\s+and\s+family|contact\s+list|contacts\s+list)",
    r"expose\s+you",
    r"ruin\s+your\s+(?:life|reputation|career|marriage)",
    r"(?:your\s+)?(?:employer|boss|spouse|wife|husband|family)\s+will\s+(?:see|get|receive|find\s+out)",
]

PAYMENT_PATTERNS = [
    r"\$\s?[\d,]+(?:\.\d+)?",
    r"(?:usd|eur|gbp|inr|rs\.?)\s?[\d,]+(?:\.\d+)?",
    r"[\d,]+(?:\.\d+)?\s?(?:usd|dollars|euros|rupees)",
    r"\bbitcoin\b", r"\bbtc\b", r"\bcrypto(?:currency)?\b", r"\bwallet\s+address\b",
    r"\bethereum\b", r"\bmonero\b",
    r"gift\s*cards?",
    r"wire\s+(?:transfer|the\s+money|payment)",
    r"\bpay(?:ment)?\s+(?:me|us|\$|of)\b",
    r"\bransom\b",
    r"send\s+(?:the\s+)?(?:payment|money)",
]

COERCION_PATTERNS = [
    r"\bor\s+(?:i\s+will|i'll|i\s+am\s+going\s+to|im\s+going\s+to)\b",
    r"\bor\s+else\b",
    r"within\s+\d+\s*(?:hours?|days?|minutes?)",
    r"you\s+have\s+\d+\s*(?:hours?|days?|minutes?)",
    r"\bact\s+now\b",
    r"\bfinal\s+(?:warning|notice)\b",
    r"\blast\s+chance\b",
    r"time\s+is\s+running\s+out",
    r"don'?t\s+(?:try\s+to\s+)?(?:tell|contact)\s+(?:anyone|the\s+police)",
    r"\bno\s+negotiations?\b",
]

_CATEGORIES = {
    "possession_claim": POSSESSION_PATTERNS,
    "distribution_threat": DISTRIBUTION_THREAT_PATTERNS,
    "payment_demand": PAYMENT_PATTERNS,
    "coercive_pressure": COERCION_PATTERNS,
}

# Markers that the passage is discussing the topic rather than making a live
# threat against the reader: a security advisory, a news article, a quoted
# example in a training email, etc. These never suppress detection outright
# (an attacker could easily add "FYI" to a real threat) - they only prevent a
# strong finding from being escalated to "confirmed" without a second look,
# producing "needs_review" instead so a human stays in the loop.
EDUCATIONAL_MARKERS = [
    r"security\s+(?:awareness|advisory|alert|bulletin|training)",
    r"example\s+of\s+(?:a\s+)?(?:sextortion|extortion|phishing)",
    r"here'?s\s+what\s+a\s+scam\s+(?:email\s+)?looks\s+like",
    r"this\s+is\s+(?:an\s+)?example",
    r"do\s+not\s+(?:click|reply|pay|respond)",
    r"report\s+(?:this\s+)?to\s+(?:your\s+)?it\s+(?:department|team)",
    r"\bpsa\b",
    r"how\s+to\s+(?:recognize|spot|avoid)\s+(?:sextortion|extortion|blackmail)",
    r"sextortion\s+prevention",
]

_COMPILED = {
    cat: [re.compile(p, re.I) for p in pats] for cat, pats in _CATEGORIES.items()
}
_EDU_COMPILED = [re.compile(p, re.I) for p in EDUCATIONAL_MARKERS]


def _findings(text, patterns):
    hits = []
    for pat in patterns:
        for m in pat.finditer(text):
            phrase = m.group(0).strip()
            if phrase and phrase.lower() not in (h.lower() for h in hits):
                hits.append(phrase)
    return hits


def _findings_with_imagery(text, compiled_patterns, imagery_flags):
    """Like _findings, but also returns whether any imagery-flagged pattern matched."""
    hits, imagery = [], False
    for pat, is_imagery in zip(compiled_patterns, imagery_flags):
        for m in pat.finditer(text):
            phrase = m.group(0).strip()
            if phrase and phrase.lower() not in (h.lower() for h in hits):
                hits.append(phrase)
            if is_imagery:
                imagery = True
    return hits, imagery


def analyze(text):
    """Scan message text for the sextortion/extortion threat pattern.

    Returns a dict:
      detected (bool), category, severity ("critical"|"high"|"medium"|"low"|"none"),
      confidence (0..1 rule-strength, NOT the ML probability), strength (0..1,
      the value fed into risk.score), evidence (per-category sanitized phrases),
      explanation (str), recommended_action (str), needs_review (bool),
      educational_context (bool).
    """
    text = text or ""
    found = {}
    possession_hits, possession_imagery = _findings_with_imagery(
        text, _COMPILED["possession_claim"], _POSSESSION_IMAGERY_FLAGS)
    found["possession_claim"] = possession_hits
    for cat, pats in _COMPILED.items():
        if cat == "possession_claim":
            continue
        found[cat] = _findings(text, pats)
    categories_hit = [cat for cat, hits in found.items() if hits]
    n_categories = len(categories_hit)
    educational = any(p.search(text) for p in _EDU_COMPILED)

    has_possession = bool(found["possession_claim"])
    has_distribution = bool(found["distribution_threat"])
    has_payment = bool(found["payment_demand"])
    has_coercion = bool(found["coercive_pressure"])

    # Core pattern: a claim of possession/compromise + a payment demand, PLUS
    # either an explicit distribution threat or coercive pressure language.
    # Payment alone, or possession alone, or "contacts" alone is routine and
    # must never fire this detector by itself.
    core_hit = has_possession and has_payment and (has_distribution or has_coercion)
    # Non-sexual blackmail variant: confidential documents/data + payment +
    # (distribution threat or coercion) - same shape, no imagery category.
    blackmail_hit = core_hit

    detected = core_hit
    category = "none"
    if detected:
        category = "suspected_sextortion" if possession_imagery else "suspected_extortion"

    # Severity / confidence from how many independent categories corroborate
    # each other. Four categories = textbook sextortion email; three = still
    # a very strong match; the floor for "detected" is already three signals
    # (possession + payment + one of distribution/coercion).
    if not detected:
        severity, confidence, strength = "none", 0.0, 0.0
    elif n_categories >= 4:
        severity, confidence, strength = "critical", 0.95, 1.0
    elif n_categories == 3:
        severity, confidence, strength = "high", 0.85, 0.9
    else:  # should not normally happen given core_hit's requirements, kept defensive
        severity, confidence, strength = "medium", 0.6, 0.6

    needs_review = detected and educational
    if needs_review:
        # Do not silently drop a strong finding just because the mail also
        # contains advisory-sounding phrasing - downgrade confidence and
        # route to human review instead of asserting it outright.
        confidence = min(confidence, 0.5)
        strength = min(strength, 0.5)

    evidence = {cat: found[cat] for cat in categories_hit} if detected else {}

    if detected:
        explanation = (
            "The message combines a claim to possess compromising material, a "
            "monetary demand, and {} - the structural pattern of a sextortion "
            "/ extortion attempt. This finding describes what the TEXT "
            "threatens; it does not and cannot confirm that the sender "
            "actually holds any material.".format(
                "an explicit threat to distribute it" if has_distribution
                else "coercive pressure to pay quickly"
            )
        )
        if needs_review:
            explanation += (
                " The message also contains language typical of a security "
                "advisory or educational example, so this has been flagged "
                "for human review rather than asserted outright."
            )
        recommended_action = (
            "Do not pay or reply. Preserve the original message and headers. "
            "Do not delete the account or device. Report to the platform the "
            "threat references and to local law enforcement / a cybercrime "
            "reporting authority. Treat any purported evidence as unverified."
        )
    else:
        explanation = "No combination of possession claim, payment demand, and distribution/coercion threat was found."
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
        "educational_context": educational,
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
    print("evidence   =", result["evidence"])
