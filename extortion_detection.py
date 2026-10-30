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

Every pattern carries a stable ID (poss_*, dist_*, pay_*, coer_*); analyze() reports the IDs that
matched in result["pattern_ids"] so tests and reviewers can assert WHICH rule fired.

Payment-vs-distribution: "send/forward/share it to your contacts" is content DISTRIBUTION, never a
payment. Only money-shaped objects make "send" a payment verb, and crypto words count only inside a
demand ("pay ... in bitcoin", "send 0.5 BTC"), never as a bare mention ("we accept bitcoin").

Standalone:  python extortion_detection.py samples/sextortion.eml
"""
import html
import re
import unicodedata

# --- Possession claims --------------------------------------------------
# Each entry bundles its compiled pattern together with whether it is
# inherently about intimate/compromising photos or video (imagery=True,
# sextortion) vs. a generic claim used for non-sexual blackmail
# (imagery=False, e.g. documents, device access). Kept as one list of
# dicts so the classification travels with the pattern itself instead of
# depending on two lists staying in the same order.
_POSSESSION_DEFS = [
    {"id": "poss_have_media", "pattern": r"i(?:'ve| have)?\s+(?:have|got|obtained|downloaded|saved|backed\s+up)\s+(?:your|a)\s+"
                r"(?:private|personal|intimate|compromising|explicit|embarrassing)?\s*"
                r"(?:photo|photos|picture|pictures|pic|pics|video|videos|footage|recording|recordings|clip|clips)",
     "imagery": True},
    {"id": "poss_in_possession", "pattern": r"i(?:'m| am)?\s+in\s+possession\s+of\s+(?:your|a)\s+"
                r"(?:private|personal|intimate|compromising|explicit)?\s*"
                r"(?:photo|photos|picture|video|footage|recording)",
     "imagery": True},
    {"id": "poss_recorded_you", "pattern": r"i\s+(?:recorded|filmed|captured|caught)\s+you(?:\s+on\s+(?:cam|camera|webcam))?",
     "imagery": True},
    {"id": "poss_webcam_footage_of_you", "pattern": r"(?:webcam|camera)\s+(?:recording|footage|video)s?\s+of\s+you",
     "imagery": True},
    {"id": "poss_recorded_via_webcam", "pattern": r"(?:recorded|filmed)\s+(?:you\s+)?(?:through|via|using)\s+your\s+(?:webcam|camera)",
     "imagery": True},
    {"id": "poss_hacked_webcam", "pattern": r"(?:hacked|accessed|took\s+over|gained\s+access\s+to)\s+your\s+(?:webcam|camera)",
     "imagery": True},
    {"id": "poss_screen_recording", "pattern": r"screen\s*record(?:er|ing|ed)?\s+(?:of\s+you|while\s+you|your\s+screen)",
     "imagery": True},
    {"id": "poss_explicit_content_of_you", "pattern": r"(?:nude|naked|explicit|intimate|compromising)\s+(?:photo|photos|picture|pictures|video|"
                r"videos|pic|pics|content)\s+of\s+you",
     "imagery": True},
    {"id": "poss_saw_you_on_cam", "pattern": r"(?:saw|watched)\s+you\s+(?:on\s+(?:cam|camera|webcam)|through\s+your\s+(?:camera|webcam))",
     "imagery": True},
    {"id": "poss_access_camera", "pattern": r"(?:access|control)\s+(?:to|over)\s+your\s+(?:camera|webcam)",
     "imagery": True},
    {"id": "poss_access_device", "pattern": r"(?:access|control)\s+(?:to|over)\s+your\s+(?:device|computer|phone|files)",
     "imagery": False},
    {"id": "poss_malware", "pattern": r"malware\s+(?:on|installed\s+on)\s+your\s+(?:computer|device|phone|pc)",
     "imagery": False},
    {"id": "poss_private_documents", "pattern": r"i\s+have\s+(?:your|access\s+to\s+your)\s+(?:private|personal|confidential|sensitive)\s+"
                r"(?:documents|files|data|information|messages|chats|records)",
     "imagery": False},
    {"id": "poss_know_secret", "pattern": r"i\s+know\s+(?:about\s+)?your\s+(?:affair|secret|criminal\s+record)",
     "imagery": False},
    {"id": "poss_got_media_from_device", "pattern": r"(?:i'?v?e?\s+)?(?:got|have)\s+(?:some\s+)?(?:private|personal|intimate|compromising|"
                r"explicit)?\s*(?:pics|pictures|photos|footage|clips?|videos?)\s+"
                r"(?:of\s+you\s+)?from\s+your\s+(?:camera|webcam|phone|computer)",
     "imagery": True},
    {"id": "poss_have_recorded_you", "pattern": r"i(?:'ve|\s+have)\s+(?:been\s+)?(?:recorded|recording|filmed|filming|captured|capturing)\s+you",
     "imagery": True},
    {"id": "poss_video_of_you", "pattern": r"(?:i\s+)?(?:have|got|obtained)\s+(?:an?|some)\s+(?:(?:private|personal|intimate|compromising|explicit|embarrassing|nude)\s+)?"
                r"(?:video|videos|footage|photo|photos|picture|pictures|recording|recordings|clip|clips)\s+of\s+you",
     "imagery": True},
    {"id": "poss_hacked_device", "pattern": r"i\s+(?:have\s+)?(?:hacked|compromised|infected|took\s+over|gained\s+control\s+of)\s+your\s+"
                r"(?:device|computer|phone|pc|laptop|account|system)",
     "imagery": False},
]
for _d in _POSSESSION_DEFS:
    _d["regex"] = re.compile(_d["pattern"], re.I)


# Same-clause gap: anything except sentence-ending punctuation, but a decimal point BETWEEN DIGITS ("0.3 BTC",
# "$1,500.50") does not end the clause.
_GAP40 = r"(?:[^.?!\n]|(?<=\d)\.(?=\d)){0,40}"
_GAP30 = r"(?:[^.?!\n]|(?<=\d)\.(?=\d)){0,30}"


def _defs(prefix, items):
    """[(short_id, pattern)] -> [{"id", "pattern", "regex"}] with compiled, case-insensitive regexes."""
    out = []
    for i, p in items:
        p = p.replace(r"[^.?!\n]{0,40}", _GAP40).replace(r"[^.?!\n]{0,30}", _GAP30)
        out.append({"id": "{}_{}".format(prefix, i), "pattern": p, "regex": re.compile(p, re.I)})
    return out


_DISTRIBUTION_DEFS = _defs("dist", [
    ("send_to_contacts", r"send\s+(?:it|them|this|these|a\s+copy|copies)\s+to\s+(?:all\s+)?your\s+contacts"),
    ("send_to_people", r"send\s+(?:it|them|this|these|a\s+copy|copies)\s+to\s+(?:your\s+)?(?:friends|family|colleagues|coworkers|boss|employer)"),
    ("forward_to_everyone", r"forward\s+(?:it|them|this|these)\s+to\s+(?:everyone|all)\s+(?:in\s+)?your\s+contact(?:\s+list)?"),
    ("share_with", r"share\s+(?:it|them|this|these)\s+with\s+(?:your\s+)?(?:contacts|friends|family|colleagues|everyone)"),
    ("post_online", r"post\s+(?:it|them|this|these)\s+(?:online|publicly|on\s+social\s+media)"),
    ("release_media", r"(?:release|leak|publish|distribute|upload)\s+(?:it|them|this|these|the\s+(?:photo|photos|picture|video|videos|footage))"),
    ("release_publicly", r"(?:release|leak|publish|distribute|upload)\s+(?:it|them)\s+publicly"),
    ("make_public", r"make\s+(?:it|them|this|these)\s+public"),
    ("everyone_you_know", r"everyone\s+(?:you\s+know|in\s+your\s+contacts|in\s+your\s+address\s+book)"),
    ("all_your_contacts", r"all\s+your\s+contacts"),
    ("friends_family_list", r"your\s+(?:friends\s+and\s+family|contact\s+list|contacts\s+list|address\s+book)"),
    ("expose_you", r"expose\s+you"),
    ("ruin_life", r"ruin\s+your\s+(?:life|reputation|career|marriage)"),
    ("employer_will_see", r"(?:your\s+)?(?:employer|boss|spouse|wife|husband|family)\s+will\s+(?:see|get|receive|find\s+out)"),
    ("goes_out_to_everyone", r"(?:it|this|they)\s+(?:will\s+)?go(?:es)?\s+out\s+to\s+(?:everyone|all)"),
    ("go_to_everyone_you_know", r"(?:goes?|go)\s+(?:out\s+)?(?:to\s+)?everyone\s+you\s+know"),
    ("wouldnt_want_contacts_seeing", r"you\s+(?:wouldn'?t|don'?t)\s+want\s+your\s+(?:contacts|friends|family|boss|employer)\s+(?:seeing|to\s+see)"),
])
DISTRIBUTION_THREAT_PATTERNS = [d["pattern"] for d in _DISTRIBUTION_DEFS]   # kept for backward compatibility

# --- Payment demand ---------------------------------------------------------------------------------
# A payment demand needs a MONEY-shaped object or method inside a demand: a bare amount ("$3,000"), a bare
# crypto word ("we accept bitcoin") or the verb "send" followed by content ("send it to your contacts")
# never counts. "send" is deliberately NOT in the generic payment-verb list: it is only a payment verb when
# its object is money ("send $3,000", "send 0.5 BTC", "send the payment"). Content-distribution objects
# directly after any payment verb (e.g. "transfer them to your contacts") are excluded by _NOT_CONTENT.
# Written amounts ("three thousand dollars", "five hundred euros"): number words are only accepted when
# followed by an explicit currency word, so "three days" / "five photos" never count as money. Every repetition
# is BOUNDED ({0,N}) so hostile input such as "1,1,1,..." or "one-one-one-..." cannot cause quadratic scans.
_NUMWORD = (r"(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|"
            r"sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|"
            r"hundred|thousand|million|lakhs?|crores?)")
_WRITTEN_AMOUNT = (r"\b(?:an?\s+)?" + _NUMWORD + r"(?:[\s-]+(?:and\s+)?" + _NUMWORD + r"){0,6}"
                   r"\s+(?:us\s+|u\.s\.\s+)?(?:dollars|euros|pounds|rupees|bucks)\b")
_AMOUNT = (r"(?:" + _WRITTEN_AMOUNT
           + r"|[$\u20ac\u00a3\u20b9]\s?\d[\d,]{0,15}(?:\.\d+)?"
           + r"|\b(?:usd|eur|gbp|inr|rs\.?)\s?\d[\d,]{0,15}(?:\.\d+)?"
           + r"|\d[\d,]{0,15}(?:\.\d+)?\s?(?:usd|dollars|euros|rupees|pounds|gbp|eur|inr|bucks))")
_CRYPTO = r"(?:bitcoins?|btc|crypto(?:currency)?|ethereum|eth|monero|xmr|usdt)"
_NOT_CONTENT = (r"(?!\s+(?:a\s+copy\s+of\s+)?(?:it|them|this|these|those|copies|"
                r"the\s+(?:photos?|pictures?|videos?|footage|files?|content|images?|material))\b)")
_PAY_VERB = (r"\b(?:pay|paying|paid|wire|wiring|transfer|transferring|deposit|depositing|remit|remitting|owe|"
             r"settle|settling|hand\s+over|cough\s+up)\w*\b" + _NOT_CONTENT)
_SEND = r"send(?:ing)?\s+(?:me\s+|us\s+)?"

_PAYMENT_DEFS = _defs("pay", [
    ("verb_amount", r"{verb}[^.?!\n]{{0,40}}{amount}".format(verb=_PAY_VERB, amount=_AMOUNT)),
    ("amount_verb", r"{amount}[^.?!\n]{{0,40}}{verb}".format(verb=_PAY_VERB, amount=_AMOUNT)),
    ("send_amount", r"\b" + _SEND + r"(?:over\s+)?" + _AMOUNT),
    ("give_amount", r"\b(?:give|get|bring|provide)\s+(?:me|us)\s+(?:over\s+)?" + _AMOUNT),
    ("demand_amount", r"\b(?:want|need|demand|require|expect)\s+(?:me\s+|us\s+)?(?:you\s+to\s+\w+\s+)?(?:over\s+)?" + _AMOUNT),
    ("amount_or_threat", _AMOUNT + r"\s*,?\s*or\s+(?:i\s+will|i'll|i\s+am\s+going\s+to|else)\b"),
    ("send_money", r"\b" + _SEND + r"(?:the\s+)?(?:payment|money|funds|ransom)\b"),
    ("amount_in_crypto", r"{amount}\s*(?:worth\s+of\s+)?(?:in\s+)?{crypto}\b".format(amount=_AMOUNT, crypto=_CRYPTO)),
    ("verb_crypto", r"{verb}[^.?!\n]{{0,40}}\b{crypto}\b".format(verb=_PAY_VERB, crypto=_CRYPTO)),
    ("send_crypto", r"\b" + _SEND + r"(?:the\s+|a\s+|[\d.,]+\s*)?{crypto}\b".format(crypto=_CRYPTO)),
    ("to_wallet", r"\b(?:send|pay|transfer|deposit|wire)\w*[^.?!\n]{{0,40}}\bto\s+(?:this|my|our|the\s+following)\s+"
                  r"(?:{crypto}\s+(?:wallet|address)|wallet(?:\s+address)?)\b".format(crypto=_CRYPTO)),
    ("gift_card_demand", r"\b(?:pay|buy|purchase|send|deposit)\w*[^.?!\n]{0,30}\bgift\s*cards?\b"),
    ("amount_in_gift_card", r"{amount}\s*(?:in|of|worth\s+of)\s+gift\s*cards?\b".format(amount=_AMOUNT)),
    ("wire_money", r"\bwire\s+(?:me\s+|us\s+)?(?:the\s+)?(?:money|payment|funds|amount)\b"),
    ("make_transfer", r"\b(?:make|do|initiate|arrange)\s+(?:a\s+|the\s+)?(?:wire|bank)\s+transfer\b"),
    ("ransom", r"\bransom\b"),
    ("settle_with_amount", r"settle\s+this\s+with\s+{amount}".format(amount=_AMOUNT)),
])
PAYMENT_PATTERNS = [d["pattern"] for d in _PAYMENT_DEFS]   # kept for backward compatibility

_COERCION_DEFS = _defs("coer", [
    ("or_i_will", r"\bor\s+(?:i\s+will|i'll|i\s+am\s+going\s+to|im\s+going\s+to|they\s+go)\b"),
    ("or_else", r"\bor\s+else\b"),
    ("within_n", r"within\s+\d+\s*(?:hours?|days?|minutes?)"),
    ("you_have_n", r"you\s+have\s+\d+\s*(?:hours?|days?|minutes?)"),
    ("you_have_until", r"you\s+have\s+until\s+\w+"),
    ("next_n", r"(?:next|coming)\s+\d+\s*(?:hours?|days?)"),
    ("act_now", r"\bact\s+now\b"),
    ("final_warning", r"\bfinal\s+(?:warning|notice)\b"),
    ("no_more_warnings", r"\bno\s+(?:more|further)\s+warnings?\b"),
    ("last_chance", r"\blast\s+chance\b"),
    ("time_running_out", r"time\s+is\s+running\s+out"),
    ("dont_tell", r"don'?t\s+(?:try\s+to\s+)?(?:tell|contact)\s+(?:anyone|the\s+police)"),
    ("keep_quiet", r"keep\s+this\s+(?:between\s+us|quiet|private)"),
    ("no_negotiation", r"\bno\s+negotiations?\b"),
])
# Plain deadlines are NOT coercion on their own ("wire $3,000 within 7 days to renew the contract"). They only
# count alongside a genuine threat: a strong coercion pattern or a distribution threat (see analyze()).
_WEAK_COERCION_IDS = {"coer_within_n", "coer_you_have_n", "coer_you_have_until", "coer_next_n"}
COERCION_PATTERNS = [d["pattern"] for d in _COERCION_DEFS]   # kept for backward compatibility

# Payment demands WITHOUT an explicit amount ("if you do not pay me ..."). These never establish a payment
# demand on their own; they only support the REVIEW tier (possession + framed distribution threat).
_PAY_NOAMOUNT_DEFS = _defs("pay", [
    ("pay_me", r"\b(?:pay|paying)\s+(?:me|us)\b"),
    ("unless_you_pay", r"\b(?:unless\s+you\s+pay|if\s+you\s+(?:do\s+not|don'?t|fail\s+to|refuse\s+to|won'?t)\s+pay)\b"),
])

# Distribution patterns that read the same as an ORDINARY instruction ("send them to all your contacts if you
# like") only count as a THREAT when the clause is threat-framed (I will / going to / will be sent / otherwise ...).
# Patterns that are inherently threatening (expose you, ruin your life, your boss will see ...) need no framing.
_DIST_NEEDS_FRAMING = {
    "dist_send_to_contacts", "dist_send_to_people", "dist_forward_to_everyone", "dist_share_with",
    "dist_post_online", "dist_release_media", "dist_release_publicly", "dist_make_public",
    "dist_everyone_you_know", "dist_all_your_contacts", "dist_friends_family_list",
}
_THREAT_CUE_RE = re.compile(
    r"\b(?:i|we|they|he|she)\s*(?:will|'ll|shall|gonna|would|could|can|may|might|must|have\s+to|"
    r"(?:am|are|is)\s+going\s+to|'m\s+going\s+to|'re\s+going\s+to)\b"
    r"|\b(?:will|shall|going\s+to)\s+be\b|\bgo(?:es)?\s+(?:out\s+)?to\b"
    r"|\bgets?\s+(?:sent|posted|shared|released|forwarded|published|leaked)\b"
    r"|\b(?:otherwise|unless)\b|\bor\s+(?:else|they|it|this|everyone|all|your|the|these|those)\b", re.I)
_THREAT_SUFFIX_RE = re.compile(r"\s*(?:will|'ll|shall|gonna|(?:are|is)\s+going\s+to)\b", re.I)
_PREFIX_WINDOW = 160

# Possession claims that are generic ("I have your photos") are weak: with no payment+distribution threat
# around them they must not be enough on their own (a photographer chasing a balance, a print shop ...).
_WEAK_POSSESSION_IDS = {"poss_have_media", "poss_video_of_you"}
_SENSITIVE_ADJ_RE = re.compile(
    r"\b(?:private|personal|intimate|compromising|explicit|embarrassing|nude|naked|confidential|sensitive)\b", re.I)

# --- Input limits and normalisation -------------------------------------------------------------------
# Bounded work per message: very long bodies are scanned as head + tail (a threat is usually at the start or end;
# padding the middle cannot push it out of view). The result carries truncated=True when this happened.
MAX_SCAN_CHARS = 100000
_HEAD_CHARS, _TAIL_CHARS = 60000, 40000
_TAG_RE = re.compile(r"<[^<>]{0,300}>")
_ZERO_WIDTH_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]")
_CONTRACTION_RE = re.compile(r"(?<=\w)[\u2019\u02bc](?=\w)")
_HSPACE_RE = re.compile(r"[ \t\f\v\r]+")
_EVIDENCE_STRIP_RE = re.compile(r"[`\x00-\x1f\x7f]+")


def _prepare(text):
    """Coerce to str, bound the size, strip HTML tags/entities, NFKC-normalise, drop zero-width characters,
    fold contraction apostrophes and collapse horizontal whitespace. Returns (text, truncated)."""
    if text is None:
        text = ""
    elif isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    elif not isinstance(text, str):
        text = str(text)
    truncated = len(text) > MAX_SCAN_CHARS
    if truncated:
        text = text[:_HEAD_CHARS] + "\n" + text[-_TAIL_CHARS:]
    if "<" in text:
        text = _TAG_RE.sub(" ", text)
    if "&" in text:
        text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH_RE.sub("", text)
    text = _CONTRACTION_RE.sub("'", text)
    return _HSPACE_RE.sub(" ", text), truncated


def _clean_phrase(phrase):
    """Evidence phrases are shown in markdown code spans and tables: strip backticks and control characters."""
    return re.sub(r"\s+", " ", _EVIDENCE_STRIP_RE.sub(" ", phrase)).strip()[:200]


def _threat_framed(text, start, end):
    s = max(text.rfind(".", 0, start), text.rfind("?", 0, start), text.rfind("!", 0, start), text.rfind("\n", 0, start))
    prefix = text[max(s + 1, start - _PREFIX_WINDOW):end]   # clause so far, including the match ("or everyone ...")
    return bool(_THREAT_CUE_RE.search(prefix) or _THREAT_SUFFIX_RE.match(text[end:end + 40]))


def _framed_distribution(text, hits):
    """Drop instruction-like distribution hits that are not threat-framed; keep inherently threatening ones."""
    out = []
    for h in hits:
        ids = [i for i in h[4] if i not in _DIST_NEEDS_FRAMING or _threat_framed(text, h[1], h[2])]
        if ids:
            out.append((h[0], h[1], h[2], h[3], ids))
    return out


def _strong_possession(possession):
    for h in possession:
        if all(i in _WEAK_POSSESSION_IDS for i in h[5]) and not _SENSITIVE_ADJ_RE.search(h[0]):
            continue
        return True
    return False


_CATEGORY_DEFS = {
    "distribution_threat": _DISTRIBUTION_DEFS,
    "payment_demand": _PAYMENT_DEFS,
    "coercive_pressure": _COERCION_DEFS,
}

# --- Quote / attribution context -------------------------------------------------------------------------
# Spans of text presented as someone else's words (a security advisory quoting a sample scam, a victim
# forwarding a threat). Evidence matches that fall ENTIRELY inside one span are "quoted". Rules:
#   * double / curly-double quotes: the text between the quotes (up to 500 chars);
#   * single / curly-single quotes with at least three words (a contraction never qualifies);
#   * a reporting lead ("reads:", "says", "for example") attributes ONLY the single sentence that follows
#     it (to the next sentence end, end of line, or 300 chars). It no longer swallows the rest of the line,
#     so a live threat that merely follows "...it reads: it is real." stays a direct threat. Multi-sentence
#     unquoted examples are therefore NOT downgraded; put them in quotation marks (documented trade-off:
#     the failure direction is a reviewable detection, not a missed threat).
_DOUBLE_QUOTE_SPAN_RE = re.compile(r'["\u201c]([^"\u201c\u201d]{10,500})["\u201d]')
_SINGLE_QUOTE_SPAN_RE = re.compile(r"'([^']{10,500})'|\u2018([^\u2018\u2019]{10,500})\u2019")
_REPORTING_LEAD_RE = re.compile(
    r"(?:reads?|says?|writes?|states?|looks\s+like\s+this|an?\s+example|for\s+example)\s*[:\-]?\s*['\u2018\"\u201c]?\s*", re.I)
_SENTENCE_END_RE = re.compile(r"[.?!](?=\s|$)")
_LEAD_SPAN_MAX = 300


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
        start = m.end()
        nl = text.find("\n", start)
        line_end = len(text) if nl < 0 else nl
        seg = text[start:min(line_end, start + _LEAD_SPAN_MAX)]
        s_end = _SENTENCE_END_RE.search(seg)
        end = start + (s_end.end() if s_end else len(seg))
        if end - start >= 10:
            spans.append((start, end))
    return spans


def _inside_any(span, containers):
    s, e = span
    return any(cs <= s and e <= ce for cs, ce in containers)


def _scan(text, defs):
    """Run defs over text. Returns list of dicts {phrase, start, end, quoted, ids, imagery}. The same phrase is
    kept once PER quoted-state (a quoted copy never hides an identical direct threat); ids lists every pattern
    that matched that phrase."""
    out, idx = [], {}
    quote_spans = _quoted_spans(text)
    for d in defs:
        for m in d["regex"].finditer(text):
            phrase = m.group(0).strip()
            if not phrase:
                continue
            quoted = _inside_any((m.start(), m.end()), quote_spans)
            key = (phrase.lower(), quoted)
            if key in idx:
                if d["id"] not in out[idx[key]]["ids"]:
                    out[idx[key]]["ids"].append(d["id"])
                continue
            idx[key] = len(out)
            out.append({"phrase": phrase, "start": m.start(), "end": m.end(), "quoted": quoted,
                        "ids": [d["id"]], "imagery": d.get("imagery")})
    return out


def _findings(text, defs):
    """Returns list of (phrase, start, end, is_quoted, ids)."""
    return [(h["phrase"], h["start"], h["end"], h["quoted"], h["ids"]) for h in _scan(text, defs)]


def _possession_findings(text):
    """Returns list of (phrase, start, end, is_quoted, is_imagery, ids)."""
    return [(h["phrase"], h["start"], h["end"], h["quoted"], h["imagery"], h["ids"]) for h in _scan(text, _POSSESSION_DEFS)]


def _unique(seq):
    seen, out = set(), []
    for x in seq:
        if x.lower() not in seen:
            seen.add(x.lower())
            out.append(x)
    return out


_NO_FINDING = ("No combination of possession claim, a contextual payment demand, and a "
               "distribution/coercion threat was found.")


def _empty_result(truncated=False, error=""):
    return {"detected": False, "category": "none", "severity": "none", "confidence": 0.0, "strength": 0.0,
            "evidence": {}, "pattern_ids": {}, "categories_hit": [], "explanation": _NO_FINDING,
            "recommended_action": "", "needs_review": False, "quoted_context": False,
            "review_reason": "", "truncated": truncated, "error": error}


def analyze(text):
    """Scan message text for the sextortion/extortion threat pattern. Never raises.

    Returns a dict:
      detected (bool), category, severity ("critical"|"high"|"medium"|"low"|"none"),
      confidence (0..1 rule-strength, NOT the ML probability), strength (0..1,
      the value fed into risk.score), evidence (per-category sanitized phrases),
      pattern_ids (per-category IDs of every pattern that matched; reported only when detected),
      explanation (str), recommended_action (str), needs_review (bool),
      quoted_context (bool),
      review_reason ("quoted_context" | "no_explicit_payment_demand" | ""),
      truncated (bool: input exceeded MAX_SCAN_CHARS and was scanned as head + tail),
      error (str: exception class name if the detector failed internally, else "" - a failed scan is
      reported as an error, never as a clean result the caller could mistake for "safe").

    Tiers: CORE = possession + payment demand (+ a threat-framed distribution threat, or - without a
    distribution threat - strong coercion and a non-generic possession claim). REVIEW = non-generic
    possession + a threat-framed distribution threat + (strong coercion or a payment demand without an
    amount), no explicit amount: always needs_review, medium severity, never auto-escalated.
    """
    try:
        return _analyze(text)
    except Exception as exc:  # fail safe: a detector fault must never interrupt the analysis pipeline
        return _empty_result(error=type(exc).__name__)


def _analyze(text):
    text, truncated = _prepare(text)

    possession = _possession_findings(text)
    found = {"possession_claim": possession}
    for cat, defs in _CATEGORY_DEFS.items():
        found[cat] = _findings(text, defs)

    found["distribution_threat"] = _framed_distribution(text, found["distribution_threat"])

    # Independence: when the payment finding exists ONLY because of "<amount>, or I will ...", that text is the
    # same evidence as the "or I will" coercion hit - do not count it as two categories.
    pay, coer = found["payment_demand"], found["coercive_pressure"]
    if pay and all(set(h[4]) <= {"pay_amount_or_threat"} for h in pay):
        spans = [(h[1], h[2]) for h in pay]
        coer = [h for h in coer if not any(h[1] < e and s < h[2] for s, e in spans)]
    # A plain deadline is not coercion: weak (deadline-only) hits need a distribution threat beside them.
    if not found["distribution_threat"] and all(set(h[4]) <= _WEAK_COERCION_IDS for h in coer):
        coer = []
    found["coercive_pressure"] = coer

    has_possession = bool(possession)
    has_strong_possession = _strong_possession(possession)
    has_distribution = bool(found["distribution_threat"])
    has_payment = bool(found["payment_demand"])
    has_coercion = bool(found["coercive_pressure"])

    core_hit = has_payment and ((has_possession and has_distribution) or (has_strong_possession and has_coercion))
    review_hit = False
    if not core_hit and has_strong_possession and has_distribution:
        noamount = _findings(text, _PAY_NOAMOUNT_DEFS)
        if has_coercion or noamount:
            review_hit = True
            if noamount and not has_payment:
                found["payment_demand"] = noamount
                has_payment = True
    detected = core_hit or review_hit

    ids_by_cat = {"possession_claim": [i for h in possession for i in h[5]]}
    for cat in _CATEGORY_DEFS:
        ids_by_cat[cat] = [i for h in found[cat] for i in h[4]]
    categories_hit = [cat for cat, hits in found.items() if hits]
    n_categories = len(categories_hit)

    # A finding is "quoted" only if EVERY possession hit, EVERY payment hit and every hit of whichever of
    # distribution/coercion fired are inside a quoted/attributed span - i.e. the whole threat is reproduced
    # as someone else's words. One direct (unquoted) hit anywhere keeps it a live threat.
    quoted_context = False
    possession_imagery = False
    if detected:
        possession_imagery = any(h[4] for h in possession)
        possession_all_quoted = all(h[3] for h in possession)
        payment_all_quoted = all(h[3] for h in found["payment_demand"]) if found["payment_demand"] else True
        closing_hits = found["distribution_threat"] if has_distribution else found["coercive_pressure"]
        closing_all_quoted = all(h[3] for h in closing_hits) if closing_hits else False
        quoted_context = possession_all_quoted and payment_all_quoted and closing_all_quoted

    category = "none"
    if detected:
        category = "suspected_sextortion" if possession_imagery else "suspected_extortion"

    review_reason = ""
    if not detected:
        severity, confidence, strength = "none", 0.0, 0.0
    elif review_hit:
        severity, confidence, strength = "medium", 0.5, 0.5
        review_reason = "quoted_context" if quoted_context else "no_explicit_payment_demand"
    elif n_categories >= 4:
        severity, confidence, strength = "critical", 0.95, 1.0
    elif n_categories == 3:
        severity, confidence, strength = "high", 0.85, 0.9
    else:  # defensive; core_hit's requirements make this unreachable in practice
        severity, confidence, strength = "medium", 0.6, 0.6

    needs_review = detected and (quoted_context or review_hit)
    if needs_review:
        # The threat text is quoted/attributed, or there is no explicit payment demand: do not silently drop
        # the finding, but do not assert it with full confidence either.
        confidence = min(confidence, 0.5)
        strength = min(strength, 0.5)
        if not review_reason:
            review_reason = "quoted_context"

    evidence = {cat: _unique([_clean_phrase(h[0]) for h in found[cat]]) for cat in categories_hit} if detected else {}
    pattern_ids = {cat: _unique(ids_by_cat[cat]) for cat in categories_hit} if detected else {}

    if detected:
        explanation = (
            "The message combines a claim to possess compromising material, {}, and {} - the "
            "structural pattern of a sextortion / extortion attempt. This finding describes what the "
            "TEXT threatens; it does not and cannot confirm that the sender actually holds any "
            "material.".format(
                "a contextual monetary demand" if core_hit else "a payment/compliance demand with no explicit amount",
                "an explicit threat to distribute it" if has_distribution else "coercive pressure to pay quickly")
        )
        if review_reason == "quoted_context":
            explanation += (
                " The matched threat language appears quoted or attributed "
                "(e.g. inside quotation marks, or introduced as an example) "
                "rather than stated directly by this message, so this has "
                "been routed to human review instead of asserted outright."
            )
        elif review_hit:
            explanation += (
                " No explicit amount or payment method was matched, so this has been routed "
                "to human review instead of asserted outright."
            )
        recommended_action = (
            "Do not pay or reply. Preserve the original message and headers. "
            "Do not delete the account or device. Report to the platform the "
            "threat references and to local law enforcement / a cybercrime "
            "reporting authority. Treat any purported evidence as unverified."
        )
        if review_reason == "quoted_context":
            recommended_action = (
                "Route to an analyst for manual review before acting: the "
                "message matches the extortion/sextortion pattern, but the "
                "matched language appears quoted or attributed rather than "
                "stated directly, so automated escalation alone is not "
                "conclusive. Do not close this out as legitimate without a "
                "human check."
            )
        elif review_hit:
            recommended_action = (
                "Route to an analyst for manual review before acting: the message pairs a claim to "
                "possess private material with a threat to distribute it, but no explicit payment "
                "demand was matched. Do not reply or engage, preserve the message and headers, and "
                "do not close this out as legitimate without a human check."
            )
    else:
        explanation = _NO_FINDING
        recommended_action = ""

    return {
        "detected": detected,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "strength": strength,
        "evidence": evidence,
        "pattern_ids": pattern_ids,
        "categories_hit": categories_hit,
        "explanation": explanation,
        "recommended_action": recommended_action,
        "needs_review": needs_review,
        "quoted_context": quoted_context,
        "review_reason": review_reason,
        "truncated": truncated,
        "error": "",
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
