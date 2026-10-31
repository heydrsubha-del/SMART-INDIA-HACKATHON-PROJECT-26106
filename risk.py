"""Module 5 (part 1): fuse every signal into one explainable verdict.

Each detector returns a 0..1 strength. We multiply by the weight from
config.WEIGHTS and sum, so the final 0..100 score is a plain weighted average -
auditable, and every point is traceable to a named reason. No magic.

Standalone:  python risk.py
"""
import config as C


def level_for(score):
    """(name, colour) for a 0..100 score."""
    for threshold, name, colour in C.RISK_LEVELS:
        if score >= threshold:
            return name, colour
    return C.RISK_LEVELS[-1][1], C.RISK_LEVELS[-1][2]


_LEVEL_RANK = {name: i for i, (_, name, _) in enumerate(C.RISK_LEVELS)}  # 0 = most severe


def _level_rank(name):
    return _LEVEL_RANK.get(name, len(C.RISK_LEVELS) - 1)


_RANGE_TOLERANCE = 1e-9   # float rounding at the 0 / 1 edges is not a malformed input


def _inspect(value):
    """(validated 0..1 float, problem). problem is "" for a valid input, else "missing" / "not numeric" /
    "not finite" / "out of range". POLICY: a malformed input (including an out-of-range one such as 1.7 or -0.5)
    contributes ZERO to the weighted score - it is never bounded into a value that still scores - and the problem is
    RECORDED by score(), which holds the verdict at the review floor, because a broken security signal is not
    evidence that a message is safe. Only float rounding within 1e-9 of 0 / 1 is tolerated and snapped to the bound."""
    if value is None:
        return 0.0, "missing"
    if isinstance(value, (bool, str, bytes, bytearray)):
        return 0.0, "not numeric"
    try:
        v = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0, "not numeric"
    if v != v or v in (float("inf"), float("-inf")):
        return 0.0, "not finite"
    if v < -_RANGE_TOLERANCE or v > 1.0 + _RANGE_TOLERANCE:
        return 0.0, "out of range"
    return max(0.0, min(1.0, v)), ""


inspect_signal = _inspect   # public name: upstream callers validate a raw signal with the same rules as score()


def _unit(value):
    """Validated 0..1 float (malformed, including out of range -> 0.0). Use _inspect() to record the problem."""
    return _inspect(value)[0]


def score(ml_prob, auth_fail, header_anomaly, url_risk, origin_risk, bec_score,
          extortion_score=0.0, extortion_confidence=0.0, extortion_review=False,
          upstream_malformed=None):
    """Combine the seven signals. Returns a dict with score, level and reasons.

    extortion_score / extortion_confidence come from extortion_detection.analyze()
    (strength / confidence). They are kept separate on purpose: extortion_score is
    the 0..1 strength fed into the weighted average like any other signal, while
    extortion_confidence is ONLY used for the override below. A weighted average
    can be dragged down by other low signals (clean auth, no links, moderate ML
    score) exactly the way the reported false negative was - so a confident
    extortion finding also floors the verdict directly, independent of the sum.
    """
    raw_inputs = {
        "ml_phish": ml_prob, "auth_fail": auth_fail, "header_anomaly": header_anomaly,
        "suspicious_url": url_risk, "origin_risk": origin_risk, "bec_pattern": bec_score,
        "extortion_pattern": extortion_score, "extortion_confidence": extortion_confidence,
    }
    inspected = {k: _inspect(v) for k, v in raw_inputs.items()}
    malformed = [{"input": k, "problem": p} for k, (_, p) in inspected.items() if p]
    # Inputs a caller already found invalid (and zeroed) before calling score(), e.g. a malformed URL score.
    for _m in (upstream_malformed or []):
        if isinstance(_m, dict) and _m.get("input") and not any(x["input"] == _m["input"] for x in malformed):
            malformed.append({"input": str(_m["input"]), "problem": str(_m.get("problem") or "invalid")})
    signals = {k: inspected[k][0] for k in raw_inputs if k != "extortion_confidence"}
    labels = {
        "ml_phish": "ML phishing-language model",
        "auth_fail": "SPF / DKIM / DMARC authentication",
        "header_anomaly": "Header & identity anomalies",
        "suspicious_url": "Malicious link indicators",
        "origin_risk": "Origin infrastructure reputation",
        "bec_pattern": "Business Email Compromise pattern",
        "extortion_pattern": "Sextortion / extortion pattern (deterministic)",
    }

    contributions, total = [], 0.0
    for key, strength in signals.items():
        weight = C.WEIGHTS[key]
        points = strength * weight
        total += points
        contributions.append({
            "key": key, "label": labels[key], "strength": strength,
            "weight": weight, "points": points,
        })

    total = max(0.0, min(100.0, total))
    name, colour = level_for(total)

    # --- Behavioral-finding override ---------------------------------------
    # A high-confidence extortion finding cannot be out-voted by a low ML
    # score, clean auth, or the absence of a URL. It can only ever RAISE the
    # verdict, never lower one a stronger weighted score already produced.
    extortion_confidence = inspected["extortion_confidence"][0]
    override_applied = False
    floor = getattr(C, "EXTORTION_OVERRIDE_LEVEL", "High")
    min_conf = getattr(C, "EXTORTION_OVERRIDE_MIN_CONFIDENCE", 0.80)
    if extortion_confidence >= min_conf and _level_rank(floor) < _level_rank(name):
        name = floor
        colour = next((c for t, n, c in C.RISK_LEVELS if n == floor), colour)
        override_applied = True

    # A detected-but-uncertain finding (extortion_review) floors the verdict at Medium so it is never shown as
    # Low next to a "manual review required" action. Like the override, it can only RAISE the verdict.
    # The same floor applies when ANY risk input was malformed: a broken signal contributes 0 to the weighted
    # score (which is otherwise left exactly as computed), but that must not read as safe, so the verdict is held at Medium.
    review_applied = False
    review_floor = getattr(C, "EXTORTION_REVIEW_LEVEL", "Medium")
    if (extortion_review or malformed) and not override_applied and _level_rank(review_floor) < _level_rank(name):
        name = review_floor
        colour = next((c for t, n, c in C.RISK_LEVELS if n == review_floor), colour)
        review_applied = True

    contributions.sort(key=lambda c: c["points"], reverse=True)

    reasons = ["{}: {:.0f}/{} points ({:.0%} strength)".format(
        c["label"], c["points"], c["weight"], c["strength"])
        for c in contributions if c["points"] >= 0.5]
    if override_applied:
        reasons.insert(0, "Behavioral override: a high-confidence extortion/sextortion "
                          "finding ({:.0%} rule confidence) raised the verdict to {} "
                          "regardless of the weighted score.".format(extortion_confidence, floor))

    if review_applied and extortion_review:
        reasons.insert(0, "Review floor: the extortion assessment is uncertain or unavailable (quoted threat, "
                          "no explicit payment demand, or detector failure); verdict raised to {} pending "
                          "analyst review.".format(review_floor))
    if malformed:
        reasons.insert(0, "Input validation: malformed risk input(s) {} were treated as 0, which is NOT evidence "
                          "that the message is safe; {}.".format(
                              ", ".join("{} ({})".format(m["input"], m["problem"]) for m in malformed),
                              "verdict raised to {} pending analyst review".format(review_floor) if review_applied
                              else "analyst review required"))

    return {
        "score": total,
        "level": name,
        "color": colour,
        "signals": signals,
        "contributions": contributions,
        "reasons": reasons or ["No detector fired above the reporting threshold."],
        "top_driver": contributions[0]["label"] if contributions else "",
        "override_applied": override_applied,
        "review_floor_applied": review_applied,
        "malformed_inputs": malformed,
        "input_validation_failed": bool(malformed),
    }


if __name__ == "__main__":
    cases = [
        ("credential phish", dict(ml_prob=0.97, auth_fail=1.0, header_anomaly=1.0,
                                 url_risk=0.9, origin_risk=1.0, bec_score=0.0)),
        ("BEC (auth passes)", dict(ml_prob=0.88, auth_fail=0.0, header_anomaly=0.68,
                                   url_risk=0.0, origin_risk=0.1, bec_score=0.83)),
        ("legit newsletter", dict(ml_prob=0.04, auth_fail=0.0, header_anomaly=0.0,
                                  url_risk=0.0, origin_risk=0.1, bec_score=0.0)),
    ]
    print("total weight = {} (should be 100)\n".format(sum(C.WEIGHTS.values())))
    for name, kwargs in cases:
        result = score(**kwargs)
        print("{:20} {:5.1f}  {:8}  driver: {}".format(
            name, result["score"], result["level"], result["top_driver"]))
