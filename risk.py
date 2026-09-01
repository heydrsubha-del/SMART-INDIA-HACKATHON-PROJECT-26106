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


def score(ml_prob, auth_fail, header_anomaly, url_risk, origin_risk, bec_score):
    """Combine the six signals. Returns a dict with score, level and reasons."""
    signals = {
        "ml_phish": max(0.0, min(1.0, float(ml_prob or 0.0))),
        "auth_fail": max(0.0, min(1.0, float(auth_fail or 0.0))),
        "header_anomaly": max(0.0, min(1.0, float(header_anomaly or 0.0))),
        "suspicious_url": max(0.0, min(1.0, float(url_risk or 0.0))),
        "origin_risk": max(0.0, min(1.0, float(origin_risk or 0.0))),
        "bec_pattern": max(0.0, min(1.0, float(bec_score or 0.0))),
    }
    labels = {
        "ml_phish": "ML phishing-language model",
        "auth_fail": "SPF / DKIM / DMARC authentication",
        "header_anomaly": "Header & identity anomalies",
        "suspicious_url": "Malicious link indicators",
        "origin_risk": "Origin infrastructure reputation",
        "bec_pattern": "Business Email Compromise pattern",
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
    contributions.sort(key=lambda c: c["points"], reverse=True)

    reasons = ["{}: {:.0f}/{} points ({:.0%} strength)".format(
        c["label"], c["points"], c["weight"], c["strength"])
        for c in contributions if c["points"] >= 0.5]

    return {
        "score": total,
        "level": name,
        "color": colour,
        "signals": signals,
        "contributions": contributions,
        "reasons": reasons or ["No detector fired above the reporting threshold."],
        "top_driver": contributions[0]["label"] if contributions else "",
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
