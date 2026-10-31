"""The analysis pipeline - one call runs every module over one email.

    raw .eml bytes
        -> email_parser   (headers, Received chain, body)
        -> classifier     (ML phishing probability + explanation)
        -> header_analysis(SPF/DKIM/DMARC, spoof anomalies, BEC)
        -> ioc_extract    (URLs, look-alike domains, wallets)
        -> geolocate      (origin IP -> country, infrastructure)
        -> risk           (weighted fusion -> score + verdict)

Local threat memory is used to remember URLs, IPs and domains seen
during previous analyses.

Keeping this separate from app.py means the whole engine is testable
from the command line without Streamlit.
"""

import os

import config as C
import extortion_detection
import geolocate
import header_analysis
import ioc_extract
import community_intel
import risk

from classifier import load_or_train, predict
from email_parser import parse_eml
from tracker import (remember_indicator, lookup_indicator, stored_reputation,
                     refresh_stale_url_scores)

try:                                    # optional: offline origin-confidence engine
    import origin_intel
except Exception:
    origin_intel = None


def analyze_email(raw, name="uploaded", pipe=None):
    """Run every module over one raw email. Returns one result dict."""

    pipe = pipe or load_or_train()

    # ------------------------------------------------------------------
    # Core email analysis
    # ------------------------------------------------------------------
    parsed = parse_eml(raw)
    ml_prob, ml_label, top_terms = predict(pipe, parsed["full_text"])
    headers = header_analysis.analyze(parsed)
    iocs = ioc_extract.extract(parsed)
    # A detector fault or malformed output is an explicit ERROR result (-> manual review), never a clean one.
    try:
        extortion = extortion_detection.analyze(parsed.get("full_text", ""))
    except Exception as exc:
        extortion = extortion_detection.failure_result(type(exc).__name__)
    extortion = extortion_detection.checked(extortion)   # strict schema check; invalid -> InvalidDetectorOutput

    # ------------------------------------------------------------------
    # Local threat-intelligence memory
    # ------------------------------------------------------------------
    # A malformed URL score contributes 0 and is RECORDED (risk.score flags it and holds the verdict at Medium);
    # it must neither crash the analysis nor read as "no malicious links".
    memory_url_risk, _url_problem = risk.inspect_signal(iocs.get("url_score", 0.0))
    upstream_malformed = [{"input": "suspicious_url", "problem": _url_problem}] if _url_problem else []
    recorded = []   # (type, value) observations THIS analysis actually wrote to threat memory

    def _record(indicator, kind, reputation, category, source, score_version=None):
        if remember_indicator(indicator, kind, reputation, category, source, score_version):
            recorded.append((kind, str(indicator).strip().lower()))

    # Locally cached URL scores from an older version of the URL heuristics are recomputed once, so an
    # obsolete result (e.g. a false positive since fixed) is not reused as evidence.
    try:
        refresh_stale_url_scores(lambda u: ioc_extract._judge_url(u)["risk"], ioc_extract.URL_SCORE_VERSION)
    except Exception:
        pass

    # Remember URLs and reuse previous URL reputation.
    try:
        url_entries = list(iocs.get("urls", []))
    except Exception:
        url_entries = []
    for entry_index, url_info in enumerate(url_entries):
        # Each entry is processed independently: one malformed entry must not stop the rest, and threat memory
        # must never break email analysis.
        try:
            if not isinstance(url_info, dict):
                continue

            # An entry without a usable URL is skipped silently: there is nothing to score or remember, and its
            # "risk" must not raise irrelevant malformed-input warnings.
            indicator = url_info.get("url", "")
            if not isinstance(indicator, str) or not indicator.strip():
                continue

            # A URL is present, so its risk must be a valid 0..1 number. An ABSENT "risk" key is passed on as None
            # and is recorded as "missing" - it is never defaulted to a clean 0.0.
            current_risk, entry_problem = risk.inspect_signal(url_info.get("risk"))
            if entry_problem:
                # A malformed per-URL risk is RECORDED for review (it contributes nothing to the score) and is never
                # written to threat memory (storing 0.0 would plant a false "clean" reputation). Its previous
                # stored reputation, if any, is still consulted below.
                upstream_malformed.append({"input": "suspicious_url_entry[{}]".format(entry_index),
                                           "problem": entry_problem})

            # Save this URL in local memory (valid scores only).
            if not entry_problem:
                _record(indicator, "url", current_risk, "observed", "local_analysis",
                        ioc_extract.URL_SCORE_VERSION)

            # Check whether this URL was previously seen.
            previous = lookup_indicator(indicator, "url")

            if previous:
                # Obsolete local heuristic scores (older score_version) are ignored; feed
                # intelligence and current-version scores are kept.
                previous_reputation = stored_reputation(
                    previous, ioc_extract.URL_SCORE_VERSION
                )

                # Previous evidence can increase risk,
                # but never reduce current evidence.
                if previous_reputation is not None:
                    memory_url_risk = max(
                        memory_url_risk,
                        previous_reputation
                    )
        except Exception:
            continue

    # ------------------------------------------------------------------
    # Remember IPs and domains
    # ------------------------------------------------------------------
    try:
        for ip in iocs.get("ips", []):
            indicator = str(ip).strip()

            if indicator:
                _record(indicator, "ip", 0.5, "observed", "local_analysis")

        for domain in iocs.get("domains", []):
            indicator = str(domain).strip()

            if indicator:
                _record(indicator, "domain", 0.5, "observed", "local_analysis")

    except Exception:
        # Threat memory must never break email analysis.
        pass

    # ------------------------------------------------------------------
    # Geographic / infrastructure analysis
    # ------------------------------------------------------------------
    geo = geolocate.trace(parsed)

    # Origin confidence is computed ONCE here, with the raw headers, and stored on the result. The
    # Origin panel and the AI assessment both read this object, so they cannot report different numbers
    # for the same metric. (Never affects the score.)
    origin_assessment = None
    if origin_intel is not None:
        try:
            origin_assessment = origin_intel.assess_origin(parsed, geo, raw=raw)
        except Exception:
            origin_assessment = None

    # ------------------------------------------------------------------
    # Final weighted risk score
    # ------------------------------------------------------------------
    verdict = risk.score(
        ml_prob=ml_prob,
        auth_fail=headers["auth_fail_score"],
        header_anomaly=headers["anomaly_score"],
        url_risk=memory_url_risk,
        origin_risk=geo["origin_risk"],
        bec_score=headers["bec"]["score"],
        # Defence in depth (checked() already guarantees this): a non-detected result can never feed the override.
        extortion_score=extortion.get("strength", 0.0) if extortion.get("detected") is True else 0.0,
        extortion_confidence=extortion.get("confidence", 0.0) if extortion.get("detected") is True else 0.0,
        extortion_review=bool(extortion.get("error") or (extortion.get("detected") and extortion.get("needs_review"))),
        upstream_malformed=upstream_malformed,
    )

    # Community intelligence (feature-flagged, OFF by default): contextual only, looked up AFTER scoring, never affects it.
    community = community_intel.lookup(parsed, iocs, geo)

    # ------------------------------------------------------------------
    # Unified result object
    # ------------------------------------------------------------------
    result = {
        "name": name,
        "parsed": parsed,
        "ml": {
            "prob": ml_prob,
            "label": ml_label,
            "top_terms": top_terms,
        },
        "headers": headers,
        "extortion": extortion,
        "iocs": iocs,
        "geo": geo,
        "origin_intel": origin_assessment,
        "recorded_indicators": recorded,
        "score": verdict["score"],
        "level": verdict["level"],
        "color": verdict["color"],
        "verdict": verdict,
    }
    if community is not None:               # key exists only when the feature is enabled
        result["community_intel"] = community
    return result


def list_samples():
    """Sample .eml files shipped in samples/, phishing first for the demo."""
    if not os.path.isdir(C.SAMPLE_DIR):
        return []

    files = sorted(
        f for f in os.listdir(C.SAMPLE_DIR)
        if f.endswith(".eml")
    )

    return [
        os.path.join(C.SAMPLE_DIR, f)
        for f in files
    ]


def analyze_all_samples(pipe=None):
    """Analyse every shipped sample - powers the case table and correlation."""

    pipe = pipe or load_or_train()

    results = []

    for path in list_samples():
        try:
            with open(path, "rb") as fh:
                results.append(
                    analyze_email(
                        fh.read(),
                        os.path.basename(path),
                        pipe
                    )
                )

        except Exception as exc:
            # Never kill the whole run because of one sample.
            results.append({
                "name": os.path.basename(path),
                "error": str(exc)
            })

    return results


if __name__ == "__main__":
    print(
        "{:28} {:>6}  {:9} {:5} {:5} {:5}  {}".format(
            "sample",
            "score",
            "verdict",
            "spf",
            "dkim",
            "dmarc",
            "origin"
        )
    )

    print("-" * 100)

    for result in analyze_all_samples():

        if "error" in result:
            print(
                "{:28} ERROR {}".format(
                    result["name"],
                    result["error"]
                )
            )
            continue

        origin = result["geo"]["origin"]

        print(
            "{:28} {:6.1f}  {:9} {:5} {:5} {:5}  {} ({}, {})".format(
                result["name"],
                result["score"],
                result["level"],
                result["headers"]["spf"],
                result["headers"]["dkim"],
                result["headers"]["dmarc"],
                origin.get("ip", "-"),
                origin.get("country", "?"),
                origin.get("infra_label", "?")
            )
        )