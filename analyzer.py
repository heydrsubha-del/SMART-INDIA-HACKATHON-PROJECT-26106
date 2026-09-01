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
import geolocate
import header_analysis
import ioc_extract
import risk

from classifier import load_or_train, predict
from email_parser import parse_eml
from tracker import remember_indicator, lookup_indicator


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

    # ------------------------------------------------------------------
    # Local threat-intelligence memory
    # ------------------------------------------------------------------
    memory_url_risk = float(
        iocs.get("url_score", 0.0) or 0.0
    )

    external_url_risk = 0.0
    external_url_count = 0
    local_memory_count = 0

    # Remember URLs and reuse previous URL reputation.
    try:
        for url_info in iocs.get("urls", []):
            if not isinstance(url_info, dict):
                continue

            url_info.setdefault("external_intel", False)
            url_info.setdefault("intel_source", "None")

            indicator = url_info.get("url", "")
            current_risk = float(
                url_info.get("risk", 0.0) or 0.0
            )

            if not indicator:
                continue

            url_info.setdefault("external_intel", False)
            url_info.setdefault("intel_source", "None")

            # Save this URL in local memory.
            remember_indicator(
                indicator,
                "url",
                current_risk,
                "observed",
                "local_analysis"
            )

            previous = lookup_indicator(indicator, "url")

            if previous:
                previous_reputation = float(previous[3] or 0.0)
                previous_source = (
                    previous[8]
                    if len(previous) > 8
                    else "unknown"
                )

                memory_url_risk = max(
                    memory_url_risk,
                    previous_reputation
                )

                # Record the strongest available intelligence source.
                if previous_source == "urlhaus":
                    url_info["external_intel"] = True
                    url_info["intel_source"] = "URLhaus"
                    external_url_count += 1
                    external_url_risk = max(
                        external_url_risk,
                        previous_reputation
                    )
                else:
                    url_info["external_intel"] = False
                    url_info["intel_source"] = "Local memory"
                    local_memory_count += 1
            else:
                url_info["external_intel"] = False
                url_info["intel_source"] = "None"
    except Exception:
        # Threat memory must never break email analysis.
        pass

    # ------------------------------------------------------------------
    # Geographic / infrastructure analysis
    # ------------------------------------------------------------------
    geo = geolocate.trace(parsed)

    # ------------------------------------------------------------------
    # Final weighted risk score
    # ------------------------------------------------------------------
    verdict = risk.score(
        ml_prob=ml_prob,
        auth_fail=headers["auth_fail_score"],
        header_anomaly=headers["anomaly_score"],
        url_risk=max(
            memory_url_risk,
            external_url_risk
        ),
        origin_risk=geo["origin_risk"],
        bec_score=headers["bec"]["score"],
    )

    # ------------------------------------------------------------------
    # Unified result object
    # ------------------------------------------------------------------
    return {
        "name": name,
        "parsed": parsed,
        "ml": {
            "prob": ml_prob,
            "label": ml_label,
            "top_terms": top_terms,
        },
        "headers": headers,
        "iocs": iocs,
        "intelligence": {
    "urlhaus_matches": external_url_count,
    "local_memory_matches": local_memory_count,
    "external_url_risk": external_url_risk,
},
        "geo": geo,
        "score": verdict["score"],
        "level": verdict["level"],
        "color": verdict["color"],
        "verdict": verdict,
    }


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