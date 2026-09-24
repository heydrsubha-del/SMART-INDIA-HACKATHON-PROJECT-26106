"""
network_trust.py
=================
Sender Network-Trust check for the "Origin & Route" panel.

The app's geolocate.py already classifies each hop's infrastructure
(tor / vpn / proxy / datacenter / residential, via INFRA_LABEL) — so
"is this IP a VPN?" is already answered elsewhere. What's missing is
the question a SOC analyst actually asks next: *"Is this normal for
THIS sender?"*

A VPN exit IP is unremarkable for a sender who always uses one. But a
finance manager who has emailed from the same residential ISP for six
months suddenly sending from a Tor exit node or a brand-new hosting
network, on the day they ask you to wire money, is the real signal.

This module adds that piece: a persistent per-sender network history,
and a flag when today's message breaks the pattern. It reuses the
app's existing tracker.py database connection so everything lives in
one place — no new DB file, no new config.

    from network_trust import assess_network_trust
    trust = assess_network_trust(sender_email, ip, infra_label, country)

Also kept: an optional, fully offline VPN/datacenter CIDR-range check
for use outside this app (or as a fallback when geolocate.py could not
classify a hop at all).
"""

import csv
import ipaddress
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

# Reuse the same SQLite file/connection as the rest of the app
# (threat-memory, feedback, etc.) when running inside app.py. Falls
# back to a local file so this module still works standalone / in
# tests without the rest of the project present.
try:
    from tracker import get_connection as _get_shared_connection
except ImportError:  # pragma: no cover - standalone/test usage only
    def _get_shared_connection():
        return sqlite3.connect("network_trust_standalone.sqlite3")

# Infra classes that count as "anonymizing" for the anomaly check --
# matches the tor/vpn/proxy categories app.py already checks for when
# picking the red marker on the hop map.
_ANONYMIZING_INFRA = {"tor", "vpn", "proxy"}


def _ensure_table(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sender_networks (
            sender_email TEXT NOT NULL,
            network_24   TEXT NOT NULL,   -- e.g. "203.0.113.0/24"
            infra_class  TEXT,            -- 'tor' | 'vpn' | 'proxy' | 'datacenter' | 'residential' | ...
            country      TEXT,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            hit_count    INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (sender_email, network_24)
        )
        """
    )
    conn.commit()


def _to_24(ip: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return None


def assess_network_trust(
    sender_email: str,
    ip: str,
    infra_label: str = "",
    country: str = "",
) -> dict:
    """
    Compares this message's origin against the sender's mailing history,
    records the observation, and returns a display-ready result:

        {
            "badge": "⚠️ New network",        # short -- safe to put in a metric/column
            "level": "warning",                # "ok" | "warning" | "alert"
            "is_new_sender": False,
            "is_new_network": True,
            "is_new_anonymizing_infra": False,
            "is_anonymizing": True,            # is *this message* on VPN/Tor/proxy at all
            "infra_display": "VPN",            # human label for that infra, for direct display
            "country_mismatch": False,
            "known_network_count": 3,
            "reasons": ["..."],                # full-sentence explanation, incl. VPN status
        }

    "is_anonymizing"/"infra_display" answer "is VPN/proxy/Tor masking present on this
    message at all" -- independent of whether it's new for this sender. "badge"/"level"
    answer the separate question this module exists for: whether that's a change from
    how this sender normally mails. A sender who always uses a VPN gets "is_anonymizing":
    True but level "ok", because that VPN use isn't a change in their behavior.

    A brand-new sender (nothing on file yet) is never flagged --
    there is no baseline to break yet, so we only record it.
    """
    sender_email = (sender_email or "unknown").strip().lower()
    net24 = _to_24(ip) if ip else None
    infra_class = (infra_label or "").strip().lower()
    is_anonymizing = infra_class in _ANONYMIZING_INFRA
    infra_display = (infra_label or infra_class).strip() or "Unknown"

    conn = _get_shared_connection()
    _ensure_table(conn)

    known_rows = conn.execute(
        "SELECT network_24, infra_class, country FROM sender_networks WHERE sender_email = ?",
        (sender_email,),
    ).fetchall()
    known_network_count = len(known_rows)
    known_networks = {r[0] for r in known_rows}
    known_infra_classes = {r[1] for r in known_rows if r[1]}
    known_countries = {r[2] for r in known_rows if r[2]}

    is_new_sender = known_network_count == 0
    is_new_network = bool(net24) and net24 not in known_networks
    is_new_anonymizing_infra = is_anonymizing and infra_class not in known_infra_classes
    country_mismatch = bool(country) and bool(known_countries) and country not in known_countries

    reasons = []
    if is_new_sender:
        reasons.append("First message on file from this sender — establishing baseline, nothing to compare yet.")
        if is_anonymizing:
            reasons.append(
                f"This message arrives through {infra_display} (anonymizing infrastructure) — "
                "noted, but with no prior history for this sender there's nothing yet to call unusual."
            )
        level = "ok"
        badge = f"🆕 Baseline ({infra_display})" if is_anonymizing else "🆕 Baseline set"
    else:
        anomaly = is_new_network or country_mismatch
        if is_new_anonymizing_infra:
            reasons.append(
                f"This sender has never mailed through {infra_display} before "
                f"({known_network_count} known network(s) on file)."
            )
        elif is_new_network:
            reasons.append(
                f"This sender has never mailed from this network before "
                f"({known_network_count} known network(s) on file)."
            )
        if country_mismatch:
            reasons.append(f"Sending country ({country}) differs from this sender's established pattern.")
        if not reasons:
            reasons.append(
                f"{infra_display} is how this sender always mails — not new or unusual for them."
                if is_anonymizing else
                "Consistent with this sender's known sending network."
            )

        if is_new_anonymizing_infra:
            level, badge = "alert", f"🚨 New {infra_display} route"
        elif anomaly:
            level, badge = "warning", "⚠️ New network"
        else:
            level, badge = "ok", "✅ Consistent"

    # Record this observation for future messages (after computing the
    # comparison above, so the current message doesn't compare against
    # itself).
    now = datetime.now(timezone.utc).isoformat()
    if net24:
        conn.execute(
            """
            INSERT INTO sender_networks (sender_email, network_24, infra_class, country, first_seen, last_seen, hit_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(sender_email, network_24)
            DO UPDATE SET last_seen = excluded.last_seen,
                          infra_class = excluded.infra_class,
                          country = excluded.country,
                          hit_count = hit_count + 1
            """,
            (sender_email, net24, infra_class or None, country or None, now, now),
        )
        conn.commit()

    try:
        conn.close()
    except Exception:
        pass

    return {
        "badge": badge,
        "level": level,
        "is_new_sender": is_new_sender,
        "is_new_network": is_new_network,
        "is_new_anonymizing_infra": is_new_anonymizing_infra,
        "is_anonymizing": is_anonymizing,
        "infra_display": infra_display,
        "country_mismatch": country_mismatch,
        "known_network_count": known_network_count,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Optional: offline VPN/proxy/datacenter CIDR lookup.
# Not required for the app (geolocate.py already classifies infra) --
# kept as a standalone fallback/enrichment for hops geolocate.py could
# not classify, or for use outside this project.
# ---------------------------------------------------------------------------

@dataclass
class VpnRange:
    network: ipaddress.IPv4Network
    provider: str
    category: str  # "vpn" | "proxy" | "datacenter"


def load_vpn_ranges(csv_path: str) -> list[VpnRange]:
    """Load an offline CIDR-range database. Expected columns: cidr,provider,category.
    Free sources: X4BNet VPN/proxy IP lists, IP2Location LITE (ASN edition),
    or published cloud-provider IP ranges (AWS/GCP/Azure/DigitalOcean/OVH)."""
    ranges: list[VpnRange] = []
    import os as _os
    _sp_root = _os.path.dirname(_os.path.abspath(__file__))
    _sp_data = _os.path.realpath(_os.path.join(_sp_root, "data"))
    csv_path = _os.path.realpath(_os.path.join(_sp_root, csv_path))
    if not csv_path.startswith(_sp_data + _os.sep):
        raise ValueError("VPN ranges file must be inside the data/ folder")
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                net = ipaddress.ip_network(row["cidr"], strict=False)
            except ValueError:
                continue
            ranges.append(VpnRange(net, row.get("provider", "unknown"), row.get("category", "vpn")))
    return ranges


def check_vpn_or_datacenter(ip: str, ranges: list[VpnRange]) -> Optional[VpnRange]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for r in ranges:
        if addr in r.network:
            return r
    return None


def scan_cases_for_vpn(
    cases: list[dict],
    ranges: list[VpnRange],
    include_hops: bool = True,
) -> list[dict]:
    """
    Bulk version of check_vpn_or_datacenter: runs the offline CIDR check over
    every IP in every already-analyzed email in one call, instead of the
    caller looping and calling check_vpn_or_datacenter one email/IP at a time.

    `cases` is the same list of per-email result dicts the app already keeps
    in memory for correlation (each with ["parsed"]["from_addr"] and
    ["geo"]["origin"] / ["geo"]["hops"]) -- just pass the whole list through.
    Every distinct IP is only checked against `ranges` once, even if it shows
    up across several emails or several hops.

    Returns one row per (email, IP) pair, flagged or not, ready to hand to a
    dataframe:
        {
            "case": "phish_2024_08.eml", "sender": "cfo@example.com",
            "ip": "185.220.101.7", "hop_role": "origin",
            "flagged": True, "provider": "X4BNet", "category": "vpn",
        }
    """
    rows: list[dict] = []
    match_cache: dict[str, Optional[VpnRange]] = {}

    def _lookup(ip: str) -> Optional[VpnRange]:
        if ip not in match_cache:
            match_cache[ip] = check_vpn_or_datacenter(ip, ranges)
        return match_cache[ip]

    for case in cases:
        case_name = case.get("name") or "Unnamed case"
        sender = ((case.get("parsed", {}) or {}).get("from_addr") or "unknown").strip().lower()
        case_geo = case.get("geo", {}) or {}

        ip_roles: list[tuple[str, str]] = []
        origin_ip = (case_geo.get("origin", {}) or {}).get("ip")
        if origin_ip:
            ip_roles.append(("origin", origin_ip))
        if include_hops:
            for h in case_geo.get("hops", []) or []:
                hop_ip = h.get("ip")
                if hop_ip and hop_ip != origin_ip:
                    ip_roles.append((f"hop {h.get('hop_index', '?')}", hop_ip))

        for role, ip in ip_roles:
            match = _lookup(ip)
            rows.append({
                "case": case_name,
                "sender": sender,
                "ip": ip,
                "hop_role": role,
                "flagged": match is not None,
                "provider": match.provider if match else "-",
                "category": match.category if match else "-",
            })

    return rows


if __name__ == "__main__":
    import os
    demo_db = "network_trust_demo.sqlite3"
    if os.path.exists(demo_db):
        os.remove(demo_db)

    def _demo_connection():
        return sqlite3.connect(demo_db)

    globals()["_get_shared_connection"] = _demo_connection

    print(assess_network_trust("cfo@example.com", "203.0.113.9", "residential", "IN"))
    print(assess_network_trust("cfo@example.com", "203.0.113.9", "residential", "IN"))
    print(assess_network_trust("cfo@example.com", "185.220.101.7", "tor", "DE"))