"""
tor_check.py
============
Confirmed-Tor-exit-node detection, from three independent sources.

Why not geolocate.py's existing "tor" tag: it's a keyword heuristic --
it only fires if "tor" or "exit relay" literally appears in the IP's
ISP/org name string from ip-api.com. Most real Tor exit nodes are
hosted on plain VPS providers (OVH, Hetzner, DigitalOcean, ...) whose
ISP field never mentions Tor, so that heuristic misses the majority of
real exits. This module checks against actual published exit-node
lists instead.

Why several sources, not one -- and why this is the "defensible" part:
  - PRIMARY: the Tor Project's own official, publicly published exit
    list (https://check.torproject.org/torbulkexitlist). First-party,
    the most defensible citation possible in a forensic report --
    "the Tor Project's own directory authorities list this IP."
  - SECONDARY: platformbuilds/Tor-IP-Addresses on GitHub
    (tor-exit-nodes.lst), an hourly auto-updated community mirror (MIT
    licensed, itself a fork of the long-standing SecOps-Institute list
    widely used in security tooling). Independent scrape, independent
    infrastructure -- if the Tor Project's endpoint is ever
    unreachable, this keeps detection working instead of silently
    going dark. Exit-specific, same as PRIMARY.
  - TERTIARY: the same platformbuilds repo's tor-nodes.lst -- its
    full Tor *network* list (all relays: guard/middle/exit combined),
    not exit-specific. Casting this wider net catches Tor participation
    an exit-only list would miss, at the cost of no longer meaning
    "exit" specifically -- which is exactly why it's kept in its own
    tagged source rather than folded silently into the exit-only rows.
    A report citing this source should say "confirmed Tor network
    node" rather than "confirmed exit node."

All three are fetched and kept *separately tagged* per IP, not silently
merged into one anonymous blob. That matters for defensibility: a
report can state precisely "confirmed by the Tor Project's official
exit list" rather than an unattributed "yes/no" that nobody could
independently verify. An IP confirmed by more sources is stronger
evidence than one confirmed by only a single list; the caller gets to
see that distinction, source by source (see tor_exit_sources()).

Failure handling is intentionally asymmetric per source: if one source
fails to fetch, its previously cached entries are left untouched
(never wiped for a fetch that never happened) and the other sources'
data is still used. is_tor_exit() only ever gets weaker (fewer sources
backing it), never wrong, from a single source being temporarily
unreachable.

Storage follows tracker.py's own conventions exactly: same DB file via
tracker.get_connection(), the same intel_sync table and
"%Y-%m-%d %H:%M:%S" timestamp format already used for the URLhaus sync
(see tracker.import_urlhaus_recent), and the same init_db()-before-
every-query pattern used throughout tracker.py. One new table is
added, tor_exit_nodes, keyed on (ip, source) so all three sources'
data can coexist.

    from tor_check import is_tor_exit, tor_exit_sources, maybe_update_tor_list

    maybe_update_tor_list()          # throttled per-source, safe every render
    is_tor_exit("185.220.101.7")     # -> True / False
    tor_exit_sources("185.220.101.7")  # -> ["Tor Project (official)"]

Standalone:  python tor_check.py
"""
import datetime

import requests

import tracker

# --- Sources --------------------------------------------------------------
# Each entry: internal key -> (fetch URL, human-readable label for reports)
SOURCES = {
    "torproject": (
        "https://check.torproject.org/torbulkexitlist",
        "Tor Project (official exit list)",
    ),
    "platformbuilds_github": (
        "https://raw.githubusercontent.com/platformbuilds/Tor-IP-Addresses/master/tor-exit-nodes.lst",
        "platformbuilds/Tor-IP-Addresses (community exit-node mirror, hourly)",
    ),
    # Same repo, but its OTHER file -- the full Tor network list (every
    # relay: guard/middle/exit), not exit-specific. Kept as its own
    # tagged source (never merged into the exit-only rows above) so a
    # hit here is always cited as "Tor network node", not overclaimed
    # as a confirmed exit -- see the module docstring's TERTIARY note.
    "platformbuilds_nodes": (
        "https://raw.githubusercontent.com/platformbuilds/Tor-IP-Addresses/master/tor-nodes.lst",
        "platformbuilds/Tor-IP-Addresses (all Tor nodes, hourly)",
    ),
}

THROTTLE_MINUTES = 30
TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"  # matches tracker.py's own convention exactly

# Per-source last-error tracking, e.g. {"torproject": None, "platformbuilds_github": "timed out", "platformbuilds_nodes": None}
LAST_SYNC_ERRORS = {key: None for key in SOURCES}


def _ensure_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tor_exit_nodes (
            ip TEXT NOT NULL,
            source TEXT NOT NULL,
            last_seen TEXT,
            PRIMARY KEY (ip, source)
        )
    """)
    conn.commit()


def _parse_ip_list(text):
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith("#")]


def _sync_key(source_key):
    """The intel_sync table is shared app-wide (URLhaus uses it too), so
    each Tor source gets its own row -- e.g. 'tor_exit_list:torproject' --
    rather than colliding on one shared timestamp for both sources."""
    return f"tor_exit_list:{source_key}"


def update_source(source_key, timeout=15):
    """
    Force-fetch one named source right now and replace only that
    source's cached rows (the other source's rows are untouched).
    Returns the number of IPs stored for this source.

    Raises on network failure -- use maybe_update_tor_list() for a
    soft-fail that won't interrupt an email scan.
    """
    if source_key not in SOURCES:
        raise ValueError(f"Unknown Tor IP source: {source_key}")
    url, _label = SOURCES[source_key]

    tracker.init_db()
    conn = tracker.get_connection()
    c = conn.cursor()
    _ensure_table(conn)

    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    ips = _parse_ip_list(response.text)

    now = datetime.datetime.now().strftime(TIMESTAMP_FMT)

    c.execute("DELETE FROM tor_exit_nodes WHERE source = ?", (source_key,))
    c.executemany(
        "INSERT OR REPLACE INTO tor_exit_nodes (ip, source, last_seen) VALUES (?, ?, ?)",
        [(ip, source_key, now) for ip in ips]
    )
    c.execute("""
        INSERT OR REPLACE INTO intel_sync (source, last_sync)
        VALUES (?, ?)
    """, (_sync_key(source_key), now))

    conn.commit()
    conn.close()

    LAST_SYNC_ERRORS[source_key] = None
    return len(ips)


def update_tor_exit_list():
    """
    Force-refresh all sources right now, regardless of throttle.
    Returns {"torproject": <count or None>, "platformbuilds_github": <count or None>,
    "platformbuilds_nodes": <count or None>}. A source that fails is
    recorded in LAST_SYNC_ERRORS and reported as None here -- this
    never raises, unlike update_source().
    """
    results = {}
    for key in SOURCES:
        try:
            results[key] = update_source(key)
        except Exception as exc:  # noqa: BLE001 - one bad source shouldn't stop the other
            LAST_SYNC_ERRORS[key] = str(exc)
            results[key] = None
    return results


def maybe_update_tor_list(min_interval_minutes=THROTTLE_MINUTES):
    """
    Refreshes each source independently, only if *that source's* last
    successful sync is older than `min_interval_minutes` (default 30 --
    the same cadence tracker.import_urlhaus_recent uses for URLhaus).
    A slow/down source never blocks or delays the other. Safe to call
    on every page render.

    Never raises. Returns True if at least one source was actually
    attempted (successfully or not), False if both are still fresh.
    """
    tracker.init_db()
    conn = tracker.get_connection()
    c = conn.cursor()
    _ensure_table(conn)

    attempted_any = False
    for key in SOURCES:
        c.execute("SELECT last_sync FROM intel_sync WHERE source = ?", (_sync_key(key),))
        row = c.fetchone()

        due = True
        if row and row[0]:
            try:
                last_sync = datetime.datetime.strptime(row[0], TIMESTAMP_FMT)
                age_minutes = (datetime.datetime.now() - last_sync).total_seconds() / 60.0
                due = age_minutes >= min_interval_minutes
            except Exception:
                due = True  # unparsable timestamp -- treat as stale and refresh

        if due:
            attempted_any = True
            try:
                update_source(key)
            except Exception as exc:  # noqa: BLE001 - keep going regardless
                LAST_SYNC_ERRORS[key] = str(exc)

    conn.close()
    return attempted_any


def is_tor_exit(ip):
    """True if `ip` is on ANY currently-cached exit list, from either source."""
    if not ip:
        return False

    tracker.init_db()
    conn = tracker.get_connection()
    c = conn.cursor()
    _ensure_table(conn)

    c.execute("SELECT 1 FROM tor_exit_nodes WHERE ip = ? LIMIT 1", (ip,))
    hit = c.fetchone()
    conn.close()
    return hit is not None


def tor_exit_sources(ip):
    """
    Human-readable labels of every source that currently lists `ip` as
    a Tor exit -- e.g. ["Tor Project (official exit list)"], or both
    labels if confirmed by both. Empty list if not a confirmed exit.
    This is the citation a forensic report should actually quote,
    rather than an unattributed True/False.
    """
    if not ip:
        return []

    tracker.init_db()
    conn = tracker.get_connection()
    c = conn.cursor()
    _ensure_table(conn)

    c.execute("SELECT DISTINCT source FROM tor_exit_nodes WHERE ip = ?", (ip,))
    rows = c.fetchall()
    conn.close()

    return [SOURCES[r[0]][1] for r in rows if r[0] in SOURCES]


def _iter_case_ips(case):
    """
    Yield (ip, hop_label) for every distinct IP attached to a single
    loaded email `case` dict (the app's in-session case shape: a
    "geo" key holding {"origin": {...}, "hops": [...]}, as produced by
    geolocate.trace()) -- the origin IP first, then every routing hop.
    Duplicate IPs within the same case (an IP reappearing at more than
    one hop) are only yielded once, so one case can't inflate its own
    flagged count.
    """
    geo = case.get("geo", {}) or {}
    origin = geo.get("origin", {}) or {}
    seen = set()

    origin_ip = origin.get("ip")
    if origin_ip and origin_ip not in seen:
        seen.add(origin_ip)
        yield origin_ip, "Origin"

    for h in geo.get("hops", []) or []:
        ip = h.get("ip")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        idx = h.get("hop_index")
        yield ip, (f"Hop {idx}" if idx is not None else "Hop")


def _case_label(case):
    """Best-effort human-readable identifier for a loaded case, for the
    bulk-scan results table -- built from the same fields (source row,
    sender, subject) already used to identify emails elsewhere in the
    app, so a flagged row here can be matched back to a specific email."""
    parsed = case.get("parsed", {}) or {}
    from_addr = parsed.get("from_addr") or "unknown sender"
    subject = (parsed.get("subject") or "").strip()
    label = f"{from_addr} — {subject[:60]}" if subject else from_addr
    row = case.get("row")
    return f"[{row}] {label}" if row is not None else label


def scan_cases_for_tor(cases):
    """
    Re-check every origin + hop IP across every currently loaded email
    `case` against the *currently cached* tor_exit_nodes table, in one
    pass -- independent of whatever tor_exit_confirmed/tor_exit_sources
    each case's own geo data already carries from whenever it was
    originally traced.

    That distinction matters: geolocate.trace() stamps each hop with
    the confirmation status current *at trace time* and never goes
    back to update older, already-loaded cases when the Tor list is
    refreshed later (e.g. via the manual "Fetch Tor exit lists now"
    button, or the 30-minute auto-throttle rolling over). A case
    traced an hour ago can be sitting on stale Tor-exit info even
    though the DB now knows more. Re-querying tor_exit_nodes right now
    for every loaded case is what actually answers "does ANY loaded
    email touch a Tor exit, using what we know about Tor at this
    moment" -- mirroring network_trust.scan_cases_for_vpn's offline
    bulk-scan pattern for VPN/datacenter ranges, but backed by this
    module's own DB table instead of a CIDR CSV, so there's no file to
    supply first.

    Returns a list of row-dicts, one per (case, ip) pair actually
    present -- suitable for pd.DataFrame(...). Each row carries a
    "flagged" bool (True = confirmed Tor exit on at least one source),
    matching the column name the VPN bulk scan already uses so the two
    panels can share the same "df['flagged'].sum() / len(df)" pattern.
    """
    tracker.init_db()
    conn = tracker.get_connection()
    c = conn.cursor()
    _ensure_table(conn)

    # One query for the whole cached list instead of one query per IP --
    # a loaded set of emails can easily have dozens of hops between them,
    # and this keeps a "scan everything" click to a single DB round trip.
    c.execute("SELECT ip, source FROM tor_exit_nodes")
    by_ip = {}
    for ip, source in c.fetchall():
        by_ip.setdefault(ip, []).append(source)
    conn.close()

    rows = []
    for case in cases:
        label = _case_label(case)
        ehash = case.get("_evidence_hash", "")
        for ip, hop_label in _iter_case_ips(case):
            sources = by_ip.get(ip, [])
            rows.append({
                "email": label,
                "evidence_hash": ehash[:12] if ehash else "",
                "hop": hop_label,
                "ip": ip,
                "confirmed_sources": "; ".join(
                    SOURCES[s][1] for s in sources if s in SOURCES
                ) or "-",
                "flagged": bool(sources),
            })
    return rows


def tor_list_status():
    """
    For the UI: per-source IP count, last successful sync, and last
    error (if any), plus the total distinct IPs across all sources.
    """
    tracker.init_db()
    conn = tracker.get_connection()
    c = conn.cursor()
    _ensure_table(conn)

    per_source = {}
    for key, (_url, label) in SOURCES.items():
        c.execute("SELECT COUNT(*) FROM tor_exit_nodes WHERE source = ?", (key,))
        count = c.fetchone()[0]
        c.execute("SELECT last_sync FROM intel_sync WHERE source = ?", (_sync_key(key),))
        row = c.fetchone()
        per_source[key] = {
            "label": label,
            "count": count,
            "last_sync": row[0] if row else None,
            "last_error": LAST_SYNC_ERRORS.get(key),
        }

    c.execute("SELECT COUNT(DISTINCT ip) FROM tor_exit_nodes")
    total_distinct = c.fetchone()[0]
    conn.close()

    return {"sources": per_source, "total_distinct_ips": total_distinct}


if __name__ == "__main__":
    print("Refreshing all sources...")
    print(update_tor_exit_list())
    print()
    print("Known exit (from live fetch):", is_tor_exit("185.220.101.7"))
    print("  confirmed by:", tor_exit_sources("185.220.101.7"))
    print("A normal IP is not:", is_tor_exit("8.8.8.8"))
    print()
    print("Status:", tor_list_status())