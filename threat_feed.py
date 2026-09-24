import csv
import os
import time
import traceback
from datetime import datetime, timezone

import requests

from tracker import remember_indicator, get_connection


# --- Real-time URLhaus API (Auth-Key) ---------------------------------
# abuse.ch's incremental "recent URLs" endpoint -- this is the endpoint
# they themselves recommend for near-real-time syncing (it's what the
# official Elastic/XSOAR integrations use), as opposed to the bulk CSV
# dump below which is a periodic snapshot. Needs a personal Auth-Key,
# free from https://auth.abuse.ch/, sent as an HTTP header (not a URL
# parameter).
#
# No key is hardcoded here on purpose -- an Auth-Key is a bearer credential
# tied to your abuse.ch account, and anyone with it can submit/query
# URLhaus as you. A key that WAS hardcoded in this spot previously has
# already been exposed and should be treated as compromised: generate a
# fresh one at https://auth.abuse.ch/ and never paste it back into source.
# Set it via the URLHAUS_AUTH_KEY environment variable instead (e.g. in a
# local, gitignored .env file, or your shell profile). With no key set,
# update_urlhaus_feed() below automatically falls back to the keyless bulk
# CSV feed, so the app still works with zero setup -- just without
# real-time sync.
URLHAUS_AUTH_KEY = os.environ.get("URLHAUS_AUTH_KEY", "")

URLHAUS_RECENT_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

# --- Bulk CSV feed (no key needed) -- kept as an automatic fallback ----
URLHAUS_RECENT_URLS = (
    "https://urlhaus.abuse.ch/downloads/csv_recent/"
)

# Set whenever a sync imports 0 indicators, so the UI can show the
# *actual* reason instead of a generic "check network access" guess.
# Reset to None on a successful import.
LAST_URLHAUS_ERROR = None

# Set by maybe_update_urlhaus_feed() so callers can tell "skipped because
# the 30-minute throttle window hasn't elapsed" (False, LAST_URLHAUS_ERROR
# is stale/irrelevant) apart from "actually tried to sync just now" (True,
# LAST_URLHAUS_ERROR reflects this attempt).
LAST_URLHAUS_SYNC_ATTEMPTED = False


def _record_sync_timestamp():
    """Stamp intel_sync.last_sync for source='urlhaus' with now.

    The "Last Sync" metric in the UI reads this column directly, but
    nothing in this module ever wrote to it -- only to a separate local
    throttle file used for the 30-minute auto-sync window -- so it stayed
    frozen at whatever value (if any) was last put there by something
    else, no matter how many times a sync actually ran. This is called
    right after a sync genuinely reaches and parses the feed, even when
    zero *new* indicators come out of it (already up to date is still a
    completed sync and should update the timestamp).
    """
    try:
        conn = get_connection()
        c = conn.cursor()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE intel_sync SET last_sync = ? WHERE source = 'urlhaus'", (now,))
        if c.rowcount == 0:
            c.execute("INSERT INTO intel_sync (source, last_sync) VALUES (?, ?)", ("urlhaus", now))
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"Could not update intel_sync.last_sync for urlhaus: {exc!r}")


def _store_rows(url_iterable):
    """Shared storage loop for both the API and CSV import paths.
    Returns (imported_count, first_store_error_or_None)."""
    imported = 0
    first_store_error = None
    seen = set()
    for url in url_iterable:
        url = (url or "").strip()
        if not url or url in seen:
            # URLhaus's "recent" feeds occasionally repeat the same URL
            # across rows (a resubmission, or overlap between the last
            # sync and this one). Every repeat would otherwise cost a
            # full remember_indicator() round trip -- normally a DB
            # write -- for a value we're about to write again with the
            # exact same kind/score/verdict/source. Skipping it here is
            # a pure win: same end state, fewer writes.
            continue
        seen.add(url)
        try:
            # URLhaus is a malicious-URL source,
            # so we assign a strong reputation.
            remember_indicator(url, "url", 0.98, "malicious", "URLhaus")
            imported += 1
        except Exception as exc:
            # Don't let one bad row (or a DB problem) kill the whole
            # sync -- keep going, but remember the first failure so we
            # can report it if nothing at all got stored.
            if first_store_error is None:
                first_store_error = f"{exc!r}\n{traceback.format_exc(limit=3)}"
    return imported, first_store_error


def _import_from_api():
    """
    Real-time sync via the Auth-Key'd URLhaus API. Returns the number of
    indicators imported, or None if the API path couldn't be used at all
    (no key configured, request failure, bad response shape) -- None
    signals the caller to fall back to the CSV bulk feed instead of
    treating it as "zero new indicators right now".
    """
    global LAST_URLHAUS_ERROR

    if not URLHAUS_AUTH_KEY:
        return None

    try:
        response = requests.get(
            URLHAUS_RECENT_API,
            timeout=15,
            headers={
                "Auth-Key": URLHAUS_AUTH_KEY,
                "User-Agent": "SIH26106-Threat-Detector/1.0",
            },
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        LAST_URLHAUS_ERROR = f"URLHaus real-time API request failed: {exc!r}"
        return None

    query_status = payload.get("query_status")
    if query_status == "no_results":
        # Valid key, just nothing new since the last poll -- not an error,
        # and still a completed sync, so the timestamp should move.
        LAST_URLHAUS_ERROR = None
        _record_sync_timestamp()
        return 0
    if query_status != "ok":
        LAST_URLHAUS_ERROR = (
            f"URLHaus API returned query_status={query_status!r} -- if "
            "this says something like 'invalid_auth_key', generate a new "
            "key at https://auth.abuse.ch/ and update URLHAUS_AUTH_KEY."
        )
        return None

    imported, first_store_error = _store_rows(
        entry.get("url") for entry in payload.get("urls", [])
    )
    _record_sync_timestamp()

    if imported > 0:
        LAST_URLHAUS_ERROR = None
    elif first_store_error:
        LAST_URLHAUS_ERROR = f"Fetched from the real-time API but couldn't store indicators: {first_store_error}"
    else:
        LAST_URLHAUS_ERROR = "URLHaus real-time API returned no URL entries."

    return imported


def _import_from_csv():
    """
    Fallback sync via the bulk CSV feed (no Auth-Key needed). Returns the
    number of indicators imported.
    """
    global LAST_URLHAUS_ERROR

    try:
        response = requests.get(
            URLHAUS_RECENT_URLS,
            timeout=15,
            headers={
                "User-Agent": "SIH26106-Threat-Detector/1.0"
            }
        )
        response.raise_for_status()
    except Exception as exc:
        LAST_URLHAUS_ERROR = f"Could not reach URLHaus CSV feed: {exc!r}"
        return 0

    try:
        text = response.text
        raw_lines = text.splitlines()

        # URLhaus prefixes the whole file with a '#' banner block, and
        # -- easy to miss -- the actual CSV header line is ALSO
        # prefixed with '# ' (e.g. "# id,dateadded,url,url_status,...").
        # Blindly dropping every line that starts with '#' throws the
        # header away too, so csv.DictReader would silently promote the
        # first data row to be the header instead, and every
        # row.get("url") would return None forever.
        #
        # Fix: locate the real header line explicitly (it's the one
        # whose de-commented text starts with "id,dateadded,url"),
        # strip its leading '#' so csv.DictReader can use it, and only
        # treat lines above/after it as banner/comments to discard.
        header_idx = None
        for i, raw_line in enumerate(raw_lines):
            decommented = raw_line.lstrip("#").strip()
            if decommented.lower().startswith("id,dateadded,url"):
                header_idx = i
                break

        if header_idx is None:
            LAST_URLHAUS_ERROR = (
                "Downloaded the CSV feed but couldn't find the header row "
                "-- URLHaus may have changed its file format. Response "
                f"started with: {text[:200]!r}"
            )
            return 0

        def _data_lines():
            # csv.DictReader accepts any iterable of strings, not just a
            # file or StringIO -- feeding it this generator directly
            # parses each line exactly once. The previous version built
            # a full `lines` list, joined it back into one big string,
            # and wrapped that in io.StringIO() just so csv could split
            # it apart again -- three passes and two extra full copies
            # of the whole feed for a file that can run to several
            # thousand rows.
            yield raw_lines[header_idx].lstrip("#").strip()
            for line in raw_lines[header_idx + 1:]:
                if line.strip() and not line.startswith("#"):
                    yield line

        reader = csv.DictReader(_data_lines())
        imported, first_store_error = _store_rows(row.get("url") for row in reader)
        # Feed was genuinely downloaded and parsed at this point, so the
        # sync counts as complete regardless of how many rows were new.
        _record_sync_timestamp()

        if imported > 0:
            LAST_URLHAUS_ERROR = None
        elif first_store_error:
            row_count = sum(
                1 for line in raw_lines[header_idx + 1:]
                if line.strip() and not line.startswith("#")
            )
            LAST_URLHAUS_ERROR = (
                f"Parsed {row_count} CSV rows but "
                f"remember_indicator() failed to store them: {first_store_error}"
            )
        else:
            LAST_URLHAUS_ERROR = (
                "Parsed the CSV feed successfully but it contained no "
                "rows with a usable 'url' value."
            )

        return imported

    except Exception as exc:
        LAST_URLHAUS_ERROR = (
            f"Unexpected error parsing the CSV feed: {exc!r}\n"
            f"{traceback.format_exc(limit=3)}"
        )
        return 0


def update_urlhaus_feed():
    """
    Sync malicious URLs from URLhaus into the local threat-intelligence
    database. Tries the real-time Auth-Key API first; if that's
    unavailable or turns up nothing, falls back to the bulk CSV feed
    (which needs no key). Returns the number of indicators imported.

    A failure doesn't disappear silently -- the reason is recorded in
    LAST_URLHAUS_ERROR so it can be surfaced in the UI.
    """
    global LAST_URLHAUS_ERROR

    api_imported = _import_from_api()
    if api_imported:
        return api_imported

    api_error = LAST_URLHAUS_ERROR  # preserve in case the CSV fallback also fails

    csv_imported = _import_from_csv()
    if csv_imported:
        return csv_imported

    # Both paths came back empty -- keep both error messages visible so a
    # bad Auth-Key doesn't get silently masked by a coincidental CSV
    # hiccup (or vice versa).
    if api_error and LAST_URLHAUS_ERROR and api_error != LAST_URLHAUS_ERROR:
        LAST_URLHAUS_ERROR = f"Real-time API: {api_error} | CSV fallback: {LAST_URLHAUS_ERROR}"
    elif api_error and not LAST_URLHAUS_ERROR:
        LAST_URLHAUS_ERROR = api_error

    return 0


FEED_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "data",
    "urlhaus_last_update.txt"
)

FEED_UPDATE_INTERVAL = 30 * 60  # 30 minutes


def maybe_update_urlhaus_feed():
    """
    Update URLhaus only when the previous update is older than
    FEED_UPDATE_INTERVAL.
    """

    global LAST_URLHAUS_ERROR, LAST_URLHAUS_SYNC_ATTEMPTED

    try:
        now = time.time()

        if os.path.exists(FEED_CACHE_FILE):
            with open(FEED_CACHE_FILE, "r", encoding="utf-8") as fh:
                last_update = float(fh.read().strip() or 0)

            if now - last_update < FEED_UPDATE_INTERVAL:
                LAST_URLHAUS_SYNC_ATTEMPTED = False
                return 0

        LAST_URLHAUS_SYNC_ATTEMPTED = True
        imported = update_urlhaus_feed()

        if imported > 0:
            os.makedirs(
                os.path.dirname(FEED_CACHE_FILE),
                exist_ok=True
            )

            with open(FEED_CACHE_FILE, "w", encoding="utf-8") as fh:
                fh.write(str(now))

        return imported

    except Exception as exc:
        LAST_URLHAUS_SYNC_ATTEMPTED = True
        LAST_URLHAUS_ERROR = f"maybe_update_urlhaus_feed() crashed: {exc!r}"
        return 0