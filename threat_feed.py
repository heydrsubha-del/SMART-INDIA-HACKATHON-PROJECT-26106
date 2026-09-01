import csv
import io
import os
import time
import requests

from tracker import remember_indicator


URLHAUS_RECENT_URLS = (
    "https://urlhaus.abuse.ch/downloads/csv_recent/"
)


def update_urlhaus_feed():
    """
    Download the recent URLhaus feed and store malicious URLs
    in the local threat-intelligence database.

    Returns the number of indicators imported.
    """

    try:
        response = requests.get(
            URLHAUS_RECENT_URLS,
            timeout=15,
            headers={
                "User-Agent": "SIH26106-Threat-Detector/1.0"
            }
        )

        response.raise_for_status()

        imported = 0

        text = response.text

        # URLhaus CSV contains comment lines beginning with '#'
        lines = [
            line
            for line in text.splitlines()
            if line.strip() and not line.startswith("#")
        ]

        reader = csv.DictReader(io.StringIO("\n".join(lines)))

        for row in reader:
            url = (row.get("url") or "").strip()

            if not url:
                continue

            # URLhaus is a malicious-URL source,
            # so we assign a strong reputation.
            remember_indicator(
                url,
                "url",
                0.98,
                "malicious",
                "URLhaus"
            )

            imported += 1

        return imported

    except Exception:
        # Threat feeds must never break the main detector.
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

    try:
        now = time.time()

        if os.path.exists(FEED_CACHE_FILE):
            with open(FEED_CACHE_FILE, "r", encoding="utf-8") as fh:
                last_update = float(fh.read().strip() or 0)

            if now - last_update < FEED_UPDATE_INTERVAL:
                return 0

        imported = update_urlhaus_feed()

        if imported > 0:
            os.makedirs(
                os.path.dirname(FEED_CACHE_FILE),
                exist_ok=True
            )

            with open(FEED_CACHE_FILE, "w", encoding="utf-8") as fh:
                fh.write(str(now))

        return imported

    except Exception:
        return 0