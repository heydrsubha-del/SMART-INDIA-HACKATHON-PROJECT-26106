import sqlite3
import datetime
import os
import requests
import certifi
import csv
import io
import urllib.request

_INDICATOR_CACHE = {}
_LOOKUP_CACHE = {}

DB_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "threat_memory.db"
)


def get_connection():
    return sqlite3.connect(DB_FILE)


def init_db():
    """Create the local adaptive threat-intelligence database."""
    conn = get_connection()
    c = conn.cursor()

    # Existing attacker memory
    c.execute("""
        CREATE TABLE IF NOT EXISTS attackers (
            date TEXT,
            ip TEXT,
            country TEXT,
            score REAL,
            verdict TEXT
        )
    """)

    # Compact threat intelligence memory
    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            reputation REAL DEFAULT 0.0,
            category TEXT DEFAULT 'unknown',
            first_seen TEXT,
            last_seen TEXT,
            observations INTEGER DEFAULT 1,
            source TEXT DEFAULT 'local_analysis'
        )
    """)

    # Verified analyst feedback
    c.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text_hash TEXT UNIQUE,
            label TEXT NOT NULL,
            created_at TEXT
        )
    """)
        # Verified samples used for future model retraining
    c.execute("""
        CREATE TABLE IF NOT EXISTS feedback_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text_hash TEXT UNIQUE,
            text TEXT NOT NULL,
            label TEXT NOT NULL,
            created_at TEXT
        )
    """)

    # Complete analyst review history.
    # Keeps every review, including repeated reviews of the same email.
    c.execute("""
        CREATE TABLE IF NOT EXISTS feedback_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text_hash TEXT NOT NULL,
            label TEXT NOT NULL,
            created_at TEXT
        )
    """)

        # External threat-intelligence synchronization state
    c.execute("""
        CREATE TABLE IF NOT EXISTS intel_sync (
            source TEXT PRIMARY KEY,
            last_sync TEXT
        )
    """)

    conn.commit()
    conn.close()


def log_threat(ip, country, score, verdict):
    """Save an analyzed attacker/IP to local memory."""
    if not ip or ip == "Unknown":
        return

    init_db()

    conn = get_connection()
    c = conn.cursor()

    date_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute(
        "INSERT INTO attackers VALUES (?, ?, ?, ?, ?)",
        (date_now, ip, country, score, verdict)
    )

    conn.commit()
    conn.close()


def remember_indicator(
    indicator,
    indicator_type,
    reputation,
    category="unknown",
    source="local_analysis"
):
    """
    Remember an IP/domain/URL/hash observed during analysis.
    Existing indicators are updated instead of duplicated.
    """

    if not indicator:
        return

    init_db()

    indicator = str(indicator).strip().lower()
    cache_key = (indicator, indicator_type)
    reputation = float(reputation)

    # If this indicator was already handled in this session,
    # avoid another SQLite write.
    if cache_key in _INDICATOR_CACHE:
        _INDICATOR_CACHE[cache_key] = max(
            _INDICATOR_CACHE[cache_key],
            reputation
        )
        return

    _INDICATOR_CACHE[cache_key] = reputation

    conn = get_connection()
    c = conn.cursor()

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute("""
        SELECT id, observations
        FROM threat_intel
        WHERE indicator = ? AND indicator_type = ?
    """, (indicator, indicator_type))

    existing = c.fetchone()

    if existing:
                c.execute("""
            UPDATE threat_intel
            SET reputation = MAX(reputation, ?),
                category = ?,
                last_seen = ?,
                observations = ?
            WHERE id = ?
        """, (
            float(reputation),
            category,
            now,
            existing[1] + 1,
            existing[0]
        ))
    else:
        c.execute("""
            INSERT INTO threat_intel
            (
                indicator,
                indicator_type,
                reputation,
                category,
                first_seen,
                last_seen,
                observations,
                source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            indicator,
            indicator_type,
            float(reputation),
            category,
            now,
            now,
            1,
            source
        ))

    conn.commit()
    conn.close()

    _LOOKUP_CACHE.pop(
        (indicator, indicator_type),
        None
    )

def lookup_indicator(indicator, indicator_type=None):
    """Return stored intelligence for an indicator."""

    if not indicator:
        return None

    init_db()

    indicator = str(indicator).strip().lower()
    cache_key = (indicator, indicator_type)

    # Avoid repeated SQLite reads for the same indicator
    # during the current application process.
    if cache_key in _LOOKUP_CACHE:
        return _LOOKUP_CACHE[cache_key]

    conn = get_connection()
    c = conn.cursor()

    if indicator_type:
        c.execute(
            """
            SELECT *
            FROM threat_intel
            WHERE indicator = ? AND indicator_type = ?
            LIMIT 1
            """,
            (indicator, indicator_type),
        )
    else:
        c.execute(
            """
            SELECT *
            FROM threat_intel
            WHERE indicator = ?
            LIMIT 1
            """,
            (indicator,),
        )

    result = c.fetchone()

    conn.close()

    _LOOKUP_CACHE[cache_key] = result

    return result

    """Return stored intelligence for an indicator."""
    if not indicator:
        return None

    init_db()

    conn = get_connection()
    c = conn.cursor()

    indicator = str(indicator).strip().lower()

    if indicator_type:
        c.execute("""
            SELECT *
            FROM threat_intel
            WHERE indicator = ? AND indicator_type = ?
            LIMIT 1
        """, (indicator, indicator_type))
    else:
        c.execute("""
            SELECT *
            FROM threat_intel
            WHERE indicator = ?
            LIMIT 1
        """, (indicator,))

    result = c.fetchone()

    conn.close()

    return result


def check_history(ip):
    """Return previous attack count and highest observed score."""
    if not ip or ip == "Unknown":
        return (0, 0)

    init_db()

    conn = get_connection()
    c = conn.cursor()

    c.execute(
        "SELECT count(*), max(score) FROM attackers WHERE ip=?",
        (ip,)
    )

    result = c.fetchone()

    conn.close()

    return result if result[0] > 0 else (0, 0)


def add_feedback(text_hash, label, text=None):
    """
    Store verified analyst feedback.

    label should be:
        phish
        legit
    """

    if not text_hash or label not in ("phish", "legit"):
        return

    init_db()

    conn = get_connection()
    c = conn.cursor()

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Preserve every analyst review, including repeat reviews.
    c.execute("""
        INSERT INTO feedback_history
        (text_hash, label, created_at)
        VALUES (?, ?, ?)
    """, (text_hash, label, now))

    c.execute("""
        INSERT OR REPLACE INTO feedback
        (text_hash, label, created_at)
        VALUES (?, ?, ?)
    """, (text_hash, label, now))
    
    if text:
        c.execute("""
            INSERT OR REPLACE INTO feedback_samples
            (text_hash, text, label, created_at)
            VALUES (?, ?, ?, ?)
        """, (text_hash, text, label, now))

    conn.commit()
    conn.close()


def get_feedback_count():
    """Return number of verified feedback samples."""
    init_db()

    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM feedback")

    count = c.fetchone()[0]

    conn.close()

    return count


def import_urlhaus_recent(auth_key, limit=5000, min_interval_minutes=5):
    """
    Import recent URLhaus malware URLs into local threat memory.

    The feed is only fetched when the last sync is older than the
    configured minimum interval.
    """

    if not auth_key:
        return {
            "status": "missing_key",
            "imported": 0,
            "message": "URLhaus Auth-Key not configured."
        }

    init_db()

    conn = get_connection()
    c = conn.cursor()

    c.execute(
        "SELECT last_sync FROM intel_sync WHERE source = ?",
        ("urlhaus",)
    )

    row = c.fetchone()

    if row and row[0]:
        try:
            last_sync = datetime.datetime.strptime(
                row[0],
                "%Y-%m-%d %H:%M:%S"
            )

            age_minutes = (
                datetime.datetime.now() - last_sync
            ).total_seconds() / 60.0

            if age_minutes < min_interval_minutes:
                conn.close()

                return {
                    "status": "cached",
                    "imported": 0,
                    "message": (
                        "URLhaus was synced recently. "
                        "Using existing local intelligence."
                    )
                }

        except Exception:
            pass

    conn.close()

    feed_url = (
        "https://urlhaus-api.abuse.ch/v2/files/exports/"
        f"{auth_key}/recent.csv"
    )

    try:
        request = urllib.request.Request(
            feed_url,
            headers={
                "User-Agent": "SIH26106-Threat-Intel/1.0"
            }
        )

        response = requests.get(
            feed_url,
            headers={
                "User-Agent": "SIH26106-Threat-Intel/1.0"
            },
            timeout=12,
            verify=certifi.where()
        )

        response.raise_for_status()

        content = response.content.decode(
            "utf-8",
            errors="ignore"
        )

    except Exception as exc:
        return {
            "status": "error",
            "imported": 0,
            "message": f"URLhaus request failed: {exc}"
        }

    reader = csv.DictReader(
        line for line in io.StringIO(content)
        if not line.startswith("#")
    )

    imported = 0

    conn = get_connection()
    c = conn.cursor()

    now = datetime.datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    for row in reader:

        url = str(row.get("url") or "").strip()

        if not url:
            continue

        try:
            c.execute("""
                SELECT id
                FROM threat_intel
                WHERE indicator = ?
                  AND indicator_type = ?
                LIMIT 1
            """, (url.lower(), "url"))

            existing = c.fetchone()

            if existing:
                c.execute("""
                    UPDATE threat_intel
                    SET reputation = MAX(reputation, ?),
                        category = ?,
                        last_seen = ?,
                        source = ?
                    WHERE id = ?
                """, (
                    1.0,
                    "malware",
                    now,
                    "urlhaus",
                    existing[0]
                ))

            else:
                c.execute("""
                    INSERT INTO threat_intel
                    (
                        indicator,
                        indicator_type,
                        reputation,
                        category,
                        first_seen,
                        last_seen,
                        observations,
                        source
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    url.lower(),
                    "url",
                    1.0,
                    "malware",
                    now,
                    now,
                    1,
                    "urlhaus"
                ))

            imported += 1

        except Exception:
            continue

        if imported >= limit:
            break

    c.execute("""
        INSERT OR REPLACE INTO intel_sync
        (source, last_sync)
        VALUES (?, ?)
    """, ("urlhaus", now))

    conn.commit()
    conn.close()

    return {
        "status": "updated",
        "imported": imported,
        "message": (
            f"Imported {imported} URLhaus malware URLs "
            "into local threat intelligence."
        )
    }


def get_feedback_history_count(text_hash):
    """Return how many analyst reviews exist for this exact email."""

    if not text_hash:
        return 0

    init_db()

    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        SELECT COUNT(*)
        FROM feedback_history
        WHERE text_hash = ?
    """, (text_hash,))

    count = c.fetchone()[0]

    conn.close()

    return count