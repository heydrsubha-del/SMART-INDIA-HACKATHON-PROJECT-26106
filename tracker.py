"""Local threat-intelligence memory (SQLite).

Two modes, chosen by the SIH26106_MULTIUSER environment variable:

* Off (default) -- single-user / local mode. Everything lives in one file,
  threat_memory.db, exactly as before.

* On ("1") -- public-hosting mode. Each visitor's session gets its OWN
  private database file (in the system temp folder), so one visitor can never
  read or affect another visitor's history, feedback or indicators. The
  public URLhaus feed is the only thing kept in a shared database, and it
  contains no visitor data. Session databases are deleted when the visitor
  presses "Delete my data" and automatically after SESSION_TTL_SECONDS of
  inactivity.
"""
import sqlite3
import datetime
import os
import requests
import certifi
import csv
import io
import hashlib
import tempfile
import threading
import time

MULTIUSER = os.environ.get("SIH26106_MULTIUSER", "").strip().lower() in (
    "1", "true", "yes", "on"
)

_INDICATOR_CACHE = {}
_LOOKUP_CACHE = {}
_CACHE_LIMIT = 20000

# Single-user database, and (in multi-user mode) the shared public-feed DB.
DB_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "threat_memory.db"
)

# Per-visitor databases live here in multi-user mode.
SESSION_DIR = os.path.join(tempfile.gettempdir(), "sih26106_sessions")
SESSION_TTL_SECONDS = 6 * 60 * 60  # delete idle session data after 6 hours

# Indicator sources that are public threat-feed data (safe to share).
_SHARED_SOURCES = {"urlhaus"}

_SCHEMA_DONE = set()
_SCHEMA_LOCK = threading.Lock()
_last_cleanup = 0.0


# --------------------------------------------------------------------------
# Session / path handling
# --------------------------------------------------------------------------

def _session_id():
    """The current Streamlit session id, or None outside a Streamlit run
    (for example inside a background thread)."""
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        try:
            ctx = get_script_run_ctx(suppress_warning=True)
        except TypeError:
            ctx = get_script_run_ctx()
        return ctx.session_id if ctx else None
    except Exception:
        return None


def _cleanup_old_sessions():
    """Delete session databases nobody has touched for SESSION_TTL_SECONDS.
    Runs at most once every 10 minutes."""
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < 600:
        return
    _last_cleanup = now
    try:
        for name in os.listdir(SESSION_DIR):
            full = os.path.join(SESSION_DIR, name)
            try:
                if now - os.path.getmtime(full) > SESSION_TTL_SECONDS:
                    os.remove(full)
                    _SCHEMA_DONE.discard(full)
            except OSError:
                pass
    except OSError:
        pass


def _db_path(shared=False):
    """Which database file the current caller should use."""
    if not MULTIUSER or shared:
        return DB_FILE

    sid = _session_id()
    if not sid:
        # No identifiable visitor (e.g. a worker thread). Use a throw-away
        # in-memory database so nothing can ever leak between visitors.
        return ":memory:"

    try:
        os.makedirs(SESSION_DIR, mode=0o700, exist_ok=True)
    except OSError:
        return ":memory:"
    _cleanup_old_sessions()
    name = hashlib.sha256(sid.encode("utf-8")).hexdigest()[:32] + ".db"
    return os.path.join(SESSION_DIR, name)


def _create_schema(conn, wal=False):
    c = conn.cursor()
    if wal:
        try:
            c.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:
            pass

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


def get_connection(shared=False):
    """Open the right database for the current visitor.

    shared=True always returns the public-feed database (URLhaus data and
    its sync timestamp). Everything else is private to the visitor in
    multi-user mode.
    """
    path = _db_path(shared)
    existed = path == ":memory:" or os.path.exists(path)

    conn = sqlite3.connect(path, timeout=30)

    if path == ":memory:" or not existed or path not in _SCHEMA_DONE:
        with _SCHEMA_LOCK:
            _create_schema(conn, wal=(MULTIUSER and shared))
            if path != ":memory:":
                _SCHEMA_DONE.add(path)
                if not existed:
                    try:
                        os.chmod(path, 0o600)
                    except OSError:
                        pass
    elif MULTIUSER and not shared:
        # Mark the session database as recently used.
        try:
            os.utime(path, None)
        except OSError:
            pass

    return conn


def init_db():
    """Create the database tables for the current visitor (idempotent)."""
    get_connection().close()


def delete_my_data():
    """Delete everything stored for the current visitor. Only acts in
    multi-user mode, so it can never wipe a local single-user database."""
    if not MULTIUSER:
        return False

    path = _db_path(False)
    if path != ":memory:":
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                os.remove(path + suffix)
            except OSError:
                pass
        _SCHEMA_DONE.discard(path)

    for cache in (_INDICATOR_CACHE, _LOOKUP_CACHE):
        for key in [k for k in cache if k and k[0] == path]:
            cache.pop(key, None)
    return True


def _trim_caches():
    if len(_INDICATOR_CACHE) > _CACHE_LIMIT:
        _INDICATOR_CACHE.clear()
    if len(_LOOKUP_CACHE) > _CACHE_LIMIT:
        _LOOKUP_CACHE.clear()


# --------------------------------------------------------------------------
# Public API (same functions as before)
# --------------------------------------------------------------------------

def log_threat(ip, country, score, verdict):
    """Save an analyzed attacker/IP to local memory."""
    if not ip or ip == "Unknown":
        return

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

    Public URLhaus feed entries go to the shared database; everything
    derived from a visitor's own emails goes to that visitor's private one.
    """

    if not indicator:
        return

    indicator = str(indicator).strip().lower()
    reputation = float(reputation)
    shared = str(source).strip().lower() in _SHARED_SOURCES

    path = _db_path(shared)
    cache_key = (path, indicator, indicator_type)

    # If this indicator was already handled for this database,
    # avoid another SQLite write.
    if cache_key in _INDICATOR_CACHE:
        _INDICATOR_CACHE[cache_key] = max(
            _INDICATOR_CACHE[cache_key],
            reputation
        )
        return

    _trim_caches()
    _INDICATOR_CACHE[cache_key] = reputation

    conn = get_connection(shared=shared)
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
            reputation,
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
            reputation,
            category,
            now,
            now,
            1,
            source
        ))

    conn.commit()
    conn.close()

    _LOOKUP_CACHE.pop((_db_path(False), indicator, indicator_type), None)
    _LOOKUP_CACHE.pop((_db_path(False), indicator, None), None)


def _query_indicator(conn, indicator, indicator_type):
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
    return c.fetchone()


def lookup_indicator(indicator, indicator_type=None):
    """Return stored intelligence for an indicator (the visitor's own
    history first, then the shared public feed)."""

    if not indicator:
        return None

    indicator = str(indicator).strip().lower()
    cache_key = (_db_path(False), indicator, indicator_type)

    if cache_key in _LOOKUP_CACHE:
        return _LOOKUP_CACHE[cache_key]

    result = None
    scopes = (False, True) if MULTIUSER else (False,)
    for shared in scopes:
        conn = get_connection(shared=shared)
        try:
            result = _query_indicator(conn, indicator, indicator_type)
        finally:
            conn.close()
        if result:
            break

    _trim_caches()
    _LOOKUP_CACHE[cache_key] = result

    return result


def check_history(ip):
    """Return previous attack count and highest observed score."""
    if not ip or ip == "Unknown":
        return (0, 0)

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
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM feedback")

    count = c.fetchone()[0]

    conn.close()

    return count


def import_urlhaus_recent(auth_key, limit=5000, min_interval_minutes=5):
    """
    Import recent URLhaus malware URLs into the shared threat memory.

    The feed is only fetched when the last sync is older than the
    configured minimum interval.
    """

    if not auth_key:
        return {
            "status": "missing_key",
            "imported": 0,
            "message": "URLhaus Auth-Key not configured."
        }

    conn = get_connection(shared=True)
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

    conn = get_connection(shared=True)
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