"""
SIH26106 - Semantic origin correlation using local Nomic embeddings.

Uses nomic-embed-text, running locally through Ollama, to turn each
message's origin/routing profile into a vector. That lets us find origins
that behave alike (same infrastructure class, same region, same
anonymising pattern) even when their literal IPs or domains never overlap.

This is intentionally separate from correlate.py, which links cases that
share an IDENTICAL indicator (same IP, same domain). This module finds
cases that are semantically SIMILAR even when no indicator matches at all.

No external AI API key is required. Ollama must be running locally with
the embedding model pulled:

    ollama pull nomic-embed-text

Nothing here is called unless the person opens the "Origin & Route" panel,
and every function fails soft (returns None / {"ok": False, ...} / [])
instead of raising, so a missing model or a stopped Ollama service can
never break the rest of the app.
"""

import datetime
import json
import math

import requests

from tracker import get_connection
from cloud_backend import BackendError, resolve_backend

OLLAMA_BASE = "http://127.0.0.1:11434"
OLLAMA_EMBED_URL = f"{OLLAMA_BASE}/api/embeddings"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE}/api/tags"
NOMIC_MODEL = "nomic-embed-text"

COHERE_API_KEY_VAR = "SIH26106_COHERE_API_KEY"
COHERE_EMBED_URL = "https://api.cohere.com/v1/embed"
COHERE_MODEL = "embed-english-v3.0"

# nomic-embed-text is instruction-prefixed: skipping the task prefix
# measurably degrades embedding quality. We're grouping similar origins
# together (not asymmetric query/document search), so "clustering:" is the
# correct prefix per the model's own usage guidance.
TASK_PREFIX = "clustering: "


def nomic_available(timeout=2):
    """True only when Ollama is reachable AND nomic-embed-text is pulled."""
    try:
        response = requests.get(OLLAMA_TAGS_URL, timeout=timeout)
        response.raise_for_status()
        names = [str(m.get("name", "")) for m in response.json().get("models", [])]
        return any(n.split(":")[0] == NOMIC_MODEL for n in names)
    except Exception:
        return False


def describe_origin(geo):
    """Compact natural-language description of one message's origin and
    routing evidence, suitable for feeding to a text-embedding model."""
    geo = geo or {}
    origin = geo.get("origin", {}) or {}
    hops = geo.get("hops", []) or []
    parts = []

    ip = origin.get("ip")
    if ip:
        parts.append(f"Origin IP {ip}.")

    where = ", ".join(p for p in [origin.get("city"), origin.get("country")] if p)
    if where:
        parts.append(f"Located in {where}.")

    infra = origin.get("infra_label") or origin.get("infra")
    if infra:
        parts.append(f"Infrastructure type: {infra}.")

    isp = origin.get("isp")
    if isp:
        parts.append(f"Network / ISP: {isp}.")

    if geo.get("anonymised"):
        parts.append(
            "This origin uses anonymising infrastructure such as Tor, a VPN, or a proxy."
        )

    countries = geo.get("countries") or []
    if hops:
        if countries:
            parts.append(
                f"Relayed through {len(hops)} hop(s) across: {', '.join(countries)}."
            )
        else:
            parts.append(f"Relayed through {len(hops)} hop(s).")

    if geo.get("summary"):
        parts.append(str(geo["summary"]))

    return " ".join(parts) or "No origin or routing information is available for this message."


def embed_text(text, timeout=60):
    """Return {"ok": True, "embedding": [...]} or {"ok": False, "error": ...}.

    Dispatches to local Ollama/nomic-embed-text (default, unchanged
    behaviour) or Cohere's cloud embed endpoint, per SIH26106_AI_BACKEND
    and Ollama's own reachability -- see cloud_backend.resolve_backend().
    Never raises -- callers can show `error` directly to the user, the same
    pattern ollama_threat.py already uses for the chat model.
    """
    if not text or not text.strip():
        return {"ok": False, "error": "Nothing to embed."}

    try:
        backend, api_key = resolve_backend(
            local_available=nomic_available(),
            env_var=COHERE_API_KEY_VAR,
            service_label="text embedding",
        )
    except BackendError as exc:
        return {"ok": False, "error": str(exc)}

    if backend == "cloud":
        return _embed_text_cohere(text, api_key, timeout=timeout)
    return _embed_text_ollama(text, timeout=timeout)


def _embed_text_ollama(text, timeout=60):
    """Original local Ollama/nomic-embed-text path -- unmoved."""
    try:
        response = requests.post(
            OLLAMA_EMBED_URL,
            json={"model": NOMIC_MODEL, "prompt": TASK_PREFIX + text},
            timeout=timeout,
        )
        response.raise_for_status()
        vector = response.json().get("embedding")
        if not vector:
            return {"ok": False, "error": "Ollama returned an empty embedding."}
        return {"ok": True, "embedding": vector}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": "Ollama is not running. Start Ollama and try again."}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "Embedding request timed out."}
    except requests.exceptions.HTTPError as exc:
        return {
            "ok": False,
            "error": f"Ollama HTTP error: {exc}. Is nomic-embed-text pulled? (ollama pull nomic-embed-text)",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _embed_text_cohere(text, api_key, timeout=60):
    """Cloud fallback: Cohere's embed endpoint.

    Cohere has a native equivalent of the TASK_PREFIX text-prefix trick --
    input_type="clustering" -- so we use that instead of prefixing the
    text ourselves. _cosine() and the SQLite storage are already
    model-agnostic and already safely no-op (0 similarity, not a crash) if
    they ever compare vectors of two different dimensions, which matters
    here since Cohere's vectors are a different size than nomic's.
    """
    try:
        response = requests.post(
            COHERE_EMBED_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": COHERE_MODEL,
                "texts": [text],
                "input_type": "clustering",
            },
            timeout=timeout,
        )
        response.raise_for_status()
        embeddings = response.json().get("embeddings")
        if not embeddings or not embeddings[0]:
            return {"ok": False, "error": "Cohere returned an empty embedding."}
        return {"ok": True, "embedding": embeddings[0]}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": "Could not reach Cohere."}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "Cohere embedding request timed out."}
    except requests.exceptions.HTTPError as exc:
        return {"ok": False, "error": f"Cohere HTTP error: {exc}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _ensure_table():
    """Create our own table in the existing threat_memory.db if needed.

    Deliberately does not touch tracker.py's init_db() or any existing
    table -- this only ever adds a new, independent table.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS origin_embeddings (
            evidence_hash TEXT PRIMARY KEY,
            description TEXT,
            embedding TEXT NOT NULL,
            origin_ip TEXT,
            origin_country TEXT,
            infra_label TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_origin_embedding(evidence_hash, description, embedding,
                           origin_ip="", origin_country="", infra_label=""):
    """Persist (or overwrite) one message's origin embedding."""
    if not evidence_hash or not embedding:
        return
    _ensure_table()
    conn = get_connection()
    c = conn.cursor()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT OR REPLACE INTO origin_embeddings
        (evidence_hash, description, embedding, origin_ip, origin_country, infra_label, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        evidence_hash, description, json.dumps(embedding),
        origin_ip or "", origin_country or "", infra_label or "", now,
    ))
    conn.commit()
    conn.close()


def _cosine(a, b):
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def find_similar_origins(evidence_hash, top_k=5):
    """Most semantically similar previously-embedded origins, excluding this
    message itself. Returns [] if this message (or nothing else) is stored
    yet -- never raises."""
    _ensure_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT embedding FROM origin_embeddings WHERE evidence_hash = ?",
        (evidence_hash,),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return []
    try:
        target_vec = json.loads(row[0])
    except Exception:
        conn.close()
        return []

    c.execute("""
        SELECT evidence_hash, origin_ip, origin_country, infra_label, created_at, embedding
        FROM origin_embeddings WHERE evidence_hash != ?
    """, (evidence_hash,))
    rows = c.fetchall()
    conn.close()

    scored = []
    for eh, ip, country, infra_label, created_at, emb_json in rows:
        try:
            vec = json.loads(emb_json)
        except Exception:
            continue
        scored.append({
            "evidence_hash": eh,
            "ip": ip,
            "country": country,
            "infra_label": infra_label,
            "created_at": created_at,
            "similarity": _cosine(target_vec, vec),
        })

    scored.sort(key=lambda m: m["similarity"], reverse=True)
    return scored[:top_k]