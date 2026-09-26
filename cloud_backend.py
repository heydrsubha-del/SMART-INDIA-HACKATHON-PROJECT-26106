"""
SIH26106 - Shared "prefer local, fall back to cloud" backend selection.

Used by antivirus_scan.py, nomic_embed.py, and ollama_threat.py so the
same decision logic (and the same env vars) live in exactly one place
instead of being copy-pasted three times and risking drift.

Env vars:
    SIH26106_AI_BACKEND     local / cloud / auto   (default: auto)
    SIH26106_VT_API_KEY     VirusTotal API key      (antivirus_scan.py)
    SIH26106_COHERE_API_KEY Cohere API key           (nomic_embed.py)
    SIH26106_GROQ_API_KEY   Groq API key             (ollama_threat.py)

On "auto" (the default), callers should first run their own fast,
short-timeout local-availability check (clamd_available() / nomic_
available() / an Ollama reachability check) and only call resolve_backend()
to decide whether cloud is allowed as the fallback. This module never
performs the local check itself -- each file already has one that's
specific to its own service.
"""
import os

MODE = "SIH26106_AI_BACKEND"


def get_mode():
    """Raw configured mode: 'local', 'cloud', or 'auto' (default)."""
    value = (os.getenv(MODE) or "auto").strip().lower()
    if value not in ("local", "cloud", "auto"):
        return "auto"
    return value


def get_api_key(env_var):
    """Return the named API key env var, stripped, or None if unset/blank."""
    value = os.getenv(env_var)
    if value is None:
        return None
    value = value.strip()
    return value or None


def resolve_backend(local_available, env_var, service_label):
    """Decide which backend to actually use for one call.

    `local_available` -- result of the caller's own fast local check.
    `env_var`         -- the API key env var this cloud provider needs.
    `service_label`   -- human name for error messages, e.g. "VirusTotal".

    Returns ("local", None) or ("cloud", api_key). Raises BackendError
    when the configured mode can't be satisfied (forced local but local is
    down; forced or fallen-back-to cloud but no API key is set) --
    callers should catch this and turn it into their existing
    {"ok": False, "error": ...} shape, exactly like any other failure.
    """
    mode = get_mode()

    if mode == "local":
        if not local_available:
            raise BackendError(
                f"SIH26106_AI_BACKEND=local but the local service for "
                f"{service_label} is not reachable."
            )
        return "local", None

    if mode == "cloud":
        api_key = get_api_key(env_var)
        if not api_key:
            raise BackendError(
                f"SIH26106_AI_BACKEND=cloud but {env_var} is not set "
                f"(needed for {service_label})."
            )
        return "cloud", api_key

    # auto: prefer local, fall back to cloud only if an API key exists.
    if local_available:
        return "local", None
    api_key = get_api_key(env_var)
    if not api_key:
        raise BackendError(
            f"{service_label}'s local service is unreachable and no "
            f"{env_var} is set for the cloud fallback."
        )
    return "cloud", api_key


class BackendError(Exception):
    """Raised when neither the local service nor the cloud fallback can
    be used given the current mode/env vars. Callers catch this and
    return their own normal fail-soft dict -- this never propagates."""
    pass


def is_usable(local_available, env_var):
    """Non-raising variant of resolve_backend(): True if SOME backend
    (local or cloud) would actually work right now, given the current
    mode/env vars. For UI gates that decide whether to show a live panel
    or a "not available" message -- checking this instead of only the
    local probe is what lets those panels work on a deployment with no
    local services at all."""
    try:
        resolve_backend(local_available, env_var, "")
        return True
    except BackendError:
        return False