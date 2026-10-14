"""Small standard-library HTTP wrapper for fixed external API integrations.

Every request must use HTTPS and an exact hostname allowlist. Redirects are
followed only when they remain on HTTPS and on the same allowlist.
"""

from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


def _normalized_hosts(allowed_hosts):
    hosts = frozenset(str(host).rstrip(".").lower() for host in allowed_hosts)
    if not hosts or any(not host for host in hosts):
        raise ValueError("at least one valid allowed hostname is required")
    return hosts


def _validate_url(url, allowed_hosts):
    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("invalid HTTPS URL") from exc

    if (
        parsed.scheme.lower() != "https"
        or hostname not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
    ):
        raise ValueError("URL is outside the HTTPS host allowlist")


class _AllowlistedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, allowed_hosts):
        super().__init__()
        self._allowed_hosts = _normalized_hosts(allowed_hosts)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            _validate_url(newurl, self._allowed_hosts)
        except ValueError:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_https(request, *, allowed_hosts, timeout):
    """Open a request only on an allowlisted HTTPS origin.

    ``request`` may be a urllib ``Request`` or URL string. Redirects to a
    different host, HTTP, userinfo URLs, and nonstandard ports are rejected.
    """
    hosts = _normalized_hosts(allowed_hosts)
    url = request.full_url if isinstance(request, Request) else request
    _validate_url(url, hosts)
    opener = build_opener(_AllowlistedRedirectHandler(hosts))
    return opener.open(request, timeout=timeout)
