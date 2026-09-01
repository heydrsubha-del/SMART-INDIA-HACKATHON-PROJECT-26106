import json
import os
import requests 
import config as C
from functools import lru_cache

INFRA_RISK = {"tor": 1.0, "proxy": 0.85, "vpn": 0.8, "hosting": 0.6, "residential": 0.2, "corporate": 0.1, "unknown": 0.35}
INFRA_LABEL = {"tor": "Tor exit node", "proxy": "Anonymising proxy", "vpn": "VPN exit node", "hosting": "Hosting / VPS provider", "residential": "Residential ISP", "corporate": "Corporate mail infrastructure", "unknown": "Unattributed"}
_ANON_HINTS = (("tor", "tor"), ("exit relay", "tor"), ("vpn", "vpn"), ("proxy", "proxy"), ("hosting", "hosting"), ("vps", "hosting"), ("datacenter", "hosting"), ("data center", "hosting"))

_cache = None
_geo_http = requests.Session()

def _load_cache():
    global _cache
    if _cache is None:
        try:
            with open(C.GEO_CACHE, encoding="utf-8") as fh:
                _cache = json.load(fh)
        except Exception:
            _cache = {}
    return _cache

def _unknown(ip):
    return {"ip": ip, "city": "", "region": "", "country": "Unknown", "country_code": "", "lat": None, "lon": None, "asn": "", "isp": "", "infra": "unknown", "note": "No geolocation data available for this IP.", "source": "unresolved_cache"}

@lru_cache(maxsize=4096)
def geolocate(ip):

    if not ip: return _unknown(ip)
    
    # 1. LIVE INTERNET API (ip-api.com)
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as"
        response = _geo_http.get(
    url,
    timeout=5
)
        if response.status_code == 200 and response.json().get("status") == "success":
            data = response.json()
            isp = (data.get("isp", "") + " " + data.get("org", "")).lower()
            infra = next((k for h, k in _ANON_HINTS if h in isp), "unknown")
            return dict({
    "ip": ip,
    "city": data.get("city", ""),
    "region": data.get("regionName", ""),
    "country": data.get("country", "Unknown"),
    "country_code": data.get("countryCode", ""),
    "lat": data.get("lat"),
    "lon": data.get("lon"),
    "asn": str(data.get("as", "")),
    "isp": data.get("isp", ""),
    "infra": infra,
    "note": "Resolved live via IP-API",
    "source": "Live API",
})
    except Exception:
        pass

    # 2. OFFLINE CACHE FALLBACK
    hit = _load_cache().get(ip)
    if hit:
        record = dict(hit)
        record["ip"] = ip
        record.setdefault("infra", "unknown")
        record["source"] = "local cache"
        return record

    return _unknown(ip)

def trace(parsed):
    hops = []
    for index, hop in enumerate(parsed.get("hops", [])):
        for ip in hop["ips"]:
            record = geolocate(ip)
            record["hop_index"] = index + 1
            record["raw"] = hop["raw"]
            record["infra_label"] = INFRA_LABEL.get(record["infra"], "Unattributed")
            hops.append(record)

    seen, ordered = set(), []
    for hop in hops:
        if hop["ip"] in seen: continue
        seen.add(hop["ip"])
        ordered.append(hop)

    origin = ordered[0] if ordered else _unknown(parsed.get("origin_ip", ""))
    origin.setdefault("infra_label", INFRA_LABEL.get(origin.get("infra", "unknown")))
    origin_risk = INFRA_RISK.get(origin.get("infra", "unknown"), 0.35)

    countries = []
    for hop in ordered:
        if hop["country"] and hop["country"] not in countries:
            countries.append(hop["country"])

    anonymised = origin.get("infra") in ("tor", "vpn", "proxy")
    if origin.get("lat") is None:
        summary = "Origin IP could not be geolocated."
    else:
        where = ", ".join(p for p in [origin.get("city"), origin.get("country")] if p)
        summary = "Earliest external hop {} traced to {} ({}).".format(
            origin["ip"], where, origin["infra_label"])
        if anonymised:
            summary += (" This is anonymising infrastructure, so the physical location shown is the relay - not the operator.")

    return {"hops": ordered, "origin": origin, "origin_risk": origin_risk, "countries": countries, "anonymised": anonymised, "summary": summary}