"""Central configuration: paths, word lists, and scoring weights.

Every other module imports from here so all the tunable numbers live in one
place. Nothing here touches the network.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
SAMPLE_DIR = os.path.join(BASE_DIR, "samples")

EMAILS_CSV = os.path.join(DATA_DIR, "emails.csv")
MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")
GEO_CACHE = os.path.join(DATA_DIR, "geo_cache.json")
GEOLITE_DB = os.path.join(DATA_DIR, "GeoLite2-City.mmdb")  # optional; used if present

# Brands commonly impersonated in phishing (for look-alike domain detection).
KNOWN_BRANDS = [
    "paypal", "microsoft", "office365", "outlook", "google", "gmail", "apple",
    "icloud", "amazon", "netflix", "facebook", "instagram", "linkedin",
    "hdfc", "sbi", "icici", "axis", "kotak", "paytm", "phonepe",
    "bank", "dhl", "fedex", "irs",
]

# Registrable domains these brands genuinely own. Checked FIRST, so a real
# domain is never reported as its own look-alike. Real products maintain exactly
# this kind of allowlist - heuristics alone produce false positives, and a
# security tool that cries wolf on hdfcbank.com gets switched off in week one.
BRAND_DOMAINS = {
    "paypal.com", "paypalobjects.com",
    "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
    "outlook.com", "live.com", "msn.com", "sharepoint.com", "azure.com",
    "google.com", "googlemail.com", "gmail.com", "youtube.com", "goo.gl",
    "apple.com", "icloud.com", "me.com",
    "amazon.com", "amazon.in", "amazonaws.com", "amazon.co.uk",
    "netflix.com", "facebook.com", "instagram.com", "linkedin.com",
    "hdfcbank.com", "onlinesbi.sbi", "sbi.co.in", "icicibank.com",
    "axisbank.com", "kotak.com", "paytm.com", "phonepe.com",
    "dhl.com", "fedex.com", "irs.gov",
}

# Suffixes that turn a brand-prefixed label into a credential-harvesting lure:
# "appleid" and "paypal-verify" are hostile, "hdfcbank" and "amazonaws" are not.
# Kept deliberately tight - a loose list re-introduces false positives.
LURE_SUFFIXES = {
    "id", "verify", "verification", "login", "signin", "secure", "security",
    "alert", "unlock", "confirm", "recovery", "recover", "reset", "billing",
}

# Visually confusable substitutions used in homoglyph attacks: "paypa1" for
# "paypal", "arnazon" for "amazon" ("rn" reads as "m" at a glance).
HOMOGLYPHS = [
    ("rn", "m"), ("vv", "w"), ("nn", "m"),
    ("1", "l"), ("0", "o"), ("5", "s"), ("3", "e"), ("4", "a"), ("7", "t"),
    ("|", "l"), ("!", "i"), ("$", "s"),
]

# Free mail providers (a "CEO" writing from one of these is a BEC red flag).
FREEMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "protonmail.com", "mail.com", "yandex.com", "gmx.com", "rediffmail.com",
]

# URL shorteners hide the true destination.
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
]

# Words that signal urgency / payment pressure (used by the BEC heuristic).
URGENCY_WORDS = [
    "urgent", "immediately", "asap", "right away", "act now", "final notice",
    "expire", "expires", "suspended", "suspend", "verify", "confirm",
    "unusual activity", "locked", "unauthorized", "time-sensitive", "today",
]
PAYMENT_WORDS = [
    "wire transfer", "wire the", "payment", "invoice", "gift card",
    "gift cards", "bank details", "beneficiary", "remit", "remittance",
    "bitcoin", "crypto", "iban", "swift",
]
EXEC_WORDS = ["ceo", "cfo", "director", "president", "chairman", "managing director"]

# --- Risk scoring -----------------------------------------------------------
# Each signal is a 0..1 factor multiplied by its weight; the weights sum to 100.
WEIGHTS = {
    "ml_phish": 38,        # ML phishing probability
    "auth_fail": 15,       # SPF/DKIM/DMARC failures
    "header_anomaly": 12,  # domain mismatches, display-name spoof
    "suspicious_url": 12,  # shorteners, IP-literal hosts, look-alikes
    "origin_risk": 5,      # Tor / VPN / proxy / hosting origin
    "bec_pattern": 18,     # Business-Email-Compromise impersonation
}

# Verdict bands, checked high-to-low; the first threshold met wins.
RISK_LEVELS = [
    (75, "Critical", "#b71c1c"),
    (55, "High", "#e65100"),
    (30, "Medium", "#f9a825"),
    (0, "Low", "#2e7d32"),
]
