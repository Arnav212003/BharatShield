import re
from urllib.parse import urlparse

import tldextract

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "shorturl.at", "rebrand.ly", "tiny.cc", "lnkd.in"
]

SUSPICIOUS_WORDS = [
    "login", "verify", "free", "bank", "secure", "account", "update",
    "confirm", "password", "signin", "payment", "wallet", "reward",
    "bonus", "gift", "otp", "kyc", "limited", "urgent", "claim", "support"
]

SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top",
    "work", "click", "link", "fit", "rest"
]


def has_ip_address(url):
    # check only the host part, otherwise numbers in the path
    # (like /v1.2.3.4/) get wrongly flagged as an IP
    host = url.split("//")[-1].split("/")[0].split("?")[0]
    return 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$", host) else 0


def is_short_url(url):
    ext = tldextract.extract(url.lower())
    domain = ".".join(p for p in [ext.domain, ext.suffix] if p)
    return 1 if domain in SHORTENERS else 0


def has_suspicious_keyword(url):
    url = url.lower()
    return 1 if any(word in url for word in SUSPICIOUS_WORDS) else 0


def has_suspicious_tld(url):
    ext = tldextract.extract(url.lower())
    return 1 if ext.suffix.lower() in SUSPICIOUS_TLDS else 0


def extract_features(url):
    """Extracts 22 lexical features from a URL. The order matters and
    must stay in sync with security_layers.FEATURE_NAMES."""
    url = str(url).strip()
    url_lower = url.lower()

    parsed = urlparse(url_lower)
    ext = tldextract.extract(url_lower)

    domain = ext.domain
    subdomain = ext.subdomain
    suffix = ext.suffix
    full_domain = ".".join(p for p in [subdomain, domain, suffix] if p)

    features = [
        # length based
        len(url_lower),
        len(domain),
        len(full_domain),

        # character counts
        url_lower.count("."),
        url_lower.count("-"),
        url_lower.count("/"),
        url_lower.count("?"),
        url_lower.count("="),
        url_lower.count("@"),
        url_lower.count("%"),
        sum(c.isdigit() for c in url_lower),
        sum(not c.isalnum() for c in url_lower),

        # binary flags
        1 if parsed.scheme == "https" else 0,
        1 if "@" in url_lower else 0,
        has_suspicious_keyword(url_lower),
        has_ip_address(url_lower),
        is_short_url(url_lower),
        has_suspicious_tld(url_lower),
        1 if parsed.query else 0,

        # domain structure
        len(subdomain.split(".")) if subdomain else 0,
        1 if "-" in domain else 0,
        1 if any(c.isdigit() for c in domain) else 0,
    ]

    return features