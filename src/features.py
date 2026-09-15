import re
from urllib.parse import urlparse

import tldextract


SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "tiny.cc",
    "lnkd.in",
]


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "free",
    "bank",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "signin",
    "payment",
    "wallet",
    "reward",
    "bonus",
    "gift",
    "otp",
    "kyc",
    "limited",
    "urgent",
    "claim",
    "support",
]


SUSPICIOUS_TLDS = [
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "xyz",
    "top",
    "work",
    "click",
    "link",
    "fit",
    "rest",
]


def has_ip_address(url):
    host = url.split("//")[-1]
    host = host.split("/")[0]
    host = host.split("?")[0]

    pattern = r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"

    return 1 if re.match(pattern, host) else 0


def is_short_url(url):
    extracted = tldextract.extract(url.lower())

    domain_parts = [
        part
        for part in [extracted.domain, extracted.suffix]
        if part
    ]

    root_domain = ".".join(domain_parts)

    return 1 if root_domain in SHORTENERS else 0


def has_suspicious_keyword(url):
    url = url.lower()

    for word in SUSPICIOUS_WORDS:
        if word in url:
            return 1

    return 0


def has_suspicious_tld(url):
    extracted = tldextract.extract(url.lower())
    tld = extracted.suffix.lower()

    return 1 if tld in SUSPICIOUS_TLDS else 0


def extract_features(url):
    """
    Extract lexical features from a URL.

    Important:
    The feature order must remain the same because the trained
    machine-learning model expects these features in this order.
    """

    url = str(url).strip()
    url_lower = url.lower()

    parsed_url = urlparse(url_lower)
    extracted = tldextract.extract(url_lower)

    domain = extracted.domain
    subdomain = extracted.subdomain
    suffix = extracted.suffix

    domain_parts = [
        part
        for part in [subdomain, domain, suffix]
        if part
    ]

    full_domain = ".".join(domain_parts)

    features = [
        # Length features
        len(url_lower),
        len(domain),
        len(full_domain),

        # Character counts
        url_lower.count("."),
        url_lower.count("-"),
        url_lower.count("/"),
        url_lower.count("?"),
        url_lower.count("="),
        url_lower.count("@"),
        url_lower.count("%"),
        sum(char.isdigit() for char in url_lower),
        sum(not char.isalnum() for char in url_lower),

        # URL flags
        1 if parsed_url.scheme == "https" else 0,
        1 if "@" in url_lower else 0,
        has_suspicious_keyword(url_lower),
        has_ip_address(url_lower),
        is_short_url(url_lower),
        has_suspicious_tld(url_lower),
        1 if parsed_url.query else 0,

        # Domain structure
        len(subdomain.split(".")) if subdomain else 0,
        1 if "-" in domain else 0,
        1 if any(char.isdigit() for char in domain) else 0,
    ]

    return features