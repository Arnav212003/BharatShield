import ipaddress
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
    "rb.gy",
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


def add_scheme(url):
    # if user did not type http/https, assume https
    if "://" in url:
        return url

    if url.startswith("//"):
        return "https:" + url

    return "https://" + url


def parse_url(url):
    try:
        parsed = urlparse(url)
        parsed.hostname
        return parsed
    except ValueError:
        return urlparse("")


def has_ip_address(host):
    if not host:
        return 0

    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        pass

    # hex (0x7f000001) and decimal (2130706433) style IPs
    if re.fullmatch(r"0x[0-9a-f]+", host):
        return 1

    if re.fullmatch(r"\d{8,10}", host):
        return 1

    return 0


def is_short_url(domain, suffix):
    root_domain = ".".join(part for part in [domain, suffix] if part)

    return 1 if root_domain in SHORTENERS else 0


def has_suspicious_keyword(url):
    tokens = re.split(r"[^a-z0-9]+", url)

    for word in SUSPICIOUS_WORDS:
        if len(word) >= 5:
            if word in url:
                return 1

        # short words only as a full word, so otp does not match hotpot
        elif word in tokens:
            return 1

    return 0


def has_suspicious_tld(suffix):
    last_part = suffix.split(".")[-1]

    return 1 if last_part in SUSPICIOUS_TLDS else 0


def extract_features(url):
    # feature order must stay same as FEATURE_NAMES in security_layers.py
    url = str(url).strip()
    url_lower = url.lower()

    full_url = add_scheme(url_lower)

    parsed_url = parse_url(full_url)
    extracted = tldextract.extract(full_url)

    host = parsed_url.hostname or ""

    domain = extracted.domain
    subdomain = extracted.subdomain
    suffix = extracted.suffix

    domain_parts = [part for part in [subdomain, domain, suffix] if part]
    full_domain = ".".join(domain_parts)

    features = [
        len(url_lower),
        len(domain),
        len(full_domain),

        url_lower.count("."),
        url_lower.count("-"),
        url_lower.count("/"),
        url_lower.count("?"),
        url_lower.count("="),
        url_lower.count("@"),
        url_lower.count("%"),
        sum(char.isdigit() for char in url_lower),
        sum(not char.isalnum() for char in url_lower),

        1 if parsed_url.scheme == "https" else 0,
        1 if "@" in url_lower else 0,
        has_suspicious_keyword(url_lower),
        has_ip_address(host),
        is_short_url(domain, suffix),
        has_suspicious_tld(suffix),
        1 if parsed_url.query else 0,

        len(subdomain.split(".")) if subdomain else 0,
        1 if "-" in domain else 0,
        1 if any(char.isdigit() for char in domain) else 0,
    ]

    return features
