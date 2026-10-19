import ipaddress
import re
from urllib.parse import urlparse

import tldextract

FEATURE_NAMES = [
    "URL Length",
    "Domain Length",
    "Full Domain Length",
    "Dots",
    "Hyphens",
    "Slashes",
    "Question Marks",
    "Equal Symbols",
    "@ Count",
    "Percent Symbols",
    "Digits",
    "Special Characters",
    "HTTPS",
    "Has @ Symbol",
    "Suspicious Keyword",
    "IP Address",
    "Short URL",
    "Suspicious TLD",
    "Has Query",
    "Subdomain Count",
    "Hyphen In Domain",
    "Digit In Domain",
]


# Use tldextract's bundled suffix list so training and prediction do not
# depend on a network request or a changing local cache.
DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


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
    # add a temporary scheme only so urlparse can find the hostname
    if get_explicit_scheme(url):
        return url

    if url.startswith("//"):
        return "https:" + url

    return "https://" + url


def get_explicit_scheme(url):
    url = str(url).lower().strip()
    match = re.match(r"^([a-z][a-z0-9+.-]*):\/\/", url)

    return match.group(1) if match else ""


def parse_url(url):
    try:
        parsed = urlparse(url)
        _ = parsed.hostname
        return parsed
    except ValueError:
        return urlparse("")


def extract_domain_parts(url):
    return DOMAIN_EXTRACTOR(str(url).lower().strip())


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


def validate_url_text(url, max_length=2048):
    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if len(url) > max_length:
        raise ValueError(f"URL cannot be longer than {max_length} characters.")

    if any(char.isspace() for char in url):
        raise ValueError("URL cannot contain spaces.")

    explicit_scheme = get_explicit_scheme(url)

    if explicit_scheme and explicit_scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    scheme_prefix = re.match(r"^([a-z][a-z0-9+.-]*):", url, re.IGNORECASE)

    if (
        scheme_prefix
        and not explicit_scheme
        and "." not in scheme_prefix.group(1)
    ):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    parsed = parse_url(add_scheme(url))
    host = parsed.hostname or ""

    try:
        _ = parsed.port
    except ValueError as error:
        raise ValueError("URL contains an invalid port.") from error

    if not host:
        raise ValueError("URL must contain a valid hostname.")

    if has_ip_address(host):
        return url

    extracted = extract_domain_parts(host)

    if not extracted.domain or not extracted.suffix:
        raise ValueError("URL must contain a valid public domain.")

    return url


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
    # Keep this order in sync with FEATURE_NAMES above.
    url = str(url).strip()
    url_lower = url.lower()
    explicit_scheme = get_explicit_scheme(url_lower)

    full_url = add_scheme(url_lower)

    parsed_url = parse_url(full_url)
    extracted = extract_domain_parts(full_url)

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

        1 if explicit_scheme == "https" else 0,
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


def feature_values_to_dict(features):
    if len(features) != len(FEATURE_NAMES):
        raise ValueError("Feature values do not match the feature names.")

    return dict(zip(FEATURE_NAMES, features, strict=True))
