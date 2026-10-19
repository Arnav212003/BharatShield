import json
import os
import warnings
from functools import lru_cache
from urllib.parse import parse_qs, urlparse

from .features import (
    FEATURE_NAMES,
    add_scheme,
    extract_domain_parts,
    extract_features,
    get_explicit_scheme,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRUSTED_DOMAINS_FILE = os.path.join(BASE_DIR, "config", "trusted_domains.json")


SAFE_CUTOFF = 0.35
PHISHING_CUTOFF = 0.70
TRUSTED_DOMAIN_MAX_RISK = 0.20

DEFAULT_RISK_POLICY = {
    "no_pattern_reduction": 0.45,
    "no_pattern_ml_limit": 0.50,
    "two_reason_bonus": 0.15,
    "three_reason_bonus": 0.10,
}


# companies that own every subdomain, so the whole root domain is trusted
DEFAULT_TRUSTED_DOMAINS = [
    "openai.com",
    "chatgpt.com",
    "camsonline.com",
    "jioblackrockamc.com",
    "jiofinance.com",
    "icicibank.com",
    "hdfcbank.com",
    "sbi.co.in",
    "onlinesbi.sbi",
]

# big platforms where users can also host content. only the exact
# hosts below are trusted for these, never the whole domain
PLATFORM_DOMAINS = [
    "google.com",
    "github.com",
]

TRUSTED_HOSTS = [
    "google.com",
    "www.google.com",
    "accounts.google.com",
    "mail.google.com",
    "myaccount.google.com",
    "support.google.com",
    "github.com",
    "www.github.com",
    "docs.github.com",
]

# anyone can host a page here, so never trust these
USER_CONTENT_HOSTS = [
    "sites.google.com",
    "docs.google.com",
    "drive.google.com",
    "forms.gle",
    "storage.googleapis.com",
    "googleusercontent.com",
    "githubusercontent.com",
    "github.io",
    "web.app",
    "firebaseapp.com",
    "pages.dev",
    "netlify.app",
    "vercel.app",
    "herokuapp.com",
    "onrender.com",
    "glitch.me",
    "blogspot.com",
    "weebly.com",
    "wixsite.com",
    "notion.site",
]

REDIRECT_PATHS = ["/url", "/redirect", "/redirector", "/away", "/out"]

REDIRECT_PATH_PREFIXES = ["/amp/"]

REDIRECT_KEYS = [
    "url",
    "q",
    "u",
    "redirect",
    "redirect_url",
    "continue",
    "dest",
    "goto",
    "next",
]


def load_trusted_domains():
    if not os.path.exists(TRUSTED_DOMAINS_FILE):
        return DEFAULT_TRUSTED_DOMAINS.copy()

    try:
        with open(TRUSTED_DOMAINS_FILE, "r", encoding="utf-8") as file:
            domains = json.load(file)

        cleaned = []

        for domain in domains:
            if isinstance(domain, str):
                domain = domain.lower().strip()

                if domain:
                    cleaned.append(domain)

        if cleaned:
            return cleaned

    except (OSError, json.JSONDecodeError, TypeError) as error:
        warnings.warn(
            f"trusted_domains.json not loaded: {error}",
            stacklevel=2,
        )

    return DEFAULT_TRUSTED_DOMAINS.copy()


TRUSTED_DOMAINS = load_trusted_domains()


@lru_cache(maxsize=2048)
def split_domain(url_text):
    extracted = extract_domain_parts(url_text)
    return extracted.subdomain, extracted.domain, extracted.suffix


def get_domain(url):
    subdomain, domain, suffix = split_domain(str(url).lower().strip())

    if suffix:
        root_domain = f"{domain}.{suffix}"
    else:
        root_domain = domain

    parts = [part for part in [subdomain, domain, suffix] if part]
    full_domain = ".".join(parts)

    return root_domain, full_domain


def parse_with_scheme(url):
    url = str(url).lower().strip()
    url = add_scheme(url)

    try:
        return urlparse(url)
    except ValueError:
        return None


def get_hostname(url):
    parsed = parse_with_scheme(url)

    if parsed is None:
        return ""

    try:
        return parsed.hostname or ""
    except ValueError:
        return ""


def is_user_content_host(url):
    hostname = get_hostname(url)

    for host in USER_CONTENT_HOSTS:
        if hostname == host or hostname.endswith("." + host):
            return True

    return False


def is_redirect_link(url):
    # true when the link sends the user to some other website
    parsed = parse_with_scheme(url)

    if parsed is None:
        return False

    path = parsed.path.rstrip("/")

    if path in REDIRECT_PATHS or any(
        parsed.path.startswith(prefix) for prefix in REDIRECT_PATH_PREFIXES
    ):
        # on a redirect style path, any domain-like value is suspicious
        for key in REDIRECT_KEYS:
            for value in parse_qs(parsed.query).get(key, []):
                if value.startswith("http") or "." in value:
                    return True

        if parsed.path.startswith("/amp/"):
            return True

    own_root = get_domain(url)[0]

    # on any path, a full link to a different site in the query is a redirect
    for values in parse_qs(parsed.query).values():
        for value in values:
            value = value.lower().strip()

            if value.startswith(("http://", "https://", "//")):
                if get_domain(value)[0] != own_root:
                    return True

    return False


def is_trusted_domain(url):
    if is_user_content_host(url):
        return False

    if is_redirect_link(url):
        return False

    root_domain, full_domain = get_domain(url)

    if root_domain in PLATFORM_DOMAINS:
        return get_hostname(url) in TRUSTED_HOSTS

    return root_domain in TRUSTED_DOMAINS or full_domain in TRUSTED_DOMAINS


REASON_TEXT = {
    "no_https": "No HTTPS found",
    "keyword": "Suspicious keyword found",
    "ip_address": "IP address used in URL",
    "short_url": "Shortened URL detected",
    "suspicious_tld": "Suspicious domain extension found",
    "long_url": "URL is too long",
    "many_slashes": "Too many slashes",
    "many_digits": "Many digits found in URL",
    "at_symbol": "@ symbol found in URL",
    "query": "URL contains query parameters",
    "many_subdomains": "Too many subdomains",
    "hyphen_domain": "Hyphen found in domain name",
    "digit_domain": "Digit found in domain name",
    "trusted_domain": "Trusted official domain detected",
    "no_pattern": "No major suspicious pattern found",
}

STRONG_REASON_CODES = [
    "no_https",
    "keyword",
    "suspicious_tld",
    "ip_address",
    "short_url",
    "at_symbol",
]

STRONG_REASONS = [REASON_TEXT[code] for code in STRONG_REASON_CODES]


def get_reason_codes(url, features):
    f = dict(zip(FEATURE_NAMES, features, strict=True))
    trusted = is_trusted_domain(url)
    explicit_scheme = get_explicit_scheme(url)

    codes = []

    if explicit_scheme and explicit_scheme != "https":
        codes.append("no_https")

    if f["Suspicious Keyword"] == 1 and not trusted:
        codes.append("keyword")

    if f["IP Address"] == 1:
        codes.append("ip_address")

    if f["Short URL"] == 1:
        codes.append("short_url")

    if f["Suspicious TLD"] == 1:
        codes.append("suspicious_tld")

    if f["URL Length"] > 75 and not trusted:
        codes.append("long_url")

    if f["Slashes"] > 6 and not trusted:
        codes.append("many_slashes")

    if f["Digits"] >= 15 and not trusted:
        codes.append("many_digits")

    if f["Has @ Symbol"] == 1:
        codes.append("at_symbol")

    if f["Has Query"] == 1 and not trusted:
        codes.append("query")

    if f["Subdomain Count"] >= 3 and not trusted:
        codes.append("many_subdomains")

    if f["Hyphen In Domain"] == 1 and not trusted:
        codes.append("hyphen_domain")

    if f["Digit In Domain"] == 1 and not trusted:
        codes.append("digit_domain")

    if trusted:
        codes.append("trusted_domain")

    if not codes:
        codes.append("no_pattern")

    return codes


def get_reasons_from_features(url, features):
    codes = get_reason_codes(url, features)
    return [REASON_TEXT[code] for code in codes]


def get_reasons(url):
    features = extract_features(url)
    return get_reasons_from_features(url, features)


def apply_risk_rules(
    raw_ml_risk,
    features,
    reasons,
    trusted,
    policy=None,
    trusted_domain_max_risk=TRUSTED_DOMAIN_MAX_RISK,
):
    if policy is None:
        policy = DEFAULT_RISK_POLICY

    risk = float(raw_ml_risk)
    f = dict(zip(FEATURE_NAMES, features, strict=True))

    strong_reason_count = 0

    for reason in STRONG_REASONS:
        if reason in reasons:
            strong_reason_count += 1

    if trusted:
        clean_trusted_url = (
            REASON_TEXT["no_https"] not in reasons
            and f["Has @ Symbol"] == 0
            and f["IP Address"] == 0
            and f["Short URL"] == 0
        )

        if clean_trusted_url:
            risk = min(risk, trusted_domain_max_risk)

    # reduce only if model is also not sure
    if (
        reasons == [REASON_TEXT["no_pattern"]]
        and risk < policy["no_pattern_ml_limit"]
    ):
        risk *= policy["no_pattern_reduction"]

    if not trusted:
        if strong_reason_count >= 2:
            risk += policy["two_reason_bonus"]

        if strong_reason_count >= 3:
            risk += policy["three_reason_bonus"]

    return max(0.0, min(risk, 1.0))


def risk_score_to_result(
    risk_score,
    safe_cutoff=SAFE_CUTOFF,
    phishing_cutoff=PHISHING_CUTOFF,
):
    if risk_score >= phishing_cutoff * 100:
        return "Phishing/Fraud URL"

    if risk_score >= safe_cutoff * 100:
        return "Suspicious URL"

    return "Safe URL"


def binary_label_from_risk_score(risk, safe_cutoff=SAFE_CUTOFF):
    # suspicious is also counted as unsafe
    if risk >= safe_cutoff:
        return 1

    return 0
