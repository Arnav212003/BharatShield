import json
import os
import re
from urllib.parse import parse_qsl

from .features import SUSPICIOUS_WORDS, has_suspicious_tld
from .url_utils import (
    domain_parts,
    get_explicit_scheme,
    get_hostname,
    host_matches,
    is_ip_address,
    registered_domain,
    split_url,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAIN_LIST_FILE = os.path.join(BASE_DIR, "config", "trusted_domains.json")

# default cutoffs, training writes the validated ones to model_config.json
SAFE_CUTOFF = 0.50
PHISHING_CUTOFF = 0.80
TRUSTED_MAX_RISK = 0.20

# Fixed rule weights. They are not learned, so each one is kept small and
# only used for signals the URL model cannot see well on its own.
RULE_POINTS = {
    "brand_impersonation": 0.30,
    "ip_address": 0.25,
    "at_symbol": 0.25,
    "punycode": 0.15,
    "redirect": 0.15,
}

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
    "t.ly",
    "s.id",
]

REDIRECT_KEYS = {
    "url",
    "u",
    "q",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "continue",
    "dest",
    "destination",
    "goto",
    "next",
    "target",
    "link",
}

# digits that phishers use in place of letters, g00gle -> google
LOOKALIKE_DIGITS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"})


def load_domain_lists(path=DOMAIN_LIST_FILE):
    with open(path, "r", encoding="utf-8") as file:
        saved = json.load(file)

    def clean(values):
        return sorted({str(value).lower().strip(".") for value in values})

    return {
        "trusted_roots": clean(saved.get("trusted_roots", [])),
        "trusted_suffixes": clean(saved.get("trusted_suffixes", [])),
        "user_content_roots": clean(saved.get("user_content_roots", [])),
        "brands": {
            brand.lower(): clean(roots)
            for brand, roots in saved.get("brands", {}).items()
        },
    }


DOMAIN_LISTS = load_domain_lists()
TRUSTED_ROOTS = DOMAIN_LISTS["trusted_roots"]
TRUSTED_SUFFIXES = DOMAIN_LISTS["trusted_suffixes"]
USER_CONTENT_ROOTS = DOMAIN_LISTS["user_content_roots"]
BRANDS = DOMAIN_LISTS["brands"]


def get_user_content_root(hostname):
    # tenant.github.io and also sites.google.com/view/anything
    for root in USER_CONTENT_ROOTS:
        if host_matches(hostname, root):
            return root

    return None


def is_shortener(hostname):
    return registered_domain(hostname) in SHORTENERS


def has_userinfo(url):
    # http://paypal.com@evil.com opens evil.com, the part before @ is a trick
    parts = split_url(url)
    return bool(parts and "@" in parts.netloc)


def get_redirect_target(url):
    """Return the other website a link sends you to, if any."""
    parts = split_url(url)

    if parts is None:
        return None

    own_root = registered_domain(get_hostname(url))

    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        value = value.strip().lower()
        looks_like_link = value.startswith(("http://", "https://", "//"))

        if not looks_like_link and key.lower() in REDIRECT_KEYS:
            # bare "evil.com/login" style values on a redirect key
            looks_like_link = bool(re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+(/|$)", value))

        if not looks_like_link:
            continue

        target_host = get_hostname(value)

        if target_host and registered_domain(target_host) != own_root:
            return target_host

    return None


def get_trusted_match(url):
    """Which trusted list the URL matches, or None.

    Links on free hosting, redirects, IP hosts and @ tricks never count
    as trusted, even when they start with a trusted name.
    """
    hostname = get_hostname(url)

    if (
        not hostname
        or is_ip_address(hostname)
        or has_userinfo(url)
        or get_user_content_root(hostname)
        or get_redirect_target(url)
    ):
        return None

    if registered_domain(hostname) in TRUSTED_ROOTS:
        return "trusted_root"

    for suffix in TRUSTED_SUFFIXES:
        if host_matches(hostname, suffix):
            return "trusted_suffix"

    return None


def brand_in_label(label, brand):
    # short names like sbi or pnb must be a whole word, longer ones can
    # start a word too (hdfcbank-kyc, paytmreward)
    for token in re.split(r"[-_]", label):
        if token == brand or (len(brand) >= 4 and token.startswith(brand)):
            return True

    return False


def find_impersonated_brand(url):
    hostname = get_hostname(url)

    if not hostname or get_trusted_match(url):
        return None

    root = registered_domain(hostname)
    parts = domain_parts(hostname)
    user_root = get_user_content_root(hostname)

    if user_root:
        # only look at the tenant part, not at "github" in github.io
        labels = hostname[: -len(user_root) - 1].split(".")
    elif parts.suffix:
        labels = hostname[: -len(parts.suffix) - 1].split(".")
    else:
        labels = hostname.split(".")

    for brand, official_roots in BRANDS.items():
        # amazon.ae or applecash.apple belong to the brand itself
        if root in official_roots or (not user_root and brand in (parts.domain, parts.suffix)):
            continue

        for label in labels:
            if brand_in_label(label, brand):
                return brand

            lookalike = label.translate(LOOKALIKE_DIGITS)

            if len(brand) >= 5 and lookalike != label and brand_in_label(lookalike, brand):
                return brand

    return None


def found_keywords(url):
    text = url.lower()
    words = set(re.split(r"[^a-z0-9]+", text))

    return [
        word
        for word in SUSPICIOUS_WORDS
        if (word in words if len(word) <= 3 else word in text)
    ]


def check_url(url):
    """Collect rule results and readable notes for one URL."""
    hostname = get_hostname(url)
    trusted = get_trusted_match(url)
    user_root = get_user_content_root(hostname)

    return {
        "hostname": hostname,
        "trusted_match": trusted,
        "user_content_root": user_root,
        "brand": find_impersonated_brand(url),
        "ip_address": is_ip_address(hostname),
        "at_symbol": has_userinfo(url),
        "punycode": "xn--" in hostname,
        "redirect_target": get_redirect_target(url),
        "shortener": is_shortener(hostname),
        "explicit_scheme": get_explicit_scheme(url),
        "keywords": found_keywords(url),
        "suspicious_tld": has_suspicious_tld(domain_parts(hostname).suffix),
        "subdomain_count": len([p for p in domain_parts(hostname).subdomain.split(".") if p]),
        "url_length": len(url),
    }


def apply_rules(
    ml_risk,
    checks,
    safe_cutoff=SAFE_CUTOFF,
    phishing_cutoff=PHISHING_CUTOFF,
):
    """Combine the model score with the fixed URL rules.

    Returns the final risk (0 to 1) and the list of rules that changed it.
    """
    risk = float(ml_risk)
    applied = []

    rule_hits = {
        "brand_impersonation": bool(checks["brand"]),
        "ip_address": checks["ip_address"],
        "at_symbol": checks["at_symbol"],
        "punycode": checks["punycode"],
        "redirect": bool(checks["redirect_target"]),
    }

    for rule, hit in rule_hits.items():
        if hit:
            risk += RULE_POINTS[rule]
            applied.append(rule)

    risk = min(risk, 1.0)

    if checks["brand"] and risk < safe_cutoff:
        # a bank or brand name on someone else's domain is never "Safe"
        risk = safe_cutoff

    if checks["shortener"] and risk < safe_cutoff:
        # we cannot see where a short link goes, so never call it safe
        risk = safe_cutoff
        applied.append("shortener")

    strong_hit = checks["brand"] or checks["ip_address"] or checks["at_symbol"]

    if checks["shortener"] and not strong_hit and risk >= phishing_cutoff:
        # the model only sees "bit.ly/xyz", not the real site, so a high
        # model score alone is not enough to call it phishing
        risk = phishing_cutoff - 0.01
        applied.append("shortener_cap")

    if checks["user_content_root"] and not checks["brand"] and risk >= phishing_cutoff:
        # free hosting has very few legitimate examples in the training data,
        # so the model alone is not enough to call it phishing
        risk = phishing_cutoff - 0.01
        applied.append("free_hosting_cap")

    if checks["trusted_match"] and risk > TRUSTED_MAX_RISK:
        risk = TRUSTED_MAX_RISK
        applied.append("trusted")

    return max(0.0, risk), applied


def build_reasons(ml_risk, checks, safe_cutoff=SAFE_CUTOFF):
    reasons = []

    if checks["trusted_match"] == "trusted_root":
        reasons.append("Domain is on the trusted list")
    elif checks["trusted_match"] == "trusted_suffix":
        reasons.append("Government or bank-only domain (.gov.in, .nic.in, .bank.in)")

    if checks["brand"]:
        reasons.append(
            f"Uses the name '{checks['brand']}' but is not its official website"
        )

    if checks["ip_address"]:
        reasons.append("IP address used instead of a domain name")

    if checks["at_symbol"]:
        reasons.append("@ symbol hides the real website address")

    if checks["punycode"]:
        reasons.append("Domain uses special (punycode) characters that can look like other letters")

    if checks["redirect_target"]:
        reasons.append(f"Link redirects to another website: {checks['redirect_target']}")

    if checks["shortener"]:
        reasons.append("Shortened link hides the real destination")

    if checks["user_content_root"]:
        reasons.append(
            f"Hosted on a free website platform ({checks['user_content_root']}), "
            "anyone can create a page here"
        )

    if ml_risk >= safe_cutoff and checks["trusted_match"]:
        reasons.append("URL model scored it as risky, but the trusted list marks it as an official site")
    elif ml_risk >= safe_cutoff:
        reasons.append("URL model: pattern is similar to known phishing links")
    else:
        reasons.append("URL model: pattern is similar to normal websites")

    if checks["keywords"]:
        reasons.append("Words often used in phishing: " + ", ".join(checks["keywords"][:5]))

    if checks["suspicious_tld"]:
        reasons.append("Domain ending is common in phishing feeds")

    if checks["subdomain_count"] >= 3:
        reasons.append("Many subdomains in the address")

    if checks["url_length"] > 100:
        reasons.append("Very long URL")

    if checks["explicit_scheme"] == "http":
        reasons.append("Not using HTTPS (connection is not encrypted)")

    return reasons


def risk_to_result(risk, safe_cutoff=SAFE_CUTOFF, phishing_cutoff=PHISHING_CUTOFF):
    if risk >= phishing_cutoff:
        return "Phishing/Fraud URL"

    if risk >= safe_cutoff:
        return "Suspicious URL"

    return "Safe URL"
