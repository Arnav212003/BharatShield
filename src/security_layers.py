import json
import os

import tldextract

from features import extract_features


# --------------------------------------------------
# Project paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TRUSTED_DOMAINS_FILE = os.path.join(
    BASE_DIR,
    "config",
    "trusted_domains.json",
)


# --------------------------------------------------
# Feature names
# --------------------------------------------------
# This order must match extract_features() exactly.

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


# --------------------------------------------------
# Risk thresholds
# --------------------------------------------------

SAFE_CUTOFF = 0.35
PHISHING_CUTOFF = 0.70


# --------------------------------------------------
# Risk calibration settings
# --------------------------------------------------

TRUSTED_DOMAIN_MAX_RISK = 0.18

NO_PATTERN_REDUCTION = 0.45

TWO_STRONG_REASON_BONUS = 0.15
THREE_STRONG_REASON_BONUS = 0.10


# --------------------------------------------------
# Default trusted domains
# --------------------------------------------------

DEFAULT_TRUSTED_DOMAINS = [
    "google.com",
    "openai.com",
    "chatgpt.com",
    "github.com",
    "githubusercontent.com",
    "camsonline.com",
    "digital.camsonline.com",
    "newmycams.camsonline.com",
    "jioblackrockamc.com",
    "jiofinance.com",
    "icicibank.com",
    "hdfcbank.com",
    "sbi.co.in",
    "onlinesbi.sbi",
]


def load_trusted_domains():
    """
    Load trusted domains from config/trusted_domains.json.

    If the file does not exist or cannot be read,
    the default trusted-domain list is used.
    """

    if not os.path.exists(TRUSTED_DOMAINS_FILE):
        return DEFAULT_TRUSTED_DOMAINS.copy()

    try:
        with open(TRUSTED_DOMAINS_FILE, "r", encoding="utf-8") as file:
            domains = json.load(file)

        cleaned_domains = []

        for domain in domains:
            if isinstance(domain, str):
                domain = domain.lower().strip()

                if domain:
                    cleaned_domains.append(domain)

        if cleaned_domains:
            return cleaned_domains

    except (OSError, json.JSONDecodeError, TypeError):
        pass

    return DEFAULT_TRUSTED_DOMAINS.copy()


TRUSTED_DOMAINS = load_trusted_domains()


# --------------------------------------------------
# Domain helpers
# --------------------------------------------------

def get_domain(url):
    """
    Return root domain and full domain.

    Example:
    https://login.example.com/page

    root domain -> example.com
    full domain -> login.example.com
    """

    extracted = tldextract.extract(str(url).lower().strip())

    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain

    if suffix:
        root_domain = f"{domain}.{suffix}"
    else:
        root_domain = domain

    parts = [
        part
        for part in [subdomain, domain, suffix]
        if part
    ]

    full_domain = ".".join(parts)

    return root_domain, full_domain


def is_trusted_domain(url):
    """
    Check whether the URL belongs to a trusted official domain.
    """

    root_domain, full_domain = get_domain(url)

    return (
        root_domain in TRUSTED_DOMAINS
        or full_domain in TRUSTED_DOMAINS
    )


# --------------------------------------------------
# Detection reasons
# --------------------------------------------------

def get_reasons_from_features(url, features):
    """
    Create simple human-readable reasons from URL features.
    """

    features = list(features)

    reasons = []

    trusted = is_trusted_domain(url)

    # No HTTPS
    if features[12] == 0:
        reasons.append("No HTTPS found")

    # Suspicious words such as login, verify, OTP, KYC etc.
    if features[14] == 1 and not trusted:
        reasons.append("Suspicious keyword found")

    # IP address instead of normal domain
    if features[15] == 1:
        reasons.append("IP address used in URL")

    # Shortened URL
    if features[16] == 1:
        reasons.append("Shortened URL detected")

    # Suspicious domain extension
    if features[17] == 1:
        reasons.append("Suspicious domain extension found")

    # Very long URL
    if features[0] > 75 and not trusted:
        reasons.append("URL is too long")

    # Too many hyphens
    if features[4] >= 2 and not trusted:
        reasons.append("Too many hyphens")

    # Too many dots
    if features[3] > 4 and not trusted:
        reasons.append("Too many dots/subdomains")

    # Too many slash sections
    if features[5] > 6 and not trusted:
        reasons.append("Too many slashes")

    # Large number of digits
    if features[10] >= 15 and not trusted:
        reasons.append("Many digits found in URL")

    # @ symbol can hide real destination
    if features[13] == 1:
        reasons.append("@ symbol found in URL")

    # Query parameters
    if features[18] == 1 and not trusted:
        reasons.append("URL contains query parameters")

    # Many subdomains
    if features[19] >= 3 and not trusted:
        reasons.append("Too many subdomains")

    # Hyphen inside domain name
    if features[20] == 1 and not trusted:
        reasons.append("Hyphen found in domain name")

    # Digit inside domain name
    if features[21] == 1 and not trusted:
        reasons.append("Digit found in domain name")

    if trusted:
        reasons.append("Trusted official domain detected")

    if not reasons:
        reasons.append("No major suspicious pattern found")

    return reasons


def get_reasons(url):
    """
    Extract URL features and return detection reasons.
    """

    features = extract_features(url)

    return get_reasons_from_features(url, features)


# --------------------------------------------------
# Strong phishing indicators
# --------------------------------------------------

STRONG_REASONS = [
    "No HTTPS found",
    "Suspicious keyword found",
    "Suspicious domain extension found",
    "IP address used in URL",
    "Shortened URL detected",
    "@ symbol found in URL",
]


# --------------------------------------------------
# Risk calibration
# --------------------------------------------------

def apply_confidence_calibration(
    raw_ml_risk,
    features,
    reasons,
    trusted,
):
    """
    Adjust the raw ML risk using simple security rules.

    raw_ml_risk must be between 0 and 1.
    """

    risk = float(raw_ml_risk)

    features = list(features)

    strong_reason_count = 0

    for reason in STRONG_REASONS:
        if reason in reasons:
            strong_reason_count += 1

    # Trusted official domain with no major dangerous patterns
    # should normally remain low risk.
    if trusted:
        clean_trusted_url = (
            features[12] == 1
            and features[13] == 0
            and features[15] == 0
            and features[16] == 0
        )

        if clean_trusted_url:
            risk = min(
                risk,
                TRUSTED_DOMAIN_MAX_RISK,
            )

    # If we cannot find any suspicious pattern,
    # reduce uncertain ML risk.
    if reasons == ["No major suspicious pattern found"]:
        risk *= NO_PATTERN_REDUCTION

    # Multiple strong indicators increase risk.
    if not trusted:

        if strong_reason_count >= 2:
            risk += TWO_STRONG_REASON_BONUS

        if strong_reason_count >= 3:
            risk += THREE_STRONG_REASON_BONUS

    # Keep risk inside 0 to 1.
    risk = max(0.0, min(risk, 1.0))

    return risk


# --------------------------------------------------
# Final result helpers
# --------------------------------------------------

def risk_score_to_result(risk_score):
    """
    Convert a 0-100 risk score into a readable result.
    """

    if risk_score >= PHISHING_CUTOFF * 100:
        return "Phishing/Fraud URL"

    if risk_score >= SAFE_CUTOFF * 100:
        return "Suspicious URL"

    return "Safe URL"


def binary_label_from_risk_score(risk):
    """
    Convert a 0-1 risk value into binary form.

    0 = Safe
    1 = Unsafe

    Suspicious URLs are also treated as unsafe during evaluation.
    """

    if risk >= SAFE_CUTOFF:
        return 1

    return 0