import os
import json
import tldextract

from features import extract_features


# -----------------------------
# Base paths
# -----------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
TRUSTED_DOMAINS_PATH = os.path.join(CONFIG_DIR, "trusted_domains.json")


# -----------------------------
# Shared feature names
# -----------------------------
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
    "Digit In Domain"
]


# -----------------------------
# Shared thresholds
# -----------------------------
SAFE_BINARY_CUTOFF = 0.35
PHISHING_CUTOFF = 0.70

TRUSTED_DOMAIN_MAX_RISK = 0.18
NO_PATTERN_REDUCTION_FACTOR = 0.45
STRONG_REASON_BONUS_TWO = 0.15
STRONG_REASON_BONUS_THREE = 0.10


# -----------------------------
# Domain reputation config
# -----------------------------
DEFAULT_DOMAIN_REPUTATION_ALLOWLIST = [
    "google.com",
    "chatgpt.com",
    "openai.com",
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
    "onlinesbi.sbi"
]


def load_domain_reputation_allowlist():
    """
    Loads domain reputation allowlist from config/trusted_domains.json.

    If the config file is missing or invalid, the system falls back
    to the default built-in allowlist.

    This keeps training/evaluation and live prediction consistent.
    """

    try:
        if os.path.exists(TRUSTED_DOMAINS_PATH):
            with open(TRUSTED_DOMAINS_PATH, "r", encoding="utf-8") as file:
                domains = json.load(file)

            return [
                domain.lower().strip()
                for domain in domains
                if isinstance(domain, str) and domain.strip()
            ]

    except Exception:
        pass

    return DEFAULT_DOMAIN_REPUTATION_ALLOWLIST


DOMAIN_REPUTATION_ALLOWLIST = load_domain_reputation_allowlist()

# Backward-compatible alias
TRUSTED_DOMAINS = DOMAIN_REPUTATION_ALLOWLIST


# -----------------------------
# Domain helpers
# -----------------------------
def get_domain(url):
    """
    Extracts root domain and full domain from a URL.

    Example:
    URL: https://digital.camsonline.com/login

    root_domain = camsonline.com
    full_domain = digital.camsonline.com
    """

    extracted = tldextract.extract(str(url).lower())

    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain

    root_domain = f"{domain}.{suffix}" if suffix else domain

    full_domain = ".".join(
        part for part in [subdomain, domain, suffix] if part
    )

    return root_domain, full_domain


def is_trusted_domain(url):
    """
    Checks whether the URL belongs to the domain reputation allowlist.
    """

    root_domain, full_domain = get_domain(url)

    return (
        root_domain in DOMAIN_REPUTATION_ALLOWLIST
        or full_domain in DOMAIN_REPUTATION_ALLOWLIST
    )


# -----------------------------
# Explainability layer
# -----------------------------
def get_reasons_from_features(url, features):
    """
    Generates explainable detection reasons using already extracted features.
    This is used during training/evaluation to avoid recalculating features.
    """

    feature_values = list(features)
    reasons = []

    trusted = is_trusted_domain(url)

    if feature_values[12] == 0:
        reasons.append("No HTTPS found")

    if feature_values[14] == 1 and not trusted:
        reasons.append("Suspicious keyword found")

    if feature_values[15] == 1:
        reasons.append("IP address used in URL")

    if feature_values[16] == 1:
        reasons.append("Shortened URL detected")

    if feature_values[17] == 1:
        reasons.append("Suspicious domain extension found")

    if feature_values[0] > 75 and not trusted:
        reasons.append("URL is too long")

    if feature_values[4] >= 2 and not trusted:
        reasons.append("Too many hyphens")

    if feature_values[3] > 4 and not trusted:
        reasons.append("Too many dots/subdomains")

    if feature_values[5] > 6 and not trusted:
        reasons.append("Too many slashes")

    if feature_values[10] >= 15 and not trusted:
        reasons.append("Many digits found in URL")

    if feature_values[13] == 1:
        reasons.append("@ symbol found in URL")

    if feature_values[18] == 1 and not trusted:
        reasons.append("URL contains query parameters")

    if feature_values[19] >= 3 and not trusted:
        reasons.append("Too many subdomains")

    if feature_values[20] == 1 and not trusted:
        reasons.append("Hyphen found in domain name")

    if feature_values[21] == 1 and not trusted:
        reasons.append("Digit found in domain name")

    if trusted:
        reasons.append("Trusted official domain detected")

    if not reasons:
        reasons.append("No major suspicious pattern found")

    return reasons


def get_reasons(url):
    """
    Generates explainable reasons directly from URL.
    This is used during live prediction.
    """

    features = extract_features(url)
    return get_reasons_from_features(url, features)


# -----------------------------
# Calibration layer
# -----------------------------
def apply_confidence_calibration(raw_ml_risk, features, reasons, trusted):
    """
    Applies confidence calibration on top of raw ML probability.

    This is not a replacement for the ML model.
    It is a separate user-facing safety layer.

    Purpose:
    1. Reduce false positives for official trusted domains.
    2. Reduce risk when no suspicious pattern is found.
    3. Increase risk when multiple strong phishing indicators appear.

    In a production version, these thresholds should be tuned
    using a validation dataset.
    """

    feature_values = list(features)
    final_risk = raw_ml_risk

    strong_reasons = [
        "No HTTPS found",
        "Suspicious keyword found",
        "Suspicious domain extension found",
        "IP address used in URL",
        "Shortened URL detected",
        "@ symbol found in URL"
    ]

    strong_reason_count = sum(reason in reasons for reason in strong_reasons)

    # Domain reputation false-positive control
    if trusted:
        is_https = feature_values[12] == 1
        has_ip = feature_values[15] == 1
        has_short_url = feature_values[16] == 1
        has_at_symbol = feature_values[13] == 1

        if is_https and not has_ip and not has_short_url and not has_at_symbol:
            final_risk = min(final_risk, TRUSTED_DOMAIN_MAX_RISK)

    # Low-risk calibration
    if reasons == ["No major suspicious pattern found"]:
        final_risk = final_risk * NO_PATTERN_REDUCTION_FACTOR

    # High-risk calibration
    if not trusted:
        if strong_reason_count >= 2:
            final_risk = min(final_risk + STRONG_REASON_BONUS_TWO, 1.0)

        if strong_reason_count >= 3:
            final_risk = min(final_risk + STRONG_REASON_BONUS_THREE, 1.0)

    return max(0.0, min(final_risk, 1.0))


# -----------------------------
# Shared decision helpers
# -----------------------------
def risk_score_to_result(risk_score):
    if risk_score >= int(PHISHING_CUTOFF * 100):
        return "Phishing/Fraud URL"

    if risk_score >= int(SAFE_BINARY_CUTOFF * 100):
        return "Suspicious URL"

    return "Safe URL"


def binary_label_from_risk_score(risk_score):
    """
    Converts final risk score into binary evaluation label.

    App has three classes:
    Safe, Suspicious, Phishing.

    For binary safety evaluation, Suspicious and Phishing are treated
    as positive/unsafe class because the system should avoid false negatives.
    A suspicious URL should not be treated as fully safe.
    """

    return 1 if risk_score >= SAFE_BINARY_CUTOFF else 0