import os
import json

import tldextract

from features import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRUSTED_DOMAINS_PATH = os.path.join(BASE_DIR, "config", "trusted_domains.json")

# same order as the output of extract_features()
FEATURE_NAMES = [
    "URL Length", "Domain Length", "Full Domain Length",
    "Dots", "Hyphens", "Slashes", "Question Marks", "Equal Symbols",
    "@ Count", "Percent Symbols", "Digits", "Special Characters",
    "HTTPS", "Has @ Symbol", "Suspicious Keyword", "IP Address",
    "Short URL", "Suspicious TLD", "Has Query", "Subdomain Count",
    "Hyphen In Domain", "Digit In Domain"
]

# thresholds - risk score on a 0 to 1 scale
SAFE_BINARY_CUTOFF = 0.35
PHISHING_CUTOFF = 0.70

TRUSTED_DOMAIN_MAX_RISK = 0.18
NO_PATTERN_REDUCTION_FACTOR = 0.45
STRONG_REASON_BONUS_TWO = 0.15
STRONG_REASON_BONUS_THREE = 0.10

# fallback list used when the config file is missing
DEFAULT_ALLOWLIST = [
    "google.com", "chatgpt.com", "openai.com",
    "github.com", "githubusercontent.com",
    "camsonline.com", "digital.camsonline.com", "newmycams.camsonline.com",
    "jioblackrockamc.com", "jiofinance.com",
    "icicibank.com", "hdfcbank.com", "sbi.co.in", "onlinesbi.sbi"
]


def load_domain_reputation_allowlist():
    try:
        if os.path.exists(TRUSTED_DOMAINS_PATH):
            with open(TRUSTED_DOMAINS_PATH, "r", encoding="utf-8") as f:
                domains = json.load(f)
            return [d.lower().strip() for d in domains
                    if isinstance(d, str) and d.strip()]
    except Exception:
        # config file is corrupt, fall back to defaults
        pass
    return DEFAULT_ALLOWLIST


DOMAIN_REPUTATION_ALLOWLIST = load_domain_reputation_allowlist()
TRUSTED_DOMAINS = DOMAIN_REPUTATION_ALLOWLIST  # kept for older imports


def get_domain(url):
    """Returns both root domain and full domain.
    e.g. digital.camsonline.com/login -> (camsonline.com, digital.camsonline.com)"""
    ext = tldextract.extract(str(url).lower())
    root = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    full = ".".join(p for p in [ext.subdomain, ext.domain, ext.suffix] if p)
    return root, full


def is_trusted_domain(url):
    root, full = get_domain(url)
    return root in DOMAIN_REPUTATION_ALLOWLIST or full in DOMAIN_REPUTATION_ALLOWLIST


def get_reasons_from_features(url, features):
    """Builds human readable reasons from already extracted feature values.
    Used during training/evaluation to avoid recomputing features."""
    f = list(features)
    reasons = []
    trusted = is_trusted_domain(url)

    if f[12] == 0:
        reasons.append("No HTTPS found")
    if f[14] == 1 and not trusted:
        reasons.append("Suspicious keyword found")
    if f[15] == 1:
        reasons.append("IP address used in URL")
    if f[16] == 1:
        reasons.append("Shortened URL detected")
    if f[17] == 1:
        reasons.append("Suspicious domain extension found")
    if f[0] > 75 and not trusted:
        reasons.append("URL is too long")
    if f[4] >= 2 and not trusted:
        reasons.append("Too many hyphens")
    if f[3] > 4 and not trusted:
        reasons.append("Too many dots/subdomains")
    if f[5] > 6 and not trusted:
        reasons.append("Too many slashes")
    if f[10] >= 15 and not trusted:
        reasons.append("Many digits found in URL")
    if f[13] == 1:
        reasons.append("@ symbol found in URL")
    if f[18] == 1 and not trusted:
        reasons.append("URL contains query parameters")
    if f[19] >= 3 and not trusted:
        reasons.append("Too many subdomains")
    if f[20] == 1 and not trusted:
        reasons.append("Hyphen found in domain name")
    if f[21] == 1 and not trusted:
        reasons.append("Digit found in domain name")

    if trusted:
        reasons.append("Trusted official domain detected")

    if not reasons:
        reasons.append("No major suspicious pattern found")

    return reasons


def get_reasons(url):
    # used during live prediction - works directly from the URL
    return get_reasons_from_features(url, extract_features(url))


STRONG_REASONS = [
    "No HTTPS found",
    "Suspicious keyword found",
    "Suspicious domain extension found",
    "IP address used in URL",
    "Shortened URL detected",
    "@ symbol found in URL"
]


def apply_confidence_calibration(raw_ml_risk, features, reasons, trusted):
    """Safety layer applied on top of the raw ML probability.

    It does three things:
    - reduces false positives for trusted official domains
    - lowers risk when no suspicious pattern is found
    - raises risk when multiple strong phishing indicators appear

    Note: these thresholds are set manually for now. In production
    they should be tuned on a validation set.
    """
    f = list(features)
    risk = raw_ml_risk

    strong_count = sum(r in reasons for r in STRONG_REASONS)

    # trusted domain with no red flags -> cap the risk
    if trusted:
        clean = (f[12] == 1 and f[15] == 0 and f[16] == 0 and f[13] == 0)
        if clean:
            risk = min(risk, TRUSTED_DOMAIN_MAX_RISK)

    if reasons == ["No major suspicious pattern found"]:
        risk = risk * NO_PATTERN_REDUCTION_FACTOR

    if not trusted:
        if strong_count >= 2:
            risk = min(risk + STRONG_REASON_BONUS_TWO, 1.0)
        if strong_count >= 3:
            risk = min(risk + STRONG_REASON_BONUS_THREE, 1.0)

    return max(0.0, min(risk, 1.0))


def risk_score_to_result(risk_score):
    # risk_score arrives on a 0-100 scale here (from predict.py)
    if risk_score >= PHISHING_CUTOFF * 100:
        return "Phishing/Fraud URL"
    if risk_score >= SAFE_BINARY_CUTOFF * 100:
        return "Suspicious URL"
    return "Safe URL"


def binary_label_from_risk_score(final_risk):
    """Converts final risk (0-1 scale) into a binary label for evaluation.

    Both Suspicious and Phishing are treated as 1 (unsafe) because
    in phishing detection a false negative is far more dangerous -
    a suspicious URL should never be reported as fully safe.
    """
    return 1 if final_risk >= SAFE_BINARY_CUTOFF else 0