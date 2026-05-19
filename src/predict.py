import os
import joblib
import tldextract
from scipy.sparse import hstack

from features import extract_features
from nlp_features import clean_url_text


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "model")

LEXICAL_MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
NLP_MODEL_PATH = os.path.join(MODEL_DIR, "nlp_model.pkl")
HYBRID_MODEL_PATH = os.path.join(MODEL_DIR, "hybrid_model.pkl")

lexical_model = joblib.load(LEXICAL_MODEL_PATH)
nlp_vectorizer = joblib.load(NLP_MODEL_PATH)
hybrid_model = joblib.load(HYBRID_MODEL_PATH)


TRUSTED_DOMAINS = [
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


def get_domain(url):
    extracted = tldextract.extract(url.lower())

    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain

    root_domain = f"{domain}.{suffix}" if suffix else domain

    full_domain = ".".join(
        part for part in [subdomain, domain, suffix] if part
    )

    return root_domain, full_domain


def is_trusted_domain(url):
    root_domain, full_domain = get_domain(url)

    return (
        root_domain in TRUSTED_DOMAINS
        or full_domain in TRUSTED_DOMAINS
    )


def get_reasons(url):
    features = extract_features(url)
    reasons = []

    trusted = is_trusted_domain(url)

    if features[12] == 0:
        reasons.append("No HTTPS found")

    if features[14] == 1 and not trusted:
        reasons.append("Suspicious keyword found")

    if features[15] == 1:
        reasons.append("IP address used in URL")

    if features[16] == 1:
        reasons.append("Shortened URL detected")

    if features[17] == 1:
        reasons.append("Suspicious domain extension found")

    if features[0] > 75 and not trusted:
        reasons.append("URL is too long")

    if features[4] >= 2 and not trusted:
        reasons.append("Too many hyphens")

    if features[3] > 4 and not trusted:
        reasons.append("Too many dots/subdomains")

    if features[5] > 6 and not trusted:
        reasons.append("Too many slashes")

    if features[10] >= 15 and not trusted:
        reasons.append("Many digits found in URL")

    if features[13] == 1:
        reasons.append("@ symbol found in URL")

    if features[18] == 1 and not trusted:
        reasons.append("URL contains query parameters")

    if features[19] >= 3 and not trusted:
        reasons.append("Too many subdomains")

    if features[20] == 1 and not trusted:
        reasons.append("Hyphen found in domain name")

    if features[21] == 1 and not trusted:
        reasons.append("Digit found in domain name")

    if trusted:
        reasons.append("Trusted official domain detected")

    if not reasons:
        reasons.append("No major suspicious pattern found")

    return reasons


def get_model_probability(model, features):
    try:
        probability = model.predict_proba(features)[0]
        return probability[1], max(probability)

    except Exception:
        prediction = model.predict(features)[0]
        risk = 0.80 if prediction == 1 else 0.20
        confidence = 0.90
        return risk, confidence


def predict_url(url):
    url = url.strip()

    features = extract_features(url)
    lexical_input = [features]

    cleaned_url = clean_url_text(url)
    nlp_input = nlp_vectorizer.transform([cleaned_url])

    hybrid_input = hstack([lexical_input, nlp_input])

    lexical_risk, lexical_confidence = get_model_probability(
        lexical_model,
        lexical_input
    )

    hybrid_risk, hybrid_confidence = get_model_probability(
        hybrid_model,
        hybrid_input
    )

    # 70% lexical model + 30% NLP hybrid model
    final_risk = (0.70 * lexical_risk) + (0.30 * hybrid_risk)

    reasons = get_reasons(url)
    trusted = is_trusted_domain(url)

    strong_reasons = [
        "No HTTPS found",
        "Suspicious keyword found",
        "Suspicious domain extension found",
        "IP address used in URL",
        "Shortened URL detected",
        "@ symbol found in URL"
    ]

    strong_reason_count = sum(reason in reasons for reason in strong_reasons)

    # Trusted domain false-positive control
    if trusted:
        is_https = features[12] == 1
        has_ip = features[15] == 1
        has_short_url = features[16] == 1
        has_at_symbol = features[13] == 1

        if is_https and not has_ip and not has_short_url and not has_at_symbol:
            final_risk = min(final_risk, 0.18)

    # If no suspicious pattern found, reduce false positives
    if reasons == ["No major suspicious pattern found"]:
        final_risk = final_risk * 0.45

    # Strong phishing indicators increase risk
    if not trusted:
        if strong_reason_count >= 2:
            final_risk = min(final_risk + 0.15, 1.0)

        if strong_reason_count >= 3:
            final_risk = min(final_risk + 0.10, 1.0)

    risk_score = int(final_risk * 100)

    confidence = round(
        max(lexical_confidence, hybrid_confidence) * 100,
        2
    )

    if risk_score >= 70:
        result = "Phishing/Fraud URL"
    elif risk_score >= 35:
        result = "Suspicious URL"
    else:
        result = "Safe URL"

    return result, risk_score, reasons, confidence