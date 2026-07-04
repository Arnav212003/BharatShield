import os
import joblib
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from features import extract_features
from nlp_features import clean_url_text

from security_layers import (
    FEATURE_NAMES,
    get_domain,
    is_trusted_domain,
    get_reasons,
    apply_confidence_calibration,
    risk_score_to_result
)


# ----------------------------
# Project paths
# ----------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "model")

LEXICAL_MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
NLP_MODEL_PATH = os.path.join(MODEL_DIR, "nlp_model.pkl")
HYBRID_MODEL_PATH = os.path.join(MODEL_DIR, "hybrid_model.pkl")


# ----------------------------
# Load trained models
# ----------------------------
lexical_model = joblib.load(LEXICAL_MODEL_PATH)
nlp_vectorizer = joblib.load(NLP_MODEL_PATH)
hybrid_model = joblib.load(HYBRID_MODEL_PATH)


# ----------------------------
# Model probability helper
# ----------------------------
def get_model_probability(model, features):
    """
    Returns phishing risk probability and model confidence.
    """

    if hasattr(model, "predict_proba"):
        probability = model.predict_proba(features)[0]
        phishing_risk = probability[1]
        confidence = max(probability)
        return phishing_risk, confidence

    prediction = model.predict(features)[0]

    phishing_risk = 0.80 if prediction == 1 else 0.20
    confidence = 0.90

    return phishing_risk, confidence


# ----------------------------
# Main prediction function
# ----------------------------
def predict_url(url):
    """
    Predicts whether a URL is safe, suspicious, or phishing.

    Flow:
    1. Extract lexical URL features.
    2. Convert cleaned URL text into NLP TF-IDF features.
    3. Get lexical model probability.
    4. Get hybrid model probability.
    5. Calculate raw ML risk.
    6. Apply shared domain reputation and calibration layer.
    7. Return final result, risk score, reasons, and confidence.
    """

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    # Lexical features
    features = extract_features(url)

    lexical_input = pd.DataFrame(
        [features],
        columns=FEATURE_NAMES
    )

    # NLP features
    cleaned_url = clean_url_text(url)
    nlp_input = nlp_vectorizer.transform([cleaned_url])

    # Hybrid input = lexical + NLP
    hybrid_input = hstack([
        csr_matrix(lexical_input.values),
        nlp_input
    ])

    # Raw model probabilities
    lexical_risk, lexical_confidence = get_model_probability(
        lexical_model,
        lexical_input
    )

    hybrid_risk, hybrid_confidence = get_model_probability(
        hybrid_model,
        hybrid_input
    )

    # Raw ML score
    raw_ml_risk = (0.70 * lexical_risk) + (0.30 * hybrid_risk)

    # Shared explanation + reputation + calibration
    reasons = get_reasons(url)
    trusted = is_trusted_domain(url)

    final_risk = apply_confidence_calibration(
        raw_ml_risk=raw_ml_risk,
        features=features,
        reasons=reasons,
        trusted=trusted
    )

    risk_score = int(final_risk * 100)

    confidence = round(
        max(lexical_confidence, hybrid_confidence) * 100,
        2
    )

    result = risk_score_to_result(risk_score)

    return result, risk_score, reasons, confidence