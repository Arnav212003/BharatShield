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

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "model")

# load trained models - this crashes here if the files are missing,
# which app.py handles with its try/except block
lexical_model = joblib.load(os.path.join(MODEL_DIR, "phishing_model.pkl"))
nlp_vectorizer = joblib.load(os.path.join(MODEL_DIR, "nlp_model.pkl"))
hybrid_model = joblib.load(os.path.join(MODEL_DIR, "hybrid_model.pkl"))

# lexical model gets more weight since it runs on interpretable
# features and was more stable during experiments
LEXICAL_WEIGHT = 0.70
HYBRID_WEIGHT = 0.30


def get_model_probability(model, features):
    """Returns both phishing probability and model confidence."""
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(features)[0]
        return proba[1], max(proba)

    # fallback for models without predict_proba support
    pred = model.predict(features)[0]
    return (0.80, 0.90) if pred == 1 else (0.20, 0.90)


def predict_url(url):
    """Runs the full analysis pipeline for a single URL.

    Returns: (result_text, risk_score 0-100, reasons list, confidence %)
    """
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty.")

    # lexical features
    features = extract_features(url)
    lexical_input = pd.DataFrame([features], columns=FEATURE_NAMES)

    # NLP features - must use the same vectorizer that was fit during training
    nlp_input = nlp_vectorizer.transform([clean_url_text(url)])

    # hybrid input = lexical + NLP combined
    hybrid_input = hstack([csr_matrix(lexical_input.values), nlp_input])

    lexical_risk, lexical_conf = get_model_probability(lexical_model, lexical_input)
    hybrid_risk, hybrid_conf = get_model_probability(hybrid_model, hybrid_input)

    raw_ml_risk = (LEXICAL_WEIGHT * lexical_risk) + (HYBRID_WEIGHT * hybrid_risk)

    # rule based layers
    reasons = get_reasons(url)
    trusted = is_trusted_domain(url)

    final_risk = apply_confidence_calibration(
        raw_ml_risk=raw_ml_risk,
        features=features,
        reasons=reasons,
        trusted=trusted
    )

    risk_score = int(final_risk * 100)
    confidence = round(max(lexical_conf, hybrid_conf) * 100, 2)

    return risk_score_to_result(risk_score), risk_score, reasons, confidence