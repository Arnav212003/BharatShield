import os

import joblib
import pandas as pd

from scipy.sparse import csr_matrix, hstack

from features import extract_features
from nlp_features import clean_url_text
from security_layers import (
    FEATURE_NAMES,
    apply_confidence_calibration,
    get_domain,
    get_reasons,
    is_trusted_domain,
    risk_score_to_result,
)


# --------------------------------------------------
# Project paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_DIR = os.path.join(BASE_DIR, "model")


# --------------------------------------------------
# Model paths
# --------------------------------------------------

LEXICAL_MODEL_PATH = os.path.join(
    MODEL_DIR,
    "phishing_model.pkl",
)

NLP_MODEL_PATH = os.path.join(
    MODEL_DIR,
    "nlp_model.pkl",
)

HYBRID_MODEL_PATH = os.path.join(
    MODEL_DIR,
    "hybrid_model.pkl",
)


# --------------------------------------------------
# Load trained models
# --------------------------------------------------

lexical_model = joblib.load(LEXICAL_MODEL_PATH)

nlp_vectorizer = joblib.load(NLP_MODEL_PATH)

hybrid_model = joblib.load(HYBRID_MODEL_PATH)


# --------------------------------------------------
# Model weights
# --------------------------------------------------

LEXICAL_WEIGHT = 0.70
HYBRID_WEIGHT = 0.30


def get_model_probability(model, model_input):
    """
    Return phishing probability and model confidence.

    phishing_probability:
        Probability that the input belongs to phishing class.

    confidence:
        Highest probability predicted by the model.
    """

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(model_input)[0]

        phishing_probability = float(probabilities[1])
        confidence = float(max(probabilities))

        return phishing_probability, confidence

    # Fallback in case a future model does not support predict_proba.
    prediction = int(model.predict(model_input)[0])

    if prediction == 1:
        return 0.80, 0.90

    return 0.20, 0.90


def predict_url(url):
    """
    Run the complete BharatShield URL detection pipeline.

    Returns:
        result
        risk_score
        reasons
        confidence
    """

    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    # --------------------------------------------------
    # Step 1: Lexical URL features
    # --------------------------------------------------

    features = extract_features(url)

    lexical_input = pd.DataFrame(
        [features],
        columns=FEATURE_NAMES,
    )

    # --------------------------------------------------
    # Step 2: NLP TF-IDF features
    # --------------------------------------------------

    cleaned_url = clean_url_text(url)

    nlp_input = nlp_vectorizer.transform(
        [cleaned_url]
    )

    # --------------------------------------------------
    # Step 3: Hybrid features
    # --------------------------------------------------

    lexical_sparse = csr_matrix(
        lexical_input.values
    )

    hybrid_input = hstack(
        [
            lexical_sparse,
            nlp_input,
        ]
    )

    # --------------------------------------------------
    # Step 4: Get model probabilities
    # --------------------------------------------------

    lexical_risk, lexical_confidence = get_model_probability(
        lexical_model,
        lexical_input,
    )

    hybrid_risk, hybrid_confidence = get_model_probability(
        hybrid_model,
        hybrid_input,
    )

    # --------------------------------------------------
    # Step 5: Combine model risks
    # --------------------------------------------------

    raw_ml_risk = (
        LEXICAL_WEIGHT * lexical_risk
        + HYBRID_WEIGHT * hybrid_risk
    )

    # --------------------------------------------------
    # Step 6: Security-rule analysis
    # --------------------------------------------------

    reasons = get_reasons(url)

    trusted = is_trusted_domain(url)

    # --------------------------------------------------
    # Step 7: Risk calibration
    # --------------------------------------------------

    final_risk = apply_confidence_calibration(
        raw_ml_risk=raw_ml_risk,
        features=features,
        reasons=reasons,
        trusted=trusted,
    )

    # Convert 0-1 probability into percentage.
    risk_score = round(
        final_risk * 100
    )

    # Use the stronger confidence from the two models.
    confidence = round(
        max(
            lexical_confidence,
            hybrid_confidence,
        ) * 100,
        2,
    )

    # --------------------------------------------------
    # Step 8: Final readable result
    # --------------------------------------------------

    result = risk_score_to_result(
        risk_score
    )

    return (
        result,
        risk_score,
        reasons,
        confidence,
    )