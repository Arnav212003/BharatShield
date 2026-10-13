import json
import os
import warnings

import joblib
import pandas as pd

from scipy.sparse import csr_matrix, hstack

from features import extract_features
from nlp_features import clean_url_text
from security_layers import (
    FEATURE_NAMES,
    PHISHING_CUTOFF,
    SAFE_CUTOFF,
    apply_confidence_calibration,
    get_reasons_from_features,
    is_trusted_domain,
    risk_score_to_result,
)


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "model")

LEXICAL_MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
NLP_MODEL_PATH = os.path.join(MODEL_DIR, "nlp_model.pkl")
HYBRID_MODEL_PATH = os.path.join(MODEL_DIR, "hybrid_model.pkl")
CONFIG_PATH = os.path.join(MODEL_DIR, "model_config.json")

MAX_URL_LENGTH = 2048


def load_file(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model file missing: {path}. Run src/train.py first.")

    return joblib.load(path)


def load_weights():
    # weights are chosen in train.py on the validation set
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as file:
            config = json.load(file)

        return float(config["lexical_weight"]), float(config["hybrid_weight"])

    except (OSError, ValueError, KeyError, TypeError):
        warnings.warn("model_config.json not found or broken, using 0.5 / 0.5 weights.")
        return 0.5, 0.5


lexical_model = load_file(LEXICAL_MODEL_PATH)
nlp_vectorizer = load_file(NLP_MODEL_PATH)
hybrid_model = load_file(HYBRID_MODEL_PATH)

LEXICAL_WEIGHT, HYBRID_WEIGHT = load_weights()


def get_model_probability(model, model_input):
    probabilities = model.predict_proba(model_input)[0]

    # find the phishing class (1) by label, not by position
    phishing_index = list(model.classes_).index(1)

    return float(probabilities[phishing_index])


def get_confidence(risk_score, lexical_risk, hybrid_risk):
    # not a real probability. it is high when the final score is far from
    # the status cutoffs, and lower when the two models disagree
    distance = min(
        abs(risk_score - SAFE_CUTOFF * 100),
        abs(risk_score - PHISHING_CUTOFF * 100),
        30,
    )

    confidence = 50 + distance * 1.5

    if abs(lexical_risk - hybrid_risk) > 0.4:
        confidence -= 15

    return round(confidence, 2)


def predict_url(url):
    """
    Returns: result, risk_score, reasons, confidence
    """

    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if len(url) > MAX_URL_LENGTH:
        raise ValueError("URL is too long.")

    features = extract_features(url)

    lexical_input = pd.DataFrame([features], columns=FEATURE_NAMES)

    nlp_input = nlp_vectorizer.transform([clean_url_text(url)])

    hybrid_input = hstack(
        [csr_matrix(lexical_input.values), nlp_input]
    ).tocsr()

    lexical_risk = get_model_probability(lexical_model, lexical_input)
    hybrid_risk = get_model_probability(hybrid_model, hybrid_input)

    raw_ml_risk = LEXICAL_WEIGHT * lexical_risk + HYBRID_WEIGHT * hybrid_risk

    reasons = get_reasons_from_features(url, features)
    trusted = is_trusted_domain(url)

    final_risk = apply_confidence_calibration(
        raw_ml_risk=raw_ml_risk,
        features=features,
        reasons=reasons,
        trusted=trusted,
    )

    risk_score = round(final_risk * 100)

    confidence = get_confidence(risk_score, lexical_risk, hybrid_risk)

    result = risk_score_to_result(risk_score)

    return result, risk_score, reasons, confidence
