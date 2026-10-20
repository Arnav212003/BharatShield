import json
import os

import joblib
import pandas as pd
from scipy.sparse import csr_matrix, hstack

from .features import FEATURE_NAMES, extract_features_from_key, feature_values_to_dict
from .security_layers import (
    PHISHING_CUTOFF,
    SAFE_CUTOFF,
    apply_rules,
    build_reasons,
    check_url,
    risk_to_result,
)
from .url_utils import canonical_key, registered_domain, validate_url_text

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.abspath(
    os.getenv("BHARATSHIELD_MODEL_DIR", os.path.join(BASE_DIR, "model"))
)

LEXICAL_MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
NLP_MODEL_PATH = os.path.join(MODEL_DIR, "nlp_model.pkl")
HYBRID_MODEL_PATH = os.path.join(MODEL_DIR, "hybrid_model.pkl")
CONFIG_PATH = os.path.join(MODEL_DIR, "model_config.json")
METADATA_PATH = os.path.join(MODEL_DIR, "training_metadata.json")

MAX_URL_LENGTH = 2048


def load_file(path):
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Model file missing: {path}. Run python -m src.train_model first."
        )

    return joblib.load(path)


def load_model_config(path=CONFIG_PATH):
    settings = {
        "lexical_weight": 0.5,
        "hybrid_weight": 0.5,
        "safe_cutoff": SAFE_CUTOFF,
        "phishing_cutoff": PHISHING_CUTOFF,
    }

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as file:
            saved = json.load(file)

        for key in settings:
            if key in saved:
                settings[key] = float(saved[key])

    if abs(settings["lexical_weight"] + settings["hybrid_weight"] - 1) > 0.001:
        raise ValueError("model weights in model_config.json must add up to 1")

    if not 0 < settings["safe_cutoff"] < settings["phishing_cutoff"] <= 1:
        raise ValueError("cutoffs in model_config.json are not in order")

    return settings


def load_training_metadata():
    try:
        with open(METADATA_PATH, "r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}


lexical_model = load_file(LEXICAL_MODEL_PATH)
nlp_vectorizer = load_file(NLP_MODEL_PATH)
hybrid_model = load_file(HYBRID_MODEL_PATH)

MODEL_CONFIG = load_model_config()
TRAINING_METADATA = load_training_metadata()

LEXICAL_WEIGHT = MODEL_CONFIG["lexical_weight"]
HYBRID_WEIGHT = MODEL_CONFIG["hybrid_weight"]
SAFE_DECISION_CUTOFF = MODEL_CONFIG["safe_cutoff"]
PHISHING_DECISION_CUTOFF = MODEL_CONFIG["phishing_cutoff"]


def phishing_column(model):
    # find the phishing class (1) by label, not by position
    return list(model.classes_).index(1)


def ml_scores(urls):
    """Return (gradient boosting, logistic regression, blended) phishing scores."""
    keys = [canonical_key(url) for url in urls]
    lexical_input = pd.DataFrame(
        [extract_features_from_key(key) for key in keys],
        columns=FEATURE_NAMES,
    )
    text_input = nlp_vectorizer.transform(keys)
    hybrid_input = hstack([csr_matrix(lexical_input.values), text_input]).tocsr()

    lexical = lexical_model.predict_proba(lexical_input)[:, phishing_column(lexical_model)]
    hybrid = hybrid_model.predict_proba(hybrid_input)[:, phishing_column(hybrid_model)]
    blended = LEXICAL_WEIGHT * lexical + HYBRID_WEIGHT * hybrid

    return lexical, hybrid, blended, lexical_input


def predict_url_details(url):
    url = validate_url_text(url, max_length=MAX_URL_LENGTH)

    lexical, hybrid, blended, features = ml_scores([url])
    ml_risk = float(blended[0])

    checks = check_url(url)
    final_risk, applied_rules = apply_rules(
        ml_risk,
        checks,
        safe_cutoff=SAFE_DECISION_CUTOFF,
        phishing_cutoff=PHISHING_DECISION_CUTOFF,
    )

    return {
        "url": url,
        "result": risk_to_result(
            final_risk,
            safe_cutoff=SAFE_DECISION_CUTOFF,
            phishing_cutoff=PHISHING_DECISION_CUTOFF,
        ),
        "risk_score": round(final_risk * 100),
        "ml_risk_score": round(ml_risk * 100),
        "reasons": build_reasons(ml_risk, checks, safe_cutoff=SAFE_DECISION_CUTOFF),
        "rules_applied": applied_rules,
        "hostname": checks["hostname"],
        "root_domain": registered_domain(checks["hostname"]),
        "trusted_match": checks["trusted_match"],
        "impersonated_brand": checks["brand"],
        "free_hosting": checks["user_content_root"],
        "explicit_scheme": checks["explicit_scheme"],
        "lexical_risk": round(float(lexical[0]), 6),
        "hybrid_risk": round(float(hybrid[0]), 6),
        "features": feature_values_to_dict(features.iloc[0].tolist()),
    }


def predict_url(url):
    """Short version used by the message scanner: (result, risk_score, reasons)."""
    details = predict_url_details(url)
    return details["result"], details["risk_score"], details["reasons"]


def predict_url_batch(urls):
    """Score many URLs at once (used for evaluation)."""
    urls = [validate_url_text(url, max_length=MAX_URL_LENGTH) for url in urls]
    lexical, hybrid, blended, _ = ml_scores(urls)
    final_scores = []

    for url, ml_risk in zip(urls, blended, strict=True):
        final_risk, _ = apply_rules(
            ml_risk,
            check_url(url),
            safe_cutoff=SAFE_DECISION_CUTOFF,
            phishing_cutoff=PHISHING_DECISION_CUTOFF,
        )
        final_scores.append(final_risk)

    return pd.DataFrame({
        "url": urls,
        "lexical_risk": lexical,
        "hybrid_risk": hybrid,
        "ml_risk": blended,
        "final_risk": final_scores,
    })


def get_model_info():
    return {
        "ready": all(
            model is not None
            for model in [lexical_model, nlp_vectorizer, hybrid_model]
        ),
        "generated_at_utc": TRAINING_METADATA.get("generated_at_utc"),
        "safe_cutoff": SAFE_DECISION_CUTOFF,
        "phishing_cutoff": PHISHING_DECISION_CUTOFF,
    }
