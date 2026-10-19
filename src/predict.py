import json
import os
import warnings

import joblib
import pandas as pd
from scipy.sparse import csr_matrix, hstack

from .features import (
    FEATURE_NAMES,
    extract_features,
    feature_values_to_dict,
    get_explicit_scheme,
    validate_url_text,
)
from .nlp_features import clean_url_text
from .security_layers import (
    DEFAULT_RISK_POLICY,
    PHISHING_CUTOFF,
    SAFE_CUTOFF,
    TRUSTED_DOMAIN_MAX_RISK,
    apply_risk_rules,
    get_domain,
    get_reasons_from_features,
    is_trusted_domain,
    risk_score_to_result,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.abspath(
    os.getenv(
        "BHARATSHIELD_MODEL_DIR",
        os.path.join(BASE_DIR, "model"),
    )
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


def default_model_config():
    return {
        "lexical_weight": 0.5,
        "hybrid_weight": 0.5,
        "safe_cutoff": SAFE_CUTOFF,
        "phishing_cutoff": PHISHING_CUTOFF,
        "trusted_domain_max_risk": TRUSTED_DOMAIN_MAX_RISK,
        "risk_policy": DEFAULT_RISK_POLICY.copy(),
    }


def load_model_config():
    settings = default_model_config()

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as file:
            config = json.load(file)

        settings["lexical_weight"] = float(config["lexical_weight"])
        settings["hybrid_weight"] = float(config["hybrid_weight"])
        settings["safe_cutoff"] = float(
            config.get("safe_cutoff", SAFE_CUTOFF)
        )
        settings["phishing_cutoff"] = float(
            config.get("phishing_cutoff", PHISHING_CUTOFF)
        )
        settings["trusted_domain_max_risk"] = float(
            config.get(
                "trusted_domain_max_risk",
                TRUSTED_DOMAIN_MAX_RISK,
            )
        )

        saved_policy = config.get("risk_policy", {})

        for key in settings["risk_policy"]:
            if key in saved_policy:
                settings["risk_policy"][key] = float(saved_policy[key])

        for key, value in settings["risk_policy"].items():
            if not 0 <= value <= 1:
                raise ValueError(f"risk policy value is invalid: {key}")

        if not 0 <= settings["safe_cutoff"] <= 1:
            raise ValueError("safe_cutoff is outside 0 to 1")

        if not settings["safe_cutoff"] < settings["phishing_cutoff"] <= 1:
            raise ValueError("phishing_cutoff must be above safe_cutoff")

        if not 0 <= settings["trusted_domain_max_risk"] < settings["safe_cutoff"]:
            raise ValueError("trusted-domain cap must be below safe_cutoff")

        weight_total = settings["lexical_weight"] + settings["hybrid_weight"]

        if abs(weight_total - 1.0) > 0.0001:
            raise ValueError("model weights must add up to 1")

        return settings

    except (OSError, ValueError, KeyError, TypeError):
        warnings.warn(
            "model_config.json not found or invalid; using defaults.",
            stacklevel=2,
        )
        return default_model_config()


def load_training_metadata():
    try:
        with open(METADATA_PATH, "r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError, TypeError):
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
RISK_POLICY = MODEL_CONFIG["risk_policy"]
TRUSTED_DOMAIN_CAP = MODEL_CONFIG["trusted_domain_max_risk"]


def get_model_probability(model, model_input):
    probabilities = model.predict_proba(model_input)[0]

    # find the phishing class (1) by label, not by position
    phishing_index = list(model.classes_).index(1)

    return float(probabilities[phishing_index])


def get_score_certainty(risk_score, lexical_risk, hybrid_risk):
    # not a real probability. it is high when the final score is far from
    # the status cutoffs, and lower when the two models disagree
    distance = min(
        abs(risk_score - SAFE_DECISION_CUTOFF * 100),
        abs(risk_score - PHISHING_DECISION_CUTOFF * 100),
        30,
    )

    certainty = 50 + distance * 1.5

    if abs(lexical_risk - hybrid_risk) > 0.4:
        certainty -= 15

    return round(certainty, 2)


def predict_url_details(url):
    url = validate_url_text(url, max_length=MAX_URL_LENGTH)

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

    final_risk = apply_risk_rules(
        raw_ml_risk=raw_ml_risk,
        features=features,
        reasons=reasons,
        trusted=trusted,
        policy=RISK_POLICY,
        trusted_domain_max_risk=TRUSTED_DOMAIN_CAP,
    )

    risk_score = round(final_risk * 100)

    score_certainty = get_score_certainty(
        risk_score,
        lexical_risk,
        hybrid_risk,
    )

    result = risk_score_to_result(
        risk_score,
        safe_cutoff=SAFE_DECISION_CUTOFF,
        phishing_cutoff=PHISHING_DECISION_CUTOFF,
    )

    root_domain, full_domain = get_domain(url)

    return {
        "url": url,
        "result": result,
        "risk_score": risk_score,
        "score_certainty": score_certainty,
        "reasons": reasons,
        "root_domain": root_domain,
        "full_domain": full_domain,
        "trusted_domain": trusted,
        "explicit_scheme": get_explicit_scheme(url),
        "features": feature_values_to_dict(features),
    }


def predict_url(url):
    """Return the original tuple used by the UI and message scanner."""
    details = predict_url_details(url)

    return (
        details["result"],
        details["risk_score"],
        details["reasons"],
        details["score_certainty"],
    )


def models_are_ready():
    models = [lexical_model, nlp_vectorizer, hybrid_model]
    return all(model is not None for model in models)


def get_model_info():
    return {
        "ready": models_are_ready(),
        "generated_at_utc": TRAINING_METADATA.get("generated_at_utc"),
        "safe_cutoff": SAFE_DECISION_CUTOFF,
    }
