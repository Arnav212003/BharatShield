import hashlib
import json
import os
import platform
from datetime import datetime, timezone

import joblib
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import scipy
import seaborn as sns
import sklearn
import tldextract
from scipy.sparse import csr_matrix, hstack
from sklearn.calibration import calibration_curve
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MaxAbsScaler

from .features import FEATURE_NAMES, extract_features, get_explicit_scheme
from .nlp_features import (
    clean_url_text,
    create_nlp_vectorizer,
    fit_transform_urls_for_nlp,
)
from .security_layers import (
    DEFAULT_RISK_POLICY,
    PHISHING_CUTOFF,
    SAFE_CUTOFF,
    TRUSTED_DOMAIN_MAX_RISK,
    apply_risk_rules,
    get_domain,
    get_reasons_from_features,
    is_trusted_domain,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.abspath(
    os.getenv(
        "BHARATSHIELD_DATA_PATH",
        os.path.join(BASE_DIR, "data", "phishing.csv"),
    )
)
MODEL_DIR = os.path.abspath(
    os.getenv(
        "BHARATSHIELD_MODEL_DIR",
        os.path.join(BASE_DIR, "model"),
    )
)
DATA_PROVENANCE_PATH = os.path.join(BASE_DIR, "data", "provenance.json")

SEED = 42
MODEL_COMPRESSION = 3
MIN_VALIDATION_RECALL = 0.90
DECISION_THRESHOLDS = [0.30, SAFE_CUTOFF, 0.40, 0.45, 0.50]

RISK_POLICY_CANDIDATES = [
    {
        "name": "no_adjustment",
        "no_pattern_reduction": 1.0,
        "no_pattern_ml_limit": 0.0,
        "two_reason_bonus": 0.0,
        "three_reason_bonus": 0.0,
    },
    {
        "name": "light_rules",
        "no_pattern_reduction": 0.70,
        "no_pattern_ml_limit": 0.45,
        "two_reason_bonus": 0.10,
        "three_reason_bonus": 0.05,
    },
    {
        "name": "balanced_rules",
        "no_pattern_reduction": 0.55,
        "no_pattern_ml_limit": 0.50,
        "two_reason_bonus": 0.15,
        "three_reason_bonus": 0.05,
    },
    {
        "name": "strong_rules",
        **DEFAULT_RISK_POLICY,
    },
]


def load_dataset_provenance():
    default = {
        "provenance_status": "unverified",
        "source": None,
        "license": None,
        "redistribution_allowed": False,
    }

    try:
        with open(DATA_PROVENANCE_PATH, "r", encoding="utf-8") as file:
            saved = json.load(file)

        for key in default:
            if key in saved:
                default[key] = saved[key]

    except (OSError, json.JSONDecodeError, TypeError):
        pass

    return default


def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def label_counts(df):
    counts = df["label"].value_counts().to_dict()

    return {
        "safe": int(counts.get(0, 0)),
        "phishing": int(counts.get(1, 0)),
    }


def split_summary(df):
    domain_sizes = df.groupby("domain").size().sort_values(ascending=False)

    return {
        "rows": int(len(df)),
        "labels": label_counts(df),
        "phishing_percent": round(float(df["label"].mean() * 100), 4),
        "unique_domains": int(df["domain"].nunique()),
        "largest_domain_rows": int(domain_sizes.iloc[0]),
        "largest_domain_percent": round(float(domain_sizes.iloc[0] / len(df) * 100), 4),
        "top_10_domains_percent": round(float(domain_sizes.iloc[:10].sum() / len(df) * 100), 4),
    }


def domain_overlap_count(left, right):
    return len(set(left["domain"]) & set(right["domain"]))


def key_overlap_count(left, right):
    return len(set(left["key"]) & set(right["key"]))


def make_key(urls):
    # same site with http/https/www/trailing slash counts as one URL
    return (
        urls.str.lower()
        .str.strip()
        .str.replace(r"^https?://", "", regex=True)
        .str.replace(r"^www\.", "", regex=True)
        .str.rstrip("/")
    )


def load_dataset():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)

    if df.shape[1] < 2:
        raise ValueError("Dataset must contain URL and label columns.")

    raw_rows = len(df)
    raw_label_counts = (
        df.iloc[:, 1]
        .astype(str)
        .str.lower()
        .str.strip()
        .value_counts()
        .to_dict()
    )

    df = df.iloc[:, :2].copy()
    df.columns = ["url", "label"]

    rows_before_missing_cleanup = len(df)
    df = df.dropna(subset=["url", "label"])
    missing_rows_removed = rows_before_missing_cleanup - len(df)

    df["url"] = df["url"].astype(str)
    df["label"] = df["label"].astype(str).str.lower().str.strip()

    label_map = {
        "bad": 1,
        "phishing": 1,
        "fraud": 1,
        "malicious": 1,
        "unsafe": 1,
        "1": 1,
        "good": 0,
        "safe": 0,
        "legitimate": 0,
        "benign": 0,
        "0": 0,
    }

    rows_before_label_mapping = len(df)
    df["label"] = df["label"].map(label_map)
    df = df.dropna(subset=["label"])
    invalid_label_rows_removed = rows_before_label_mapping - len(df)
    df["label"] = df["label"].astype(int)

    if df["label"].nunique() < 2:
        raise ValueError("Dataset must contain both safe and phishing URLs.")

    rows_before = len(df)

    df["key"] = make_key(df["url"])

    # same URL with both labels is confusing, remove it fully
    conflict = df.groupby("key")["label"].transform("nunique") > 1
    conflicting_keys = int(df.loc[conflict, "key"].nunique())
    conflicting_rows = int(conflict.sum())
    df = df[~conflict]

    rows_before_duplicate_cleanup = len(df)
    df = df.drop_duplicates(subset="key")
    duplicate_rows_removed = rows_before_duplicate_cleanup - len(df)
    cleaned_rows = len(df)
    cleaned_label_counts = label_counts(df)

    print("Removed duplicate/conflicting URLs:", rows_before - len(df))

    sampled = len(df) > 100000

    if sampled:
        df = df.sample(n=100000, random_state=SEED)

    df = df.reset_index(drop=True)

    explicit_schemes = df["url"].apply(get_explicit_scheme)
    explicit_http = (explicit_schemes == "http").mean()
    explicit_https = (explicit_schemes == "https").mean()
    with_scheme = (explicit_schemes != "").mean()

    print("URLs with explicit HTTP:", round(explicit_http * 100, 3), "%")
    print("URLs with explicit HTTPS:", round(explicit_https * 100, 3), "%")
    print("URLs without an explicit scheme:", round((1 - with_scheme) * 100, 3), "%")

    if with_scheme < 0.10:
        print("Warning: most URLs have no explicit scheme, so the HTTPS "
              "feature will usually be 0.")

    df["domain"] = df["url"].apply(lambda url: get_domain(url)[0])
    df.attrs["dataset_summary"] = {
        "raw_rows": int(raw_rows),
        "raw_label_counts": {str(key): int(value) for key, value in raw_label_counts.items()},
        "missing_rows_removed": int(missing_rows_removed),
        "invalid_label_rows_removed": int(invalid_label_rows_removed),
        "conflicting_keys_removed": conflicting_keys,
        "conflicting_rows_removed": conflicting_rows,
        "duplicate_rows_removed": int(duplicate_rows_removed),
        "cleaned_rows_before_sampling": int(cleaned_rows),
        "cleaned_label_counts": cleaned_label_counts,
        "sampled": sampled,
        "sample_rows": int(len(df)),
        "sample_label_counts": label_counts(df),
        "explicit_http_percent": round(float(explicit_http * 100), 4),
        "explicit_https_percent": round(float(explicit_https * 100), 4),
        "missing_scheme_percent": round(float((1 - with_scheme) * 100), 4),
    }

    return df


def split_by_domain(df, test_size):
    # all URLs of one domain go to the same side, so the model
    # cannot just remember domains it has already seen
    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=test_size,
        random_state=SEED,
    )

    first_idx, second_idx = next(
        splitter.split(df, df["label"], groups=df["domain"])
    )

    return (
        df.iloc[first_idx].reset_index(drop=True),
        df.iloc[second_idx].reset_index(drop=True),
    )


def make_hybrid(lexical, nlp):
    return hstack([csr_matrix(lexical.values), nlp]).tocsr()


def get_domain_macro_accuracy(domains, y_true, predictions):
    rows = pd.DataFrame({
        "domain": np.asarray(domains),
        "correct": np.asarray(y_true) == np.asarray(predictions),
    })

    return float(rows.groupby("domain")["correct"].mean().mean())


def get_binary_metrics(y_true, scores, threshold):
    scores = np.asarray(scores, dtype=float)
    predictions = (scores >= threshold).astype(int)

    matrix = confusion_matrix(y_true, predictions, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "predictions": predictions,
        "accuracy": accuracy_score(y_true, predictions),
        "precision": precision_score(y_true, predictions, zero_division=0),
        "recall": recall_score(y_true, predictions, zero_division=0),
        "fpr": fpr,
        "f1_score": f1_score(y_true, predictions, zero_division=0),
        "confusion_matrix": matrix,
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }


def precision_at_prevalence(recall, fpr, prevalence):
    true_positive_share = recall * prevalence
    false_positive_share = fpr * (1 - prevalence)
    denominator = true_positive_share + false_positive_share

    return true_positive_share / denominator if denominator else 0.0


def evaluate_scores(name, y_true, scores, domains, threshold):
    scores = np.asarray(scores, dtype=float)
    result = get_binary_metrics(y_true, scores, threshold)
    predictions = result.pop("predictions")

    result.update({
        "model_name": name,
        "domain_macro_accuracy": get_domain_macro_accuracy(
            domains,
            y_true,
            predictions,
        ),
        "roc_auc": roc_auc_score(y_true, scores),
        "pr_auc": average_precision_score(y_true, scores),
        "brier": brier_score_loss(y_true, scores),
        "precision_at_1_percent": precision_at_prevalence(
            result["recall"],
            result["fpr"],
            0.01,
        ),
    })

    print(f"\n{name}")
    print("Accuracy :", round(result["accuracy"] * 100, 2), "%")
    print("Domain accuracy:", round(result["domain_macro_accuracy"] * 100, 2), "%")
    print("Precision:", round(result["precision"] * 100, 2), "%")
    print("Recall   :", round(result["recall"] * 100, 2), "%")
    print("FPR      :", round(result["fpr"] * 100, 2), "%")
    print("F1 Score :", round(result["f1_score"] * 100, 2), "%")
    print("PR-AUC   :", round(result["pr_auc"] * 100, 2), "%")
    print(
        "Est. precision at 1% prevalence:",
        round(result["precision_at_1_percent"] * 100, 2),
        "%",
    )
    print(
        "Confusion matrix [[TN FP] [FN TP]]:",
        result["confusion_matrix"].tolist(),
    )

    return result


def pick_lexical_weight(lexical_scores, hybrid_scores, y_val):
    # try different weights on the validation set (not the test set)
    results = []

    for weight in np.arange(0, 1.01, 0.1):
        blend = weight * lexical_scores + (1 - weight) * hybrid_scores
        score = round(average_precision_score(y_val, blend), 4)
        results.append((score, float(weight)))

    best_score = max(score for score, weight in results)

    # if many weights are equally good, take the one closest to 0.5
    best_weights = [weight for score, weight in results if score == best_score]
    best_weight = min(best_weights, key=lambda weight: abs(weight - 0.5))

    return round(best_weight, 1)


def final_system_scores(urls, lexical, raw_scores, policy):
    final_scores = []

    for i, url in enumerate(urls):
        features = lexical.iloc[i].tolist()

        reasons = get_reasons_from_features(url, features)
        trusted = is_trusted_domain(url)

        final_risk = apply_risk_rules(
            raw_ml_risk=raw_scores[i],
            features=features,
            reasons=reasons,
            trusted=trusted,
            policy=policy,
            trusted_domain_max_risk=TRUSTED_DOMAIN_MAX_RISK,
        )

        final_scores.append(final_risk)

    return np.array(final_scores)


def pick_decision_settings(urls, lexical, raw_scores, y_val):
    candidates = []

    for saved_policy in RISK_POLICY_CANDIDATES:
        policy = {
            key: value
            for key, value in saved_policy.items()
            if key != "name"
        }
        scores = final_system_scores(urls, lexical, raw_scores, policy)

        for threshold in DECISION_THRESHOLDS:
            metrics = get_binary_metrics(y_val, scores, threshold)
            metrics.pop("predictions")
            metrics.pop("confusion_matrix")

            candidates.append({
                "policy_name": saved_policy["name"],
                "policy": policy,
                "threshold": threshold,
                **metrics,
            })

    eligible = [
        item
        for item in candidates
        if item["recall"] >= MIN_VALIDATION_RECALL
    ]

    if not eligible:
        eligible = candidates

    best = max(
        eligible,
        key=lambda item: (
            item["f1_score"],
            item["precision"],
            -item["fpr"],
        ),
    )

    return best, candidates


def save_confusion_matrix(matrix, title, file_name):
    plt.figure(figsize=(6, 4))

    sns.heatmap(
        matrix,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Safe", "Phishing"],
        yticklabels=["Safe", "Phishing"],
    )

    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title(title)
    plt.tight_layout()
    plt.savefig(os.path.join(MODEL_DIR, file_name))
    plt.close()


def save_reliability_curve(y_true, scores, file_name):
    frac_positive, mean_predicted = calibration_curve(
        y_true,
        scores,
        n_bins=10,
    )

    plt.figure(figsize=(5, 5))
    plt.plot([0, 1], [0, 1], "--", label="Perfect")
    plt.plot(mean_predicted, frac_positive, marker="o", label="ML blend")
    plt.xlabel("Predicted phishing probability")
    plt.ylabel("Actual phishing fraction")
    plt.title("Reliability curve (test set)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(MODEL_DIR, file_name))
    plt.close()


def save_feature_importance(model, x_val, y_val, file_name):
    if len(x_val) > 5000:
        x_val = x_val.sample(n=5000, random_state=SEED)
        y_val = y_val.loc[x_val.index]

    result = permutation_importance(
        model,
        x_val,
        y_val,
        scoring="average_precision",
        n_repeats=5,
        random_state=SEED,
        n_jobs=-1,
    )

    importance = pd.DataFrame({
        "Feature": FEATURE_NAMES,
        "Importance": result.importances_mean,
    }).sort_values("Importance")

    plt.figure(figsize=(8, 7))
    plt.barh(importance["Feature"], importance["Importance"])
    plt.xlabel("Drop in PR-AUC when feature is shuffled")
    plt.title("Lexical Feature Importance (permutation, validation set)")
    plt.tight_layout()
    plt.savefig(os.path.join(MODEL_DIR, file_name))
    plt.close()


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    print("Loading dataset...")
    df = load_dataset()

    print("Dataset size:", len(df))
    print(df["label"].value_counts())

    train_val_df, test_df = split_by_domain(df, test_size=0.20)
    train_df, val_df = split_by_domain(train_val_df, test_size=0.20)

    for name, part in [("Train", train_df), ("Validation", val_df), ("Test", test_df)]:
        if part["label"].nunique() < 2:
            raise ValueError(f"{name} split has only one class.")

        print(name, "size:", len(part), "| phishing %:", round(part["label"].mean() * 100, 1))

    y_train = train_df["label"]
    y_val = val_df["label"]
    y_test = test_df["label"]

    print("\nExtracting lexical features...")

    x_train_lexical = pd.DataFrame(
        train_df["url"].apply(extract_features).tolist(),
        columns=FEATURE_NAMES,
    )
    x_val_lexical = pd.DataFrame(
        val_df["url"].apply(extract_features).tolist(),
        columns=FEATURE_NAMES,
    )
    x_test_lexical = pd.DataFrame(
        test_df["url"].apply(extract_features).tolist(),
        columns=FEATURE_NAMES,
    )

    print("Creating TF-IDF features...")

    vectorizer = create_nlp_vectorizer()

    x_train_nlp = fit_transform_urls_for_nlp(train_df["url"], vectorizer)
    x_val_nlp = vectorizer.transform(val_df["url"].apply(clean_url_text))
    x_test_nlp = vectorizer.transform(test_df["url"].apply(clean_url_text))

    x_train_hybrid = make_hybrid(x_train_lexical, x_train_nlp)
    x_val_hybrid = make_hybrid(x_val_lexical, x_val_nlp)
    x_test_hybrid = make_hybrid(x_test_lexical, x_test_nlp)

    print("Training Random Forest...")

    lexical_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=18,
        random_state=SEED,
        class_weight="balanced",
        n_jobs=-1,
    )
    lexical_model.fit(x_train_lexical, y_train)

    print("Training hybrid Logistic Regression...")

    # lexical columns have big values (url length) and tf-idf is 0 to 1,
    # so lexical columns are scaled first
    scaler = ColumnTransformer(
        [("lexical", MaxAbsScaler(), list(range(len(FEATURE_NAMES))))],
        remainder="passthrough",
        sparse_threshold=1.0,
    )

    hybrid_model = Pipeline([
        ("scale", scaler),
        (
            "lr",
            LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                random_state=SEED,
            ),
        ),
    ])
    hybrid_model.fit(x_train_hybrid, y_train)

    val_lexical_scores = lexical_model.predict_proba(x_val_lexical)[:, 1]
    val_hybrid_scores = hybrid_model.predict_proba(x_val_hybrid)[:, 1]

    lexical_weight = pick_lexical_weight(val_lexical_scores, val_hybrid_scores, y_val)
    hybrid_weight = round(1 - lexical_weight, 1)

    print("\nBest weights on validation set -> lexical:", lexical_weight, "hybrid:", hybrid_weight)

    val_ml_scores = (
        lexical_weight * val_lexical_scores
        + hybrid_weight * val_hybrid_scores
    )
    decision_settings, policy_candidates = pick_decision_settings(
        val_df["url"],
        x_val_lexical,
        val_ml_scores,
        y_val,
    )
    selected_policy = decision_settings["policy"]
    eval_threshold = decision_settings["threshold"]

    print(
        "Selected validation policy:",
        decision_settings["policy_name"],
        "| threshold:",
        eval_threshold,
        "| F1:",
        round(decision_settings["f1_score"], 4),
        "| recall:",
        round(decision_settings["recall"], 4),
    )

    test_lexical_scores = lexical_model.predict_proba(x_test_lexical)[:, 1]
    test_hybrid_scores = hybrid_model.predict_proba(x_test_hybrid)[:, 1]

    test_ml_scores = (
        lexical_weight * test_lexical_scores
        + hybrid_weight * test_hybrid_scores
    )

    test_final_scores = final_system_scores(
        test_df["url"],
        x_test_lexical,
        test_ml_scores,
        selected_policy,
    )

    print("\nAll results below are on the test set, threshold =", eval_threshold)

    lexical_result = evaluate_scores(
        "Lexical Random Forest Model",
        y_test,
        test_lexical_scores,
        test_df["domain"],
        eval_threshold,
    )
    hybrid_result = evaluate_scores(
        "Hybrid NLP + Lexical Logistic Regression Model",
        y_test,
        test_hybrid_scores,
        test_df["domain"],
        eval_threshold,
    )
    ml_only_result = evaluate_scores(
        "ML only (lexical + hybrid blend)",
        y_test,
        test_ml_scores,
        test_df["domain"],
        eval_threshold,
    )
    final_result = evaluate_scores(
        "Final System (validated policy)",
        y_test,
        test_final_scores,
        test_df["domain"],
        eval_threshold,
    )

    results = [lexical_result, hybrid_result, ml_only_result, final_result]

    print("\nEffect of selected policy (ML blend -> final score)")
    print("F1 :", round(ml_only_result["f1_score"] * 100, 2), "->", round(final_result["f1_score"] * 100, 2))
    print("FPR:", round(ml_only_result["fpr"] * 100, 2), "->", round(final_result["fpr"] * 100, 2))

    report_rows = []

    for result in results:
        report_rows.append({
            "Model": result["model_name"],
            "Threshold": eval_threshold,
            "Accuracy": round(result["accuracy"] * 100, 2),
            "Domain-Macro Accuracy": round(result["domain_macro_accuracy"] * 100, 2),
            "Precision": round(result["precision"] * 100, 2),
            "Recall": round(result["recall"] * 100, 2),
            "FPR": round(result["fpr"] * 100, 2),
            "F1 Score": round(result["f1_score"] * 100, 2),
            "ROC-AUC": round(result["roc_auc"] * 100, 2),
            "PR-AUC": round(result["pr_auc"] * 100, 2),
            "Brier": round(result["brier"], 4),
            "Est. Precision at 1% Prevalence": round(
                result["precision_at_1_percent"] * 100,
                2,
            ),
            "TN": result["true_negatives"],
            "FP": result["false_positives"],
            "FN": result["false_negatives"],
            "TP": result["true_positives"],
        })

    report = pd.DataFrame(report_rows)
    report.to_csv(os.path.join(MODEL_DIR, "model_evaluation_report.csv"), index=False)

    joblib.dump(
        lexical_model,
        os.path.join(MODEL_DIR, "phishing_model.pkl"),
        compress=MODEL_COMPRESSION,
    )
    joblib.dump(
        vectorizer,
        os.path.join(MODEL_DIR, "nlp_model.pkl"),
        compress=MODEL_COMPRESSION,
    )
    joblib.dump(
        hybrid_model,
        os.path.join(MODEL_DIR, "hybrid_model.pkl"),
        compress=MODEL_COMPRESSION,
    )

    with open(os.path.join(MODEL_DIR, "model_config.json"), "w") as file:
        json.dump(
            {
                "lexical_weight": lexical_weight,
                "hybrid_weight": hybrid_weight,
                "safe_cutoff": eval_threshold,
                "phishing_cutoff": PHISHING_CUTOFF,
                "trusted_domain_max_risk": TRUSTED_DOMAIN_MAX_RISK,
                "risk_policy_name": decision_settings["policy_name"],
                "risk_policy": selected_policy,
            },
            file,
            indent=2,
        )

    dataset_provenance = load_dataset_provenance()

    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "path": "data/phishing.csv",
            "sha256": sha256_file(DATA_PATH),
            **dataset_provenance,
            **df.attrs["dataset_summary"],
        },
        "training": {
            "seed": SEED,
            "split_method": "group shuffle split by root domain",
            "test_size": 0.20,
            "validation_size_within_train": 0.20,
            "evaluation_threshold": eval_threshold,
            "feature_count": len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
            "model_compression": MODEL_COMPRESSION,
            "lexical_model": {
                "type": "RandomForestClassifier",
                "n_estimators": 200,
                "max_depth": 18,
                "class_weight": "balanced",
            },
            "hybrid_model": {
                "type": "LogisticRegression",
                "max_iter": 2000,
                "class_weight": "balanced",
            },
        },
        "splits": {
            "train": split_summary(train_df),
            "validation": split_summary(val_df),
            "test": split_summary(test_df),
        },
        "overlap_checks": {
            "train_validation_domains": domain_overlap_count(train_df, val_df),
            "train_test_domains": domain_overlap_count(train_df, test_df),
            "validation_test_domains": domain_overlap_count(val_df, test_df),
            "train_validation_urls": key_overlap_count(train_df, val_df),
            "train_test_urls": key_overlap_count(train_df, test_df),
            "validation_test_urls": key_overlap_count(val_df, test_df),
        },
        "blend_weights": {
            "lexical": lexical_weight,
            "hybrid": hybrid_weight,
        },
        "decision_policy_selection": {
            "split": "validation",
            "objective": (
                "highest F1 among candidates with at least 90% recall"
            ),
            "selected_policy": decision_settings["policy_name"],
            "score_adjustment_enabled": (
                decision_settings["policy_name"] != "no_adjustment"
            ),
            "selected_threshold": eval_threshold,
            "selected_validation_precision": round(
                decision_settings["precision"],
                6,
            ),
            "selected_validation_recall": round(
                decision_settings["recall"],
                6,
            ),
            "selected_validation_f1": round(
                decision_settings["f1_score"],
                6,
            ),
            "threshold_candidates": DECISION_THRESHOLDS,
            "policy_candidates": [
                item["name"] for item in RISK_POLICY_CANDIDATES
            ],
            "evaluated_candidate_count": len(policy_candidates),
        },
        "fixed_security_guards": {
            "trusted_domain_max_risk": TRUSTED_DOMAIN_MAX_RISK,
            "trusted_domain_notes": (
                "Only clean, exact allowlisted hosts are capped. Redirects, "
                "user-content hosts, HTTP URLs, and @-symbol URLs are excluded."
            ),
        },
        "evaluation": report.to_dict(orient="records"),
        "versions": {
            "python": platform.python_version(),
            "pandas": pd.__version__,
            "numpy": np.__version__,
            "scipy": scipy.__version__,
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
            "tldextract": tldextract.__version__,
        },
    }

    with open(
        os.path.join(MODEL_DIR, "training_metadata.json"),
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(metadata, file, indent=2)

    save_confusion_matrix(lexical_result["confusion_matrix"], "Lexical Random Forest Model", "confusion_matrix_lexical.png")
    save_confusion_matrix(hybrid_result["confusion_matrix"], "Hybrid NLP + Lexical Model", "confusion_matrix_hybrid.png")
    save_confusion_matrix(
        final_result["confusion_matrix"],
        "Final System (validated policy)",
        "confusion_matrix_final.png",
    )
    save_confusion_matrix(
        final_result["confusion_matrix"],
        "Final System (validated policy)",
        "confusion_matrix.png",
    )

    save_reliability_curve(y_test, test_ml_scores, "reliability_curve.png")
    save_feature_importance(lexical_model, x_val_lexical, y_val, "feature_importance.png")

    print("\nTraining completed.")
    print()
    print(report.to_string(index=False))
    print("\nNote: predict.py must use the same weights (model/model_config.json).")


if __name__ == "__main__":
    main()
