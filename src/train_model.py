"""Train the URL models and evaluate them.

    python -m scripts.download_data
    python -m scripts.build_dataset
    python -m src.train_model

Two test sets are used:
- internal: a site-grouped split of data/train.csv (same sources)
- external: data/external_test.csv (newer phishing, unseen sites)
Cutoffs and blend weights are picked on the validation split only.
"""

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
import sklearn
import tldextract
from scipy.sparse import csr_matrix, hstack
from sklearn.calibration import calibration_curve
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MaxAbsScaler

from .evaluation import (
    binary_metrics,
    pick_blend_weight,
    pick_phishing_cutoff,
    pick_safe_cutoff,
)
from .features import FEATURE_NAMES, extract_features_from_key
from .nlp_features import create_nlp_vectorizer
from .security_layers import apply_rules, check_url
from .url_utils import canonical_key

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.abspath(
    os.getenv("BHARATSHIELD_MODEL_DIR", os.path.join(BASE_DIR, "model"))
)
TRAIN_PATH = os.path.join(DATA_DIR, "train.csv")
EXTERNAL_PATH = os.path.join(DATA_DIR, "external_test.csv")
SUMMARY_PATH = os.path.join(DATA_DIR, "dataset_summary.json")

SEED = 42
# a random forest (100 trees) was 33 MB with slightly lower PR-AUC on
# validation (0.924 vs 0.927), so boosted trees are used instead
GB_PARAMS = {
    "max_iter": 300,
    "learning_rate": 0.1,
    "max_leaf_nodes": 63,
    "class_weight": "balanced",
}
LR_PARAMS = {"C": 4.0, "max_iter": 3000, "class_weight": "balanced"}


def split_by_site(df):
    """Train/validation/test split where one site never appears in two parts."""
    outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    rest_idx, test_idx = next(outer.split(df, df["label"], groups=df["group"]))
    rest, test = df.iloc[rest_idx], df.iloc[test_idx]

    inner = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=SEED)
    train_idx, val_idx = next(inner.split(rest, rest["label"], groups=rest["group"]))

    return (
        rest.iloc[train_idx].reset_index(drop=True),
        rest.iloc[val_idx].reset_index(drop=True),
        test.reset_index(drop=True),
    )


def feature_table(keys):
    return pd.DataFrame([extract_features_from_key(key) for key in keys], columns=FEATURE_NAMES)


def build_lexical_model():
    return HistGradientBoostingClassifier(**GB_PARAMS, random_state=SEED)


def build_hybrid_model():
    # scale only the numeric columns, TF-IDF columns are already 0 to 1
    scaler = ColumnTransformer(
        [("numeric", MaxAbsScaler(), list(range(len(FEATURE_NAMES))))],
        remainder="passthrough",
        sparse_threshold=1.0,
    )

    return Pipeline([
        ("scale", scaler),
        ("lr", LogisticRegression(**LR_PARAMS, random_state=SEED)),
    ])


class UrlModels:
    def __init__(self):
        self.vectorizer = create_nlp_vectorizer()
        self.lexical = build_lexical_model()
        self.hybrid = build_hybrid_model()
        self.weight = 0.5

    def _inputs(self, keys, fit=False):
        numeric = feature_table(keys)
        text = self.vectorizer.fit_transform(keys) if fit else self.vectorizer.transform(keys)
        return numeric, hstack([csr_matrix(numeric.values), text]).tocsr()

    def fit(self, keys, labels):
        numeric, combined = self._inputs(keys, fit=True)
        print("  gradient boosting on", numeric.shape[1], "URL features")
        self.lexical.fit(numeric, labels)
        print("  logistic regression on URL features + TF-IDF", combined.shape)
        self.hybrid.fit(combined, labels)

    def scores(self, keys):
        numeric, combined = self._inputs(keys)
        lexical = self.lexical.predict_proba(numeric)[:, 1]
        hybrid = self.hybrid.predict_proba(combined)[:, 1]
        return lexical, hybrid, self.weight * lexical + (1 - self.weight) * hybrid


def system_scores(urls, ml_risk, safe_cutoff, phishing_cutoff):
    return np.array([
        apply_rules(risk, check_url(url), safe_cutoff, phishing_cutoff)[0]
        for url, risk in zip(urls, ml_risk, strict=True)
    ])


def report_row(dataset, name, metrics):
    return {
        "Dataset": dataset,
        "Model": name,
        "Rows": metrics["rows"],
        "Threshold": metrics["threshold"],
        "Accuracy": round(metrics["accuracy"] * 100, 2),
        "Precision": round(metrics["precision"] * 100, 2),
        "Recall": round(metrics["recall"] * 100, 2),
        "F1 Score": round(metrics["f1"] * 100, 2),
        "FPR": round(metrics["fpr"] * 100, 2),
        "ROC-AUC": round(metrics["roc_auc"] * 100, 2) if metrics["roc_auc"] else None,
        "PR-AUC": round(metrics["pr_auc"] * 100, 2) if metrics["pr_auc"] else None,
        "TN": metrics["tn"],
        "FP": metrics["fp"],
        "FN": metrics["fn"],
        "TP": metrics["tp"],
    }


def print_metrics(title, metrics):
    print(
        f"  {title:34s} precision {metrics['precision']:.3f}  recall {metrics['recall']:.3f}"
        f"  F1 {metrics['f1']:.3f}  FPR {metrics['fpr']:.3f}"
    )


def save_confusion_matrix(metrics, title, file_name):
    matrix = np.array([[metrics["tn"], metrics["fp"]], [metrics["fn"], metrics["tp"]]])

    fig, ax = plt.subplots(figsize=(5, 4))
    ax.imshow(matrix, cmap="Blues")

    for row in range(2):
        for col in range(2):
            color = "white" if matrix[row, col] > matrix.max() / 2 else "black"
            ax.text(col, row, f"{matrix[row, col]:,}", ha="center", va="center", color=color)

    ax.set_xticks([0, 1], ["Safe", "Phishing"])
    ax.set_yticks([0, 1], ["Safe", "Phishing"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(os.path.join(MODEL_DIR, file_name))
    plt.close(fig)


def save_reliability_curve(y_true, scores, file_name):
    actual, predicted = calibration_curve(y_true, scores, n_bins=10)

    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 1], [0, 1], "--", color="grey", label="Perfect")
    ax.plot(predicted, actual, marker="o", label="ML score")
    ax.set_xlabel("Predicted phishing score")
    ax.set_ylabel("Actual phishing fraction")
    ax.set_title("Reliability curve (external test)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(MODEL_DIR, file_name))
    plt.close(fig)


def save_feature_importance(model, keys, labels, file_name):
    sample = pd.DataFrame({"key": keys, "label": labels}).sample(
        n=min(5000, len(keys)),
        random_state=SEED,
    )
    result = permutation_importance(
        model,
        feature_table(sample["key"]),
        sample["label"],
        scoring="average_precision",
        n_repeats=5,
        random_state=SEED,
        n_jobs=-1,
    )
    order = np.argsort(result.importances_mean)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(np.array(FEATURE_NAMES)[order], result.importances_mean[order])
    ax.set_xlabel("Drop in PR-AUC when the feature is shuffled")
    ax.set_title("Gradient boosting feature importance (validation set)")
    fig.tight_layout()
    fig.savefig(os.path.join(MODEL_DIR, file_name))
    plt.close(fig)


def evaluate_external(models, safe_cutoff, phishing_cutoff):
    external = pd.read_csv(EXTERNAL_PATH, dtype={"url": str})
    _, _, ml_risk = models.scores(list(external["url"].map(canonical_key)))
    final = system_scores(external["url"], ml_risk, safe_cutoff, phishing_cutoff)
    labels = external["label"].values

    results = {
        "ml_only": binary_metrics(labels, ml_risk, safe_cutoff),
        "final_system": binary_metrics(labels, final, safe_cutoff),
        "slices": {},
    }

    checks = [check_url(url) for url in external["url"]]
    slices = {source: (external["source"] == source).values for source in external["source"].unique()}
    slices["free_hosting"] = np.array([bool(c["user_content_root"]) for c in checks])
    slices["brand_name_in_url"] = np.array([bool(c["brand"]) for c in checks])

    # flagged share before and after the rules: this is recall for phishing
    # rows and the false positive rate for legitimate rows
    for name, mask in slices.items():
        for label, label_name in [(1, "phishing"), (0, "legitimate")]:
            part = mask & (labels == label)

            if part.sum() == 0:
                continue

            results["slices"][f"{name}_{label_name}"] = {
                "rows": int(part.sum()),
                "flagged_ml_only": round(float((ml_risk[part] >= safe_cutoff).mean()), 4),
                "flagged_final": round(float((final[part] >= safe_cutoff).mean()), 4),
            }

    return results, labels, ml_risk


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    if not os.path.exists(TRAIN_PATH):
        raise FileNotFoundError(
            "data/train.csv not found. Run python -m scripts.download_data "
            "and python -m scripts.build_dataset first."
        )

    df = pd.read_csv(TRAIN_PATH, dtype={"key": str, "group": str})
    df = df.dropna(subset=["key"])
    print("Training rows:", len(df), "| phishing share:", round(df["label"].mean(), 3))

    train, val, test = split_by_site(df)

    for name, part in [("train", train), ("validation", val), ("test", test)]:
        print(f"  {name:10s} {len(part):7d} rows, phishing {part['label'].mean():.3f}")

    print("Training models...")
    models = UrlModels()
    models.fit(list(train["key"]), train["label"])

    val_lexical, val_hybrid, _ = models.scores(list(val["key"]))
    models.weight = pick_blend_weight(val["label"], val_lexical, val_hybrid)
    val_ml = models.weight * val_lexical + (1 - models.weight) * val_hybrid

    # cutoffs are picked on the ML score, the fixed rules are then
    # measured with the same cutoffs on the test sets
    safe =pick_safe_cutoff(val["label"], val_ml)
    phishing = pick_phishing_cutoff(val["label"], val_ml, safe["threshold"])
    safe_cutoff, phishing_cutoff = safe["threshold"], phishing["threshold"]

    print("Validation choices: boosting weight", models.weight, "| safe cutoff", safe_cutoff,
          "| phishing cutoff", phishing_cutoff)

    test_lexical, test_hybrid, test_ml = models.scores(list(test["key"]))
    test_final = system_scores(test["key"], test_ml, safe_cutoff, phishing_cutoff)
    internal = {
        "Gradient boosting (URL features)": binary_metrics(test["label"], test_lexical, safe_cutoff),
        "Logistic regression (features + TF-IDF)": binary_metrics(test["label"], test_hybrid, safe_cutoff),
        "ML blend": binary_metrics(test["label"], test_ml, safe_cutoff),
        "Final system (ML + rules)": binary_metrics(test["label"], test_final, safe_cutoff),
    }

    print("Internal test (same sources, unseen sites):")
    rows = []

    for name, metrics in internal.items():
        print_metrics(name, metrics)
        rows.append(report_row("internal", name, metrics))

    external = None

    if os.path.exists(EXTERNAL_PATH):
        external, ext_labels, ext_ml = evaluate_external(models, safe_cutoff, phishing_cutoff)
        print("External test (newer phishing, unseen sites):")
        print_metrics("ML blend", external["ml_only"])
        print_metrics("Final system (ML + rules)", external["final_system"])

        for source, item in external["slices"].items():
            print("   ", source, item)

        rows.append(report_row("external", "ML blend", external["ml_only"]))
        rows.append(report_row("external", "Final system (ML + rules)", external["final_system"]))
        save_confusion_matrix(external["final_system"], "Final system, external test", "confusion_matrix_external.png")
        save_reliability_curve(ext_labels, ext_ml, "reliability_curve.png")
    else:
        print("data/external_test.csv not found, skipping the external test.")

    report = pd.DataFrame(rows)
    report.to_csv(os.path.join(MODEL_DIR, "model_evaluation_report.csv"), index=False)

    save_confusion_matrix(internal["Final system (ML + rules)"], "Final system, internal test", "confusion_matrix_internal.png")
    save_feature_importance(models.lexical, list(val["key"]), val["label"], "feature_importance.png")

    joblib.dump(models.lexical, os.path.join(MODEL_DIR, "phishing_model.pkl"), compress=3)
    joblib.dump(models.vectorizer, os.path.join(MODEL_DIR, "nlp_model.pkl"), compress=3)
    joblib.dump(models.hybrid, os.path.join(MODEL_DIR, "hybrid_model.pkl"), compress=3)

    config = {
        "lexical_weight": models.weight,
        "hybrid_weight": round(1 - models.weight, 1),
        "safe_cutoff": safe_cutoff,
        "phishing_cutoff": phishing_cutoff,
    }

    with open(os.path.join(MODEL_DIR, "model_config.json"), "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2)
        file.write("\n")

    dataset_summary = {}

    if os.path.exists(SUMMARY_PATH):
        with open(SUMMARY_PATH, "r", encoding="utf-8") as file:
            dataset_summary = json.load(file)

    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": dataset_summary,
        "split": {
            "method": "StratifiedGroupKFold by site group (registered domain or free-hosting tenant)",
            "train_rows": len(train),
            "validation_rows": len(val),
            "test_rows": len(test),
            "shared_groups_train_test": len(set(train["group"]) & set(test["group"])),
            "shared_groups_train_validation": len(set(train["group"]) & set(val["group"])),
        },
        "models": {
            "gradient_boosting": GB_PARAMS,
            "logistic_regression": LR_PARAMS,
            "tfidf": {"analyzer": "char_wb", "ngram_range": [3, 5], "max_features": 50000},
            "features": FEATURE_NAMES,
        },
        "validation_choices": {
            **config,
            "safe_cutoff_rule": "highest F1 with recall >= 0.90",
            "phishing_cutoff_rule": "lowest cutoff with precision >= 0.98",
            "validation_at_safe_cutoff": {k: safe[k] for k in ["precision", "recall", "f1", "fpr"]},
        },
        "internal_test": internal,
        "external_test": external,
        "versions": {
            "python": platform.python_version(),
            "pandas": pd.__version__,
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
            "tldextract": tldextract.__version__,
        },
    }

    with open(os.path.join(MODEL_DIR, "training_metadata.json"), "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2)
        file.write("\n")

    print("\n" + report.to_string(index=False))
    print("\nSaved models and reports to", MODEL_DIR)


if __name__ == "__main__":
    main()
