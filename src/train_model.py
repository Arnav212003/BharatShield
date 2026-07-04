import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from scipy.sparse import hstack, csr_matrix

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

from features import extract_features
from nlp_features import (
    create_nlp_vectorizer,
    fit_transform_urls_for_nlp,
    clean_url_text
)

from security_layers import (
    FEATURE_NAMES,
    get_reasons_from_features,
    is_trusted_domain,
    apply_confidence_calibration,
    binary_label_from_risk_score
)


# -----------------------------
# Base paths
# -----------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(BASE_DIR, "data", "phishing.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model")

PHISHING_MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
NLP_MODEL_PATH = os.path.join(MODEL_DIR, "nlp_model.pkl")
HYBRID_MODEL_PATH = os.path.join(MODEL_DIR, "hybrid_model.pkl")

EVALUATION_REPORT_PATH = os.path.join(MODEL_DIR, "model_evaluation_report.csv")

os.makedirs(MODEL_DIR, exist_ok=True)


# -----------------------------
# Evaluation helper
# -----------------------------
def print_evaluation(model_name, y_test, y_pred, y_score=None):
    """
    Prints and returns evaluation metrics for a model/system.
    """

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    roc_auc = None

    if y_score is not None:
        try:
            roc_auc = roc_auc_score(y_test, y_score)
        except Exception:
            roc_auc = None

    print(f"\n========== {model_name} Evaluation ==========")
    print("Accuracy :", round(accuracy * 100, 2), "%")
    print("Precision:", round(precision * 100, 2), "%")
    print("Recall   :", round(recall * 100, 2), "%")
    print("F1 Score :", round(f1 * 100, 2), "%")

    if roc_auc is not None:
        print("ROC-AUC  :", round(roc_auc * 100, 2), "%")
    else:
        print("ROC-AUC  : N/A")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=["Safe", "Phishing"],
            zero_division=0
        )
    )

    cm = confusion_matrix(y_test, y_pred)

    return {
        "model_name": model_name,
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "roc_auc": round(roc_auc * 100, 2) if roc_auc is not None else "N/A",
        "confusion_matrix": cm,
        "y_pred": y_pred
    }


def evaluate_model(model_name, model, X_test, y_test):
    """
    Evaluates a trained ML model using standard raw model metrics.
    """

    y_pred = model.predict(X_test)

    y_score = None

    if hasattr(model, "predict_proba"):
        try:
            y_score = model.predict_proba(X_test)[:, 1]
        except Exception:
            y_score = None

    return print_evaluation(
        model_name=model_name,
        y_test=y_test,
        y_pred=y_pred,
        y_score=y_score
    )


def save_confusion_matrix(cm, title, file_name):
    """
    Saves confusion matrix image inside model folder.
    """

    plt.figure(figsize=(6, 4))

    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Safe", "Phishing"],
        yticklabels=["Safe", "Phishing"]
    )

    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title(title)
    plt.tight_layout()

    save_path = os.path.join(MODEL_DIR, file_name)
    plt.savefig(save_path)
    plt.close()

    print(f"{title} saved at: {save_path}")


# -----------------------------
# Final calibrated system evaluation
# -----------------------------
def evaluate_final_calibrated_system(
    X_test_url,
    X_test_lexical,
    lexical_model,
    hybrid_model,
    X_test_hybrid,
    y_test
):
    """
    Evaluates the final user-facing system.

    This includes:
    1. lexical model risk,
    2. hybrid model risk,
    3. domain reputation layer,
    4. confidence calibration layer.

    For binary evaluation:
    Safe = 0
    Suspicious/Phishing = 1

    Reason:
    In phishing detection, suspicious URLs should not be treated as fully safe.
    False negatives are more costly than false positives.
    """

    lexical_scores = lexical_model.predict_proba(X_test_lexical)[:, 1]
    hybrid_scores = hybrid_model.predict_proba(X_test_hybrid)[:, 1]

    final_scores = []

    for i, url in enumerate(X_test_url):
        features = X_test_lexical.iloc[i].tolist()

        # Same raw ML risk formula used in predict.py
        raw_ml_risk = (0.70 * lexical_scores[i]) + (0.30 * hybrid_scores[i])

        reasons = get_reasons_from_features(url, features)
        trusted = is_trusted_domain(url)

        final_risk = apply_confidence_calibration(
            raw_ml_risk=raw_ml_risk,
            features=features,
            reasons=reasons,
            trusted=trusted
        )

        final_scores.append(final_risk)

    final_predictions = [
        binary_label_from_risk_score(score)
        for score in final_scores
    ]

    return print_evaluation(
        model_name="Final Calibrated System",
        y_test=y_test,
        y_pred=final_predictions,
        y_score=final_scores
    )


# -----------------------------
# Load dataset
# -----------------------------
df = pd.read_csv(DATA_PATH)

print("Dataset loaded successfully")
print(df.head())
print("Dataset shape:", df.shape)


# -----------------------------
# Fix column names
# -----------------------------
df = df.iloc[:, :2]
df.columns = ["url", "label"]


# -----------------------------
# Remove null values
# -----------------------------
df = df.dropna(subset=["url", "label"])


# -----------------------------
# Convert labels
# -----------------------------
df["label"] = df["label"].astype(str).str.lower().str.strip()

df["label"] = df["label"].map({
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
    "0": 0
})

df = df.dropna(subset=["label"])
df["label"] = df["label"].astype(int)


# -----------------------------
# Fast training sample
# -----------------------------
df = df.sample(n=min(100000, len(df)), random_state=42)

print("\nCleaned dataset shape:", df.shape)
print("\nLabel count:")
print(df["label"].value_counts())


# -----------------------------
# Train-test split
# -----------------------------
X_url = df["url"]
y = df["label"]

X_train_url, X_test_url, y_train, y_test = train_test_split(
    X_url,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Reset index for safe iloc-based evaluation later
X_test_url = X_test_url.reset_index(drop=True)
y_test = y_test.reset_index(drop=True)


# -----------------------------
# 1. Lexical Feature Extraction
# -----------------------------
print("\nExtracting lexical features...")

X_train_lexical = X_train_url.apply(extract_features)
X_test_lexical = X_test_url.apply(extract_features)

X_train_lexical = pd.DataFrame(X_train_lexical.tolist())
X_test_lexical = pd.DataFrame(X_test_lexical.tolist())

X_train_lexical.columns = FEATURE_NAMES
X_test_lexical.columns = FEATURE_NAMES


# -----------------------------
# 2. NLP Feature Extraction
# -----------------------------
print("\nExtracting NLP TF-IDF features...")

vectorizer = create_nlp_vectorizer()

# Training NLP features
X_train_nlp = fit_transform_urls_for_nlp(X_train_url, vectorizer)

# Test data should use the same cleaning logic as predict.py
X_test_url_cleaned = X_test_url.apply(clean_url_text)
X_test_nlp = vectorizer.transform(X_test_url_cleaned)


# -----------------------------
# 3. Hybrid Feature Combination
# -----------------------------
print("\nCombining lexical + NLP features...")

X_train_hybrid = hstack([
    csr_matrix(X_train_lexical.values),
    X_train_nlp
])

X_test_hybrid = hstack([
    csr_matrix(X_test_lexical.values),
    X_test_nlp
])


# -----------------------------
# 4. Train Lexical Model
# -----------------------------
print("\nTraining lexical Random Forest model...")

lexical_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

lexical_model.fit(X_train_lexical, y_train)


# -----------------------------
# 5. Train Hybrid Model
# -----------------------------
print("\nTraining hybrid NLP + lexical model...")

hybrid_model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    n_jobs=-1
)

hybrid_model.fit(X_train_hybrid, y_train)


# -----------------------------
# 6. Raw Model Evaluation
# -----------------------------
print("\nEvaluating raw models...")

lexical_eval = evaluate_model(
    model_name="Lexical Random Forest Model",
    model=lexical_model,
    X_test=X_test_lexical,
    y_test=y_test
)

hybrid_eval = evaluate_model(
    model_name="Hybrid NLP + Lexical Logistic Regression Model",
    model=hybrid_model,
    X_test=X_test_hybrid,
    y_test=y_test
)


# -----------------------------
# 7. Final Calibrated System Evaluation
# -----------------------------
print("\nEvaluating final calibrated system...")

final_eval = evaluate_final_calibrated_system(
    X_test_url=X_test_url,
    X_test_lexical=X_test_lexical,
    lexical_model=lexical_model,
    hybrid_model=hybrid_model,
    X_test_hybrid=X_test_hybrid,
    y_test=y_test
)


# -----------------------------
# 8. Save evaluation report
# -----------------------------
evaluation_report = pd.DataFrame([
    {
        "Model": lexical_eval["model_name"],
        "Accuracy": lexical_eval["accuracy"],
        "Precision": lexical_eval["precision"],
        "Recall": lexical_eval["recall"],
        "F1 Score": lexical_eval["f1_score"],
        "ROC-AUC": lexical_eval["roc_auc"]
    },
    {
        "Model": hybrid_eval["model_name"],
        "Accuracy": hybrid_eval["accuracy"],
        "Precision": hybrid_eval["precision"],
        "Recall": hybrid_eval["recall"],
        "F1 Score": hybrid_eval["f1_score"],
        "ROC-AUC": hybrid_eval["roc_auc"]
    },
    {
        "Model": final_eval["model_name"],
        "Accuracy": final_eval["accuracy"],
        "Precision": final_eval["precision"],
        "Recall": final_eval["recall"],
        "F1 Score": final_eval["f1_score"],
        "ROC-AUC": final_eval["roc_auc"]
    }
])

evaluation_report.to_csv(EVALUATION_REPORT_PATH, index=False)

print("\nModel evaluation report saved at:")
print(EVALUATION_REPORT_PATH)

print("\nFinal Evaluation Summary:")
print(evaluation_report.to_string(index=False))


# -----------------------------
# 9. Save models
# -----------------------------
joblib.dump(lexical_model, PHISHING_MODEL_PATH)
joblib.dump(vectorizer, NLP_MODEL_PATH)
joblib.dump(hybrid_model, HYBRID_MODEL_PATH)

print("\nModels saved successfully:")
print("Lexical model:", PHISHING_MODEL_PATH)
print("NLP vectorizer:", NLP_MODEL_PATH)
print("Hybrid model:", HYBRID_MODEL_PATH)


# -----------------------------
# 10. Save confusion matrices
# -----------------------------
save_confusion_matrix(
    cm=lexical_eval["confusion_matrix"],
    title="Lexical Random Forest Model - Confusion Matrix",
    file_name="confusion_matrix_lexical.png"
)

save_confusion_matrix(
    cm=hybrid_eval["confusion_matrix"],
    title="Hybrid NLP + Lexical Model - Confusion Matrix",
    file_name="confusion_matrix_hybrid.png"
)

save_confusion_matrix(
    cm=final_eval["confusion_matrix"],
    title="Final Calibrated System - Confusion Matrix",
    file_name="confusion_matrix_final.png"
)

# Keep this for app.py compatibility
save_confusion_matrix(
    cm=hybrid_eval["confusion_matrix"],
    title="Hybrid NLP + Lexical Model - Confusion Matrix",
    file_name="confusion_matrix.png"
)


# -----------------------------
# 11. Feature importance
# -----------------------------
importances = lexical_model.feature_importances_

feature_importance_df = pd.DataFrame({
    "Feature": FEATURE_NAMES,
    "Importance": importances
}).sort_values(by="Importance", ascending=True)

plt.figure(figsize=(8, 7))
plt.barh(
    feature_importance_df["Feature"],
    feature_importance_df["Importance"]
)
plt.xlabel("Importance")
plt.title("Lexical Feature Importance")
plt.tight_layout()

feature_importance_path = os.path.join(MODEL_DIR, "feature_importance.png")
plt.savefig(feature_importance_path)
plt.close()

print("Feature importance saved at:", feature_importance_path)


print("\nTraining and evaluation completed successfully.")