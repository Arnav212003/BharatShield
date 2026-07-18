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
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

from features import extract_features
from nlp_features import create_nlp_vectorizer, fit_transform_urls_for_nlp, clean_url_text
from security_layers import (
    FEATURE_NAMES,
    get_reasons_from_features,
    is_trusted_domain,
    apply_confidence_calibration,
    binary_label_from_risk_score
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "phishing.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model")

os.makedirs(MODEL_DIR, exist_ok=True)


def print_evaluation(model_name, y_test, y_pred, y_score=None):
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    roc_auc = None
    if y_score is not None:
        try:
            roc_auc = roc_auc_score(y_test, y_score)
        except Exception:
            pass

    print(f"\n========== {model_name} Evaluation ==========")
    print("Accuracy :", round(acc * 100, 2), "%")
    print("Precision:", round(prec * 100, 2), "%")
    print("Recall   :", round(rec * 100, 2), "%")
    print("F1 Score :", round(f1 * 100, 2), "%")
    print("ROC-AUC  :", round(roc_auc * 100, 2) if roc_auc else "N/A")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=["Safe", "Phishing"],
                                zero_division=0))

    return {
        "model_name": model_name,
        "accuracy": round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "roc_auc": round(roc_auc * 100, 2) if roc_auc else "N/A",
        "confusion_matrix": confusion_matrix(y_test, y_pred),
        "y_pred": y_pred
    }


def evaluate_model(model_name, model, X_test, y_test):
    y_pred = model.predict(X_test)
    y_score = None
    if hasattr(model, "predict_proba"):
        try:
            y_score = model.predict_proba(X_test)[:, 1]
        except Exception:
            pass
    return print_evaluation(model_name, y_test, y_pred, y_score)


def save_confusion_matrix(cm, title, file_name):
    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Safe", "Phishing"],
                yticklabels=["Safe", "Phishing"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title(title)
    plt.tight_layout()

    path = os.path.join(MODEL_DIR, file_name)
    plt.savefig(path)
    plt.close()
    print(f"{title} saved at: {path}")


def evaluate_final_calibrated_system(X_test_url, X_test_lexical,
                                     lexical_model, hybrid_model,
                                     X_test_hybrid, y_test):
    """Evaluates the same pipeline the end user actually sees -
    ML score + domain reputation + calibration combined.

    For binary evaluation, Suspicious is also counted as unsafe (1)
    because the cost of a false negative is higher than a false positive."""

    lexical_scores = lexical_model.predict_proba(X_test_lexical)[:, 1]
    hybrid_scores = hybrid_model.predict_proba(X_test_hybrid)[:, 1]

    final_scores = []
    for i, url in enumerate(X_test_url):
        features = X_test_lexical.iloc[i].tolist()

        # same formula used in predict.py
        raw_ml_risk = (0.70 * lexical_scores[i]) + (0.30 * hybrid_scores[i])

        reasons = get_reasons_from_features(url, features)
        trusted = is_trusted_domain(url)

        final_scores.append(apply_confidence_calibration(
            raw_ml_risk=raw_ml_risk,
            features=features,
            reasons=reasons,
            trusted=trusted
        ))

    final_preds = [binary_label_from_risk_score(s) for s in final_scores]

    return print_evaluation("Final Calibrated System", y_test,
                            final_preds, final_scores)


# ---- load and clean dataset ----
df = pd.read_csv(DATA_PATH)
print("Dataset loaded successfully")
print(df.head())
print("Dataset shape:", df.shape)

# only the first 2 columns are needed: url, label
df = df.iloc[:, :2]
df.columns = ["url", "label"]
df = df.dropna(subset=["url", "label"])

# different datasets use different label names, map them all
df["label"] = df["label"].astype(str).str.lower().str.strip()
df["label"] = df["label"].map({
    "bad": 1, "phishing": 1, "fraud": 1, "malicious": 1, "unsafe": 1, "1": 1,
    "good": 0, "safe": 0, "legitimate": 0, "benign": 0, "0": 0
})
df = df.dropna(subset=["label"])
df["label"] = df["label"].astype(int)

# sample up to 100k rows to keep training fast
df = df.sample(n=min(100000, len(df)), random_state=42)

print("\nCleaned dataset shape:", df.shape)
print("\nLabel count:")
print(df["label"].value_counts())

# ---- train test split ----
X_train_url, X_test_url, y_train, y_test = train_test_split(
    df["url"], df["label"],
    test_size=0.2, random_state=42, stratify=df["label"]
)

# index reset is required for iloc based evaluation later
X_test_url = X_test_url.reset_index(drop=True)
y_test = y_test.reset_index(drop=True)

# ---- lexical features ----
print("\nExtracting lexical features...")
X_train_lexical = pd.DataFrame(X_train_url.apply(extract_features).tolist(),
                               columns=FEATURE_NAMES)
X_test_lexical = pd.DataFrame(X_test_url.apply(extract_features).tolist(),
                              columns=FEATURE_NAMES)

# ---- NLP features ----
print("\nExtracting NLP TF-IDF features...")
vectorizer = create_nlp_vectorizer()

# fit only on train data, only transform on test data (avoids data leakage)
X_train_nlp = fit_transform_urls_for_nlp(X_train_url, vectorizer)
X_test_nlp = vectorizer.transform(X_test_url.apply(clean_url_text))

# ---- hybrid = lexical + NLP ----
print("\nCombining lexical + NLP features...")
X_train_hybrid = hstack([csr_matrix(X_train_lexical.values), X_train_nlp])
X_test_hybrid = hstack([csr_matrix(X_test_lexical.values), X_test_nlp])

# ---- model training ----
print("\nTraining lexical Random Forest model...")
lexical_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)
lexical_model.fit(X_train_lexical, y_train)

print("\nTraining hybrid NLP + lexical model...")
# logistic regression works well and fast on sparse high-dimensional data
hybrid_model = LogisticRegression(max_iter=1000, class_weight="balanced")
hybrid_model.fit(X_train_hybrid, y_train)

# ---- evaluation ----
print("\nEvaluating raw models...")
lexical_eval = evaluate_model("Lexical Random Forest Model",
                              lexical_model, X_test_lexical, y_test)
hybrid_eval = evaluate_model("Hybrid NLP + Lexical Logistic Regression Model",
                             hybrid_model, X_test_hybrid, y_test)

print("\nEvaluating final calibrated system...")
final_eval = evaluate_final_calibrated_system(
    X_test_url, X_test_lexical,
    lexical_model, hybrid_model,
    X_test_hybrid, y_test
)

# ---- save report ----
rows = []
for ev in [lexical_eval, hybrid_eval, final_eval]:
    rows.append({
        "Model": ev["model_name"],
        "Accuracy": ev["accuracy"],
        "Precision": ev["precision"],
        "Recall": ev["recall"],
        "F1 Score": ev["f1_score"],
        "ROC-AUC": ev["roc_auc"]
    })

report = pd.DataFrame(rows)
report_path = os.path.join(MODEL_DIR, "model_evaluation_report.csv")
report.to_csv(report_path, index=False)

print("\nModel evaluation report saved at:", report_path)
print("\nFinal Evaluation Summary:")
print(report.to_string(index=False))

# ---- save models ----
joblib.dump(lexical_model, os.path.join(MODEL_DIR, "phishing_model.pkl"))
joblib.dump(vectorizer, os.path.join(MODEL_DIR, "nlp_model.pkl"))
joblib.dump(hybrid_model, os.path.join(MODEL_DIR, "hybrid_model.pkl"))
print("\nModels saved successfully in:", MODEL_DIR)

# ---- confusion matrix images ----
save_confusion_matrix(lexical_eval["confusion_matrix"],
                      "Lexical Random Forest Model - Confusion Matrix",
                      "confusion_matrix_lexical.png")
save_confusion_matrix(hybrid_eval["confusion_matrix"],
                      "Hybrid NLP + Lexical Model - Confusion Matrix",
                      "confusion_matrix_hybrid.png")
save_confusion_matrix(final_eval["confusion_matrix"],
                      "Final Calibrated System - Confusion Matrix",
                      "confusion_matrix_final.png")

# app.py also looks for the image under the old file name
save_confusion_matrix(hybrid_eval["confusion_matrix"],
                      "Hybrid NLP + Lexical Model - Confusion Matrix",
                      "confusion_matrix.png")

# ---- feature importance ----
imp_df = pd.DataFrame({
    "Feature": FEATURE_NAMES,
    "Importance": lexical_model.feature_importances_
}).sort_values("Importance")

plt.figure(figsize=(8, 7))
plt.barh(imp_df["Feature"], imp_df["Importance"])
plt.xlabel("Importance")
plt.title("Lexical Feature Importance")
plt.tight_layout()

imp_path = os.path.join(MODEL_DIR, "feature_importance.png")
plt.savefig(imp_path)
plt.close()
print("Feature importance saved at:", imp_path)

print("\nTraining and evaluation completed successfully.")