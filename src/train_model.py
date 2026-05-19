import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.sparse import hstack

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from features import extract_features
from nlp_features import create_nlp_vectorizer, fit_transform_urls_for_nlp


# Base paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(BASE_DIR, "data", "phishing.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model")

PHISHING_MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
NLP_MODEL_PATH = os.path.join(MODEL_DIR, "nlp_model.pkl")
HYBRID_MODEL_PATH = os.path.join(MODEL_DIR, "hybrid_model.pkl")

os.makedirs(MODEL_DIR, exist_ok=True)


# Load dataset
df = pd.read_csv(DATA_PATH)

print("Dataset loaded successfully")
print(df.head())
print("Dataset shape:", df.shape)


# Fix column names automatically
df.columns = ["url", "label"]


# Remove null values
df = df.dropna(subset=["url", "label"])


# Convert labels
df["label"] = df["label"].astype(str).str.lower().str.strip()

df["label"] = df["label"].map({
    "bad": 1,
    "phishing": 1,
    "fraud": 1,
    "malicious": 1,
    "1": 1,

    "good": 0,
    "safe": 0,
    "legitimate": 0,
    "benign": 0,
    "0": 0
})

df = df.dropna(subset=["label"])
df["label"] = df["label"].astype(int)


# Fast training sample
# Later final version me 100000 ya full data use kar sakte ho
df = df.sample(n=min(100000, len(df)), random_state=42)

print("\nCleaned dataset shape:", df.shape)
print("\nLabel count:")
print(df["label"].value_counts())


# Train-test split first
X_url = df["url"]
y = df["label"]

X_train_url, X_test_url, y_train, y_test = train_test_split(
    X_url,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# -----------------------------
# 1. Lexical Feature Extraction
# -----------------------------
print("\nExtracting lexical features...")

X_train_lexical = X_train_url.apply(extract_features)
X_test_lexical = X_test_url.apply(extract_features)

X_train_lexical = pd.DataFrame(X_train_lexical.tolist())
X_test_lexical = pd.DataFrame(X_test_lexical.tolist())


feature_names = [
    "URL Length",
    "Domain Length",
    "Full Domain Length",
    "Dots",
    "Hyphens",
    "Slashes",
    "Question Marks",
    "Equal Symbols",
    "@ Count",
    "Percent Symbols",
    "Digits",
    "Special Characters",
    "HTTPS",
    "Has @ Symbol",
    "Suspicious Keyword",
    "IP Address",
    "Short URL",
    "Suspicious TLD",
    "Has Query",
    "Subdomain Count",
    "Hyphen In Domain",
    "Digit In Domain"
]

X_train_lexical.columns = feature_names
X_test_lexical.columns = feature_names


# -----------------------------
# 2. NLP Feature Extraction
# -----------------------------
print("\nExtracting NLP TF-IDF features...")

vectorizer = create_nlp_vectorizer()

X_train_nlp = fit_transform_urls_for_nlp(X_train_url, vectorizer)
X_test_nlp = vectorizer.transform(X_test_url)


# -----------------------------
# 3. Hybrid Feature Combination
# -----------------------------
print("\nCombining lexical + NLP features...")

X_train_hybrid = hstack([X_train_lexical.values, X_train_nlp])
X_test_hybrid = hstack([X_test_lexical.values, X_test_nlp])


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
# 5. Train Hybrid NLP Model
# -----------------------------
print("\nTraining hybrid NLP model...")

hybrid_model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    n_jobs=-1
)

hybrid_model.fit(X_train_hybrid, y_train)


# -----------------------------
# 6. Evaluation
# -----------------------------
print("\nEvaluating hybrid model...")

y_pred = hybrid_model.predict(X_test_hybrid)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0)
recall = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)

print("\nHybrid Model Evaluation")
print("-----------------------")
print("Accuracy :", round(accuracy * 100, 2), "%")
print("Precision:", round(precision * 100, 2), "%")
print("Recall   :", round(recall * 100, 2), "%")
print("F1 Score :", round(f1 * 100, 2), "%")

print("\nClassification Report")
print(classification_report(y_test, y_pred))


# -----------------------------
# 7. Save Models
# -----------------------------
joblib.dump(lexical_model, PHISHING_MODEL_PATH)
joblib.dump(vectorizer, NLP_MODEL_PATH)
joblib.dump(hybrid_model, HYBRID_MODEL_PATH)

print("\nModels saved successfully:")
print("Lexical model:", PHISHING_MODEL_PATH)
print("NLP vectorizer:", NLP_MODEL_PATH)
print("Hybrid model:", HYBRID_MODEL_PATH)


# -----------------------------
# 8. Confusion Matrix
# -----------------------------
cm = confusion_matrix(y_test, y_pred)

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
plt.title("Hybrid NLP Model - Confusion Matrix")
plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "confusion_matrix.png"))
plt.show()


# -----------------------------
# 9. Feature Importance
# -----------------------------
importances = lexical_model.feature_importances_

feature_importance_df = pd.DataFrame({
    "Feature": feature_names,
    "Importance": importances
}).sort_values(by="Importance", ascending=True)

plt.figure(figsize=(8, 7))
plt.barh(feature_importance_df["Feature"], feature_importance_df["Importance"])
plt.xlabel("Importance")
plt.title("Lexical Feature Importance")
plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "feature_importance.png"))
plt.show()