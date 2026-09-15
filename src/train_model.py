import os

import joblib
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from scipy.sparse import csr_matrix, hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from features import extract_features
from nlp_features import create_nlp_vectorizer, fit_transform_urls_for_nlp, clean_url_text
from security_layers import (
    FEATURE_NAMES,
    apply_confidence_calibration,
    binary_label_from_risk_score,
    get_reasons_from_features,
    is_trusted_domain,
)


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "phishing.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model")


def evaluate_predictions(name, y_true, y_pred, y_score=None):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    roc_auc = None

    if y_score is not None:
        try:
            roc_auc = roc_auc_score(y_true, y_score)
        except ValueError:
            pass

    print(f"\n{name}")
    print("Accuracy :", round(accuracy * 100, 2), "%")
    print("Precision:", round(precision * 100, 2), "%")
    print("Recall   :", round(recall * 100, 2), "%")
    print("F1 Score :", round(f1 * 100, 2), "%")

    if roc_auc is not None:
        print("ROC-AUC  :", round(roc_auc * 100, 2), "%")

    print()
    print(
        classification_report(
            y_true,
            y_pred,
            target_names=["Safe", "Phishing"],
            zero_division=0,
        )
    )

    return {
        "model_name": name,
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "roc_auc": round(roc_auc * 100, 2) if roc_auc is not None else "N/A",
        "confusion_matrix": confusion_matrix(y_true, y_pred),
    }


def evaluate_model(name, model, x_test, y_test):
    predictions = model.predict(x_test)
    scores = None

    if hasattr(model, "predict_proba"):
        scores = model.predict_proba(x_test)[:, 1]

    return evaluate_predictions(
        name,
        y_test,
        predictions,
        scores,
    )


def evaluate_final_system(
    urls,
    lexical_features,
    lexical_model,
    hybrid_model,
    hybrid_features,
    y_test,
):
    lexical_scores = lexical_model.predict_proba(lexical_features)[:, 1]
    hybrid_scores = hybrid_model.predict_proba(hybrid_features)[:, 1]

    final_scores = []

    for i, url in enumerate(urls):
        features = lexical_features.iloc[i].tolist()

        raw_risk = (
            0.70 * lexical_scores[i]
            + 0.30 * hybrid_scores[i]
        )

        reasons = get_reasons_from_features(url, features)
        trusted = is_trusted_domain(url)

        final_risk = apply_confidence_calibration(
            raw_ml_risk=raw_risk,
            features=features,
            reasons=reasons,
            trusted=trusted,
        )

        final_scores.append(final_risk)

    predictions = [
        binary_label_from_risk_score(score)
        for score in final_scores
    ]

    return evaluate_predictions(
        "Final Calibrated System",
        y_test,
        predictions,
        final_scores,
    )


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

    path = os.path.join(MODEL_DIR, file_name)

    plt.savefig(path)
    plt.close()


def load_dataset():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}"
        )

    df = pd.read_csv(DATA_PATH)

    if df.shape[1] < 2:
        raise ValueError(
            "Dataset must contain URL and label columns."
        )

    df = df.iloc[:, :2].copy()
    df.columns = ["url", "label"]

    df = df.dropna(
        subset=["url", "label"]
    )

    df["url"] = df["url"].astype(str)

    df["label"] = (
        df["label"]
        .astype(str)
        .str.lower()
        .str.strip()
    )

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

    df["label"] = df["label"].map(label_map)
    df = df.dropna(subset=["label"])

    df["label"] = df["label"].astype(int)

    if df["label"].nunique() < 2:
        raise ValueError(
            "Dataset must contain both safe and phishing URLs."
        )

    if len(df) > 100000:
        df = df.sample(
            n=100000,
            random_state=42,
        )

    return df


def main():
    os.makedirs(
        MODEL_DIR,
        exist_ok=True,
    )

    print("Loading dataset...")

    df = load_dataset()

    print("Dataset size:", len(df))
    print(df["label"].value_counts())

    x_train_url, x_test_url, y_train, y_test = train_test_split(
        df["url"],
        df["label"],
        test_size=0.20,
        random_state=42,
        stratify=df["label"],
    )

    x_train_url = x_train_url.reset_index(drop=True)
    x_test_url = x_test_url.reset_index(drop=True)

    y_train = y_train.reset_index(drop=True)
    y_test = y_test.reset_index(drop=True)

    print("\nExtracting lexical features...")

    x_train_lexical = pd.DataFrame(
        x_train_url.apply(extract_features).tolist(),
        columns=FEATURE_NAMES,
    )

    x_test_lexical = pd.DataFrame(
        x_test_url.apply(extract_features).tolist(),
        columns=FEATURE_NAMES,
    )

    print("Creating TF-IDF features...")

    vectorizer = create_nlp_vectorizer()

    x_train_nlp = fit_transform_urls_for_nlp(
        x_train_url,
        vectorizer,
    )

    cleaned_test_urls = x_test_url.apply(
        clean_url_text
    )

    x_test_nlp = vectorizer.transform(
        cleaned_test_urls
    )

    x_train_hybrid = hstack([
        csr_matrix(x_train_lexical.values),
        x_train_nlp,
    ])

    x_test_hybrid = hstack([
        csr_matrix(x_test_lexical.values),
        x_test_nlp,
    ])

    print("Training Random Forest...")

    lexical_model = RandomForestClassifier(
        n_estimators=60,
        max_depth=18,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    lexical_model.fit(
        x_train_lexical,
        y_train,
    )

    print("Training hybrid Logistic Regression...")

    hybrid_model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
    )

    hybrid_model.fit(
        x_train_hybrid,
        y_train,
    )

    lexical_result = evaluate_model(
        "Lexical Random Forest Model",
        lexical_model,
        x_test_lexical,
        y_test,
    )

    hybrid_result = evaluate_model(
        "Hybrid NLP + Lexical Logistic Regression Model",
        hybrid_model,
        x_test_hybrid,
        y_test,
    )

    final_result = evaluate_final_system(
        x_test_url,
        x_test_lexical,
        lexical_model,
        hybrid_model,
        x_test_hybrid,
        y_test,
    )

    results = [
        lexical_result,
        hybrid_result,
        final_result,
    ]

    report_rows = []

    for result in results:
        report_rows.append({
            "Model": result["model_name"],
            "Accuracy": result["accuracy"],
            "Precision": result["precision"],
            "Recall": result["recall"],
            "F1 Score": result["f1_score"],
            "ROC-AUC": result["roc_auc"],
        })

    report = pd.DataFrame(report_rows)

    report.to_csv(
        os.path.join(
            MODEL_DIR,
            "model_evaluation_report.csv",
        ),
        index=False,
    )

    joblib.dump(
        lexical_model,
        os.path.join(
            MODEL_DIR,
            "phishing_model.pkl",
        ),
    )

    joblib.dump(
        vectorizer,
        os.path.join(
            MODEL_DIR,
            "nlp_model.pkl",
        ),
    )

    joblib.dump(
        hybrid_model,
        os.path.join(
            MODEL_DIR,
            "hybrid_model.pkl",
        ),
    )

    save_confusion_matrix(
        lexical_result["confusion_matrix"],
        "Lexical Random Forest Model",
        "confusion_matrix_lexical.png",
    )

    save_confusion_matrix(
        hybrid_result["confusion_matrix"],
        "Hybrid NLP + Lexical Model",
        "confusion_matrix_hybrid.png",
    )

    save_confusion_matrix(
        final_result["confusion_matrix"],
        "Final Calibrated System",
        "confusion_matrix_final.png",
    )

    save_confusion_matrix(
        hybrid_result["confusion_matrix"],
        "Hybrid NLP + Lexical Model",
        "confusion_matrix.png",
    )

    feature_importance = pd.DataFrame({
        "Feature": FEATURE_NAMES,
        "Importance": lexical_model.feature_importances_,
    })

    feature_importance = feature_importance.sort_values(
        "Importance"
    )

    plt.figure(figsize=(8, 7))

    plt.barh(
        feature_importance["Feature"],
        feature_importance["Importance"],
    )

    plt.xlabel("Importance")
    plt.title("Lexical Feature Importance")
    plt.tight_layout()

    plt.savefig(
        os.path.join(
            MODEL_DIR,
            "feature_importance.png",
        )
    )

    plt.close()

    print("\nTraining completed.")
    print()
    print(report.to_string(index=False))


if __name__ == "__main__":
    main()