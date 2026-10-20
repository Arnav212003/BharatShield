import math

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    roc_auc_score,
)


def wilson_interval(successes, total, z=1.96):
    """95% confidence interval for a rate like recall or FPR."""
    if total <= 0:
        return None

    rate = successes / total
    denominator = 1 + z * z / total
    centre = rate + z * z / (2 * total)
    spread = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total))

    return (
        round(max(0.0, (centre - spread) / denominator), 6),
        round(min(1.0, (centre + spread) / denominator), 6),
    )


def binary_metrics(y_true, scores, threshold):
    y_true = np.asarray(y_true, dtype=int)
    scores = np.asarray(scores, dtype=float)
    predictions = (scores >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    tn, fp, fn, tp = int(tn), int(fp), int(fn), int(tp)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    both_classes = (tp + fn) > 0 and (tn + fp) > 0

    return {
        "rows": int(len(y_true)),
        "threshold": float(threshold),
        "accuracy": (tp + tn) / len(y_true),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "roc_auc": float(roc_auc_score(y_true, scores)) if both_classes else None,
        "pr_auc": float(average_precision_score(y_true, scores)) if both_classes else None,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "recall_95_ci": wilson_interval(tp, tp + fn),
        "fpr_95_ci": wilson_interval(fp, fp + tn),
    }


def pick_safe_cutoff(y_true, scores, min_recall=0.90):
    """Highest-F1 cutoff that still catches at least min_recall of phishing."""
    results = [
        binary_metrics(y_true, scores, cutoff)
        for cutoff in np.arange(0.30, 0.71, 0.05).round(2)
    ]
    good_enough = [item for item in results if item["recall"] >= min_recall] or results

    return max(good_enough, key=lambda item: (item["f1"], -item["fpr"]))


def pick_phishing_cutoff(y_true, scores, safe_cutoff, min_precision=0.98):
    """Lowest cutoff above the safe one where 'Phishing' is almost always right."""
    for cutoff in np.arange(safe_cutoff + 0.10, 0.96, 0.05).round(2):
        result = binary_metrics(y_true, scores, cutoff)

        if result["precision"] >= min_precision:
            return result

    return binary_metrics(y_true, scores, 0.95)


def pick_blend_weight(y_true, lexical_scores, hybrid_scores):
    """Weight for the first (URL feature) model in the blend, chosen by PR-AUC."""
    best_weight, best_score = 0.5, -1.0

    for weight in np.arange(0, 1.01, 0.1).round(1):
        blended = weight * lexical_scores + (1 - weight) * hybrid_scores
        score = average_precision_score(y_true, blended)

        if score > best_score + 1e-4:
            best_weight, best_score = float(weight), score

    return best_weight
