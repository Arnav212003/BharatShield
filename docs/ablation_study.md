# Ablation Study

This table shows how each layer improves the system. The values come from the latest `model/model_evaluation_report.csv`.

| System | Accuracy | Domain-Macro Accuracy | Precision | Recall | FPR | F1 Score | ROC-AUC | PR-AUC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Lexical Random Forest | 84.03% | 79.06% | 57.06% | 89.18% | 17.29% | 69.60% | 93.40% | 85.48% |
| Hybrid NLP + Lexical Logistic Regression | 88.10% | 83.24% | 64.42% | 93.63% | 13.33% | 76.32% | 97.04% | 92.24% |
| ML only blend | 89.64% | 85.43% | 67.31% | 96.13% | 12.03% | 79.18% | 98.13% | 95.06% |
| Final system, ML + rules | 93.94% | 91.17% | 81.14% | 91.75% | 5.49% | 86.12% | 97.86% | 94.58% |

## Observation

The hybrid model improves over the lexical-only model because character TF-IDF captures phishing-style text patterns inside URLs. The blended ML model gets the best recall, but it still has a higher false-positive rate.

The final rule layer improves precision and F1 score. It also reduces false positives from 12.03% to 5.49%. This is useful for a fraud-warning tool because users should not see too many unnecessary alerts.

Domain-macro accuracy gives every root domain equal weight. The final system scores 91.17% on this measure, compared with 93.94% row-level accuracy, so the effect of large domains is visible instead of hidden.

## Trade-off

The final system has slightly lower recall than the ML-only blend, but it gives a better balance between catching fraud and avoiding false alarms. For a student project and demo use case, this is a reasonable trade-off.
