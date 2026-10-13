# Ablation Study

This table shows how each layer improves the system. The values come from the latest `model/model_evaluation_report.csv`.

| System | Accuracy | Precision | Recall | FPR | F1 Score | ROC-AUC | PR-AUC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Lexical Random Forest | 84.02% | 57.05% | 88.95% | 17.26% | 69.52% | 93.56% | 85.51% |
| Hybrid NLP + Lexical Logistic Regression | 88.25% | 64.75% | 93.58% | 13.13% | 76.54% | 97.09% | 92.37% |
| ML only blend | 89.72% | 67.48% | 96.17% | 11.94% | 79.31% | 98.16% | 95.09% |
| Final system, ML + rules | 93.92% | 81.07% | 91.73% | 5.52% | 86.07% | 97.89% | 94.61% |

## Observation

The hybrid model improves over the lexical-only model because character TF-IDF captures phishing-style text patterns inside URLs. The blended ML model gets the best recall, but it still has a higher false-positive rate.

The final rule layer improves precision and F1 score. It also reduces false positives from 11.94% to 5.52%. This is useful for a fraud-warning tool because users should not see too many unnecessary alerts.

## Trade-off

The final system has slightly lower recall than the ML-only blend, but it gives a better balance between catching fraud and avoiding false alarms. For a student project and demo use case, this is a reasonable trade-off.
