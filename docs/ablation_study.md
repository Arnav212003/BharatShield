# Ablation Study

These values come from `model/model_evaluation_report.csv`. Every row uses the
same untouched domain-separated test split and the `0.50` threshold selected on
validation data.

| System | Accuracy | Domain-Macro Accuracy | Precision | Recall | FPR | F1 | ROC-AUC | PR-AUC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Lexical Random Forest | 90.25% | 85.41% | 76.36% | 75.92% | 6.06% | 76.14% | 93.40% | 85.48% |
| Hybrid NLP + Lexical Logistic Regression | 91.47% | 87.96% | 75.00% | 87.57% | 7.52% | 80.80% | 97.03% | 92.21% |
| Equal-weight ML blend | 95.20% | 92.97% | 86.75% | 90.40% | 3.56% | 88.53% | 98.13% | 95.06% |
| Final validated policy | 95.20% | 92.97% | 86.75% | 90.40% | 3.56% | 88.53% | 98.13% | 95.06% |

## What Changed

The hybrid model improves recall over the lexical-only model because character
TF-IDF captures spelling and token patterns that handcrafted counts can miss.
Blending both models gives the strongest F1 score and lowest false-positive
rate in this comparison.

Four score policies and five thresholds were compared on the validation split.
Only candidates with at least 90% validation recall were considered when that
constraint could be met. The winning setup used equal model weights, threshold
`0.50`, and the `no_adjustment` policy.

The last two rows are therefore identical. This is intentional: validation did
not support the candidate pattern bonuses or reductions, so the current runtime
does not apply them. A fixed exact-host trusted guard still exists, but it did
not change a test-set classification at the selected threshold. Security rules
also provide readable reasons, redirect detection, and trusted-list reporting.

## Remaining Trade-off

The final test confusion matrix is:

```text
TN = 15,744   FP = 581
FN =    404   TP = 3,803
```

The test set contains 20.49% phishing URLs. If phishing prevalence were 1% and
the same recall/FPR held, estimated precision would be about 20.42%. This is a
scenario calculation, not a measurement from production traffic.
