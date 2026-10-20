# Ablation Study

Every number here comes from files written by `python -m src.train_model`
(`model/model_evaluation_report.csv` and `model/training_metadata.json`).

All rows use the validated safe cutoff of 0.50.

## 1. Which model parts help (internal test)

Site-grouped internal test, 83,974 rows, 26.2% phishing. No site in this split
appears in training or validation.

| System | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Gradient boosting (17 URL features) | 91.65% | 83.47% | 84.92% | 84.19% | 5.96% | 96.00% | 92.80% |
| Logistic regression (features + TF-IDF) | 95.62% | 91.82% | 91.43% | 91.62% | 2.89% | 98.87% | 97.49% |
| ML blend (0.3 / 0.7) | 96.43% | 93.30% | 93.05% | 93.17% | 2.37% | 98.98% | 97.78% |
| Final system (ML + rules) | 96.41% | 93.21% | 93.08% | 93.14% | 2.40% | 98.82% | 96.99% |

- The TF-IDF character n-grams carry most of the signal: logistic regression is
  about 7 F1 points better than gradient boosting on the numeric features alone.
- The blend is better than either model, mainly because it cuts false positives
  (2.37% vs 2.89% for logistic regression alone).

## 2. What the rules change (external test)

Time-separated external test, 35,988 rows (see [dataset.md](dataset.md)).

| System | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ML blend | 89.83% | 91.93% | 90.87% | 3.64% | 98.50% | 97.09% |
| Final system (ML + rules) | 89.67% | 91.95% | 90.80% | 3.71% | 97.96% | 94.60% |

Share flagged (score >= 0.50) by slice, before and after the rules:

| Slice | Rows | ML only | Final |
| --- | ---: | ---: | ---: |
| OpenPhish phishing | 9,330 | 91.93% | 91.95% |
| Phishing on free hosting | 6,320 | 99.95% | 99.95% |
| Phishing with a brand name in the URL | 195 | 99.49% | 100.00% |
| Common Crawl legitimate | 18,658 | 1.83% | 1.88% |
| Tranco legitimate | 8,000 | 7.88% | 7.96% |
| Legitimate on free hosting | 180 | 11.11% | 11.11% |
| Legitimate with a brand name in the URL | 14 | 35.71% | 100.00% |

**The rules do not improve the overall numbers.** F1 is 0.07 points lower and
PR-AUC drops because the fixed caps and floors flatten the score ranking. They
are kept because:

- they give plain-language reasons ("Uses the name 'sbi' but is not its
  official website"),
- they cover cheap tricks (brand names, `@`, IP hosts, short links) with a
  predictable result instead of depending on the model.

The cost is real: every one of the 14 "legitimate" URLs with a brand name was
flagged, because brand misuse is never allowed to be "Safe". Looking at them:

- 6 are sketchy sites that are only labelled legitimate because they are on a
  list (`microsoftdownloaderonline.com`, `e-appleclub.xyz`, `googlebbs.top`,
  `acheter-followers-instagram.com`, `amazonaws.org`, `yonogames8.com`).
- 5 are name collisions where a word starts with a brand (`applelix.com`,
  `appleseeds.org.il`, `pink-apple.ru`, `kotaku.id` matching "kotak",
  `amazon-ranking.com`).
- 3 are real brand-related sites missing from the brand list
  (`amazonappstream.com`, `paypal-press.fr`, `icicibankrussia.com`).

So the prefix matching in `brand_in_label` and the hand-made brand list are
both sources of false alarms. The sample is small.

## 3. Choices made on validation

From `model/training_metadata.json` (validation split, 83,974 rows):

| Setting | Value | Rule |
| --- | --- | --- |
| Blend weights | 0.3 gradient boosting, 0.7 logistic regression | Highest PR-AUC over weights 0.0 to 1.0 |
| Safe cutoff | 0.50 | Highest F1 with recall >= 90% |
| Phishing cutoff | 0.80 | Lowest cutoff with precision >= 98% |

At the 0.50 cutoff, validation precision was 92.62%, recall 91.31%, F1 91.96%,
FPR 2.58%.

## 4. Historical note

Earlier exploratory experiments, run with temporary scripts that are not in
this repository, motivated the current design: training on hostnames or URLs
without the scheme instead of PhiUSIIL, the current mix of training sources,
and gradient boosting instead of a random forest for the numeric features.
Their numbers are not reported here because they cannot be reproduced from
the repository.
