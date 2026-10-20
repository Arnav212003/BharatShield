# BharatShield Model Card

## Project Goal

BharatShield warns about phishing-style URLs and scam messages before a user
opens a link or shares information such as an OTP, UPI PIN, CVV, or password.

## Intended Use

- Final-year project demonstration
- Portfolio discussion for machine learning, security, APIs, and testing
- Educational fraud-awareness experiments
- Local screening of URL and message patterns

## Not Intended For

- Automatic production blocking without independent validation
- Banking, legal, compliance, or law-enforcement decisions
- Replacing browser safe-browsing or bank fraud systems

## Training Data

The saved model was trained from a local two-column URL/label CSV with SHA-256:

```text
b1a7c26b354632c80817e10af154c4e5007f9480fb43a8ac2730491500fa2780
```

Its exact source and license are unverified. The raw CSV is therefore ignored
and not part of the current project tree. This limitation also means model
artifact usage rights should be confirmed before commercial deployment.

After duplicate/conflict removal, training uses a reproducible 100,000-row
sample. The test split has 20,532 rows: 16,325 safe and 4,207 phishing.
`docs/dataset.md` contains the complete cleanup and split record.

## Features And Models

The lexical model uses 22 features, including URL/domain length, punctuation,
digits, explicit HTTPS, suspicious words/TLDs, IP addresses, shortened domains,
query presence, and subdomain structure.

The hybrid model adds TF-IDF character n-grams. Current model scores are blended
with equal weights.

Training uses a root-domain group split. The validation split selects blend
weights and evaluates 20 threshold/policy combinations. The test split is not
used for those choices. The current selection is:

```text
alert threshold: 0.50
phishing display threshold: 0.70
risk policy: no_adjustment
clean trusted-host maximum: 0.20
```

Candidate pattern bonuses and reductions do not modify the current model score.
A separate fixed guard caps a clean exact-host allowlist match at `0.20`.
Redirects, user-hosted pages, HTTP URLs, and `@`-symbol URLs do not receive that
cap. The rule layer also reports observed signals and redirect behavior.

## Evaluation

| Metric | Value |
| --- | ---: |
| Accuracy | 95.20% |
| Domain-Macro Accuracy | 92.97% |
| Precision | 86.75% |
| Recall | 90.40% |
| F1 Score | 88.53% |
| ROC-AUC | 98.13% |
| PR-AUC | 95.06% |
| Brier Score | 0.0593 |
| False Positive Rate | 3.56% |
| True Negatives | 15,744 |
| False Positives | 581 |
| False Negatives | 404 |
| True Positives | 3,803 |

The test set phishing share is 20.49%. At an assumed 1% prevalence, the test
recall and false-positive rate imply about 20.42% precision. This estimate
assumes those rates transfer unchanged, which may not hold after deployment.

## Explainability

The UI reports readable reasons generated from URL and message signals. These
are deterministic rule explanations, not a claim that each reason caused the
model prediction. `model/feature_importance.png` provides global permutation
importance on validation data; it is not a per-URL explanation.

The displayed score certainty is based on distance from decision cutoffs and
model agreement. It is a UI heuristic, not a calibrated probability.

## Reproducibility

- Python: 3.11.9
- scikit-learn: 1.8.0
- NumPy: 1.26.4
- SciPy: 1.17.1
- pandas: 2.3.3
- joblib: 1.5.3
- tldextract: 5.3.1
- Random seed: 42

Exact settings, split checks, and package versions are saved in
`model/training_metadata.json`. Runtime, training, and development dependencies
are pinned in separate requirement files.

## Known Limitations

- Dataset provenance and licensing are unresolved.
- Evaluation is from one dataset and one group split, not a recent temporal or
  independently sourced holdout.
- Most training URLs are scheme-less, so the explicit HTTPS feature has very
  little support in this dataset.
- The largest test domain contributes 13.41% of test rows.
- Trusted-domain and message-pattern lists require manual maintenance.
- The message detector is rule-based and has no labeled message benchmark.
- No page content, WHOIS, DNS, certificate, or live reputation data is used.
- Adversaries and legitimate URL patterns can change after training.

## Next Validation Work

- Confirm or replace the training dataset with a licensed source.
- Evaluate on a time-separated and independently collected URL set.
- Build a labeled Indian SMS/email benchmark for the message rules.
- Measure latency and error rates in a controlled deployment.
- Review false positives and false negatives by domain and attack type.
