# BharatShield Model Card

## Project Goal

BharatShield detects suspicious URLs and scam-style messages. The goal is to give users an explainable warning before they open a phishing link or share sensitive information such as OTP, UPI PIN, CVV, passwords, or card details.

## Intended Use

- Final-year computer science project demonstration
- Portfolio project for AI, cybersecurity, and backend/API skills
- Educational fraud-awareness tool
- Local testing of URL and message risk patterns

## Not Intended For

- Production fraud blocking without additional validation
- Legal, banking, or compliance decisions
- Replacing browser security systems, bank fraud systems, or official cybercrime reporting

## Data

The URL dataset is stored in `data/phishing.csv` with two columns:

- `URL`
- `Label`

Supported labels are normalized during training. Malicious labels such as `bad`, `phishing`, `fraud`, `malicious`, and `unsafe` map to `1`. Safe labels such as `good`, `safe`, `legitimate`, and `benign` map to `0`.

The current repository dataset contains more safe URLs than phishing URLs, so the training code uses balanced class weights. A short dataset profile is available in `docs/dataset.md`.

## Feature Design

The URL model uses lexical features such as:

- URL length
- Domain length
- Number of dots, hyphens, slashes, query markers, digits, and special characters
- HTTPS flag
- IP-address usage
- Suspicious keywords
- Shortened-link domains
- Suspicious TLDs
- Subdomain count
- Hyphen or digit usage in the domain

The hybrid model combines these lexical features with TF-IDF character n-grams. Character n-grams are useful for phishing URLs because attackers often use small spelling changes, fake brand words, or unusual token patterns.

## Model Pipeline

Training is handled by `src/train_model.py`.

1. Load and normalize the dataset.
2. Remove duplicate and conflicting URLs.
3. Split by root domain to reduce domain memorization.
4. Train a Random Forest model on lexical features.
5. Train a Logistic Regression model on lexical + TF-IDF features.
6. Select blend weights on validation data.
7. Evaluate the final model on the test split.
8. Save model artifacts, metrics, confusion matrices, feature importance, and blend config.

## Explainability

`src/security_layers.py` converts URL features into human-readable reasons, such as:

- No HTTPS found
- Suspicious keyword found
- IP address used in URL
- Shortened URL detected
- Suspicious domain extension found
- Too many subdomains
- Trusted official domain detected

The message scanner also reports reasons such as sensitive information requests, urgency, account-blocking threats, reward bait, payment requests, and suspicious embedded links.

## Evaluation

Saved metrics are stored in:

```text
model/model_evaluation_report.csv
```

The project reports accuracy, precision, recall, F1 score, ROC-AUC, threshold, false-positive rate, PR-AUC, and Brier score for the saved models.

Latest retrained final-system metrics:

| Metric | Value |
| --- | ---: |
| Accuracy | 93.92% |
| Precision | 81.07% |
| Recall | 91.73% |
| F1 Score | 86.07% |
| ROC-AUC | 97.89% |
| PR-AUC | 94.61% |
| False Positive Rate | 5.52% |

For a fraud-warning system, recall is especially important because a missed phishing URL can cause real harm. Precision still matters because too many false alarms reduce user trust.

The layer-by-layer comparison is available in `docs/ablation_study.md`.

## Known Limitations

- The system does not fetch live pages or inspect page content.
- The trusted-domain list is static and must be maintained.
- Attackers can create new TLD, redirect, and message patterns.
- The scam-message detector is rule-based and should be expanded with real labeled SMS/email data before production use.
- The confidence score is a decision-support score, not a mathematical guarantee.

## Future Improvements

- Add WHOIS/domain-age signals.
- Add DNS and certificate metadata.
- Add live URL reputation sources.
- Add multilingual scam-message examples.
- Add CI checks for tests and linting.
- Track dataset version and training run metadata.
