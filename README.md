# BharatShield

BharatShield is a Python-based fraud detection project for identifying phishing URLs and suspicious scam messages. It combines lexical URL analysis, TF-IDF text features, machine learning models, trusted-domain checks, and rule-based risk calibration.

The project is intended as an educational/final-year computer science project. It should be used as a warning and analysis tool, not as a guaranteed security decision engine.

## Features

- Phishing URL detection with risk score, confidence score, and readable reasons
- Scam message detection for OTP, PIN, CVV, password, KYC, payment, urgency, and reward-bait patterns
- Embedded-link scanning when a message contains URLs
- Trusted-domain and redirect-link checks
- Streamlit dashboard for interactive scanning
- FastAPI service for API-based integration
- Model evaluation report, confusion matrices, and feature importance output
- Dataset hash, split checks, and training metadata for reproducibility
- Unit tests for message analysis, URL features, security rules, API endpoints, and model artifacts
- Docker support for running the FastAPI service in a clean environment

## Tech Stack

- Python
- Streamlit
- FastAPI
- scikit-learn
- pandas, NumPy, SciPy
- TF-IDF character n-grams
- Random Forest
- Logistic Regression
- tldextract
- joblib

## Project Structure

```text
BharatShield/
|-- api.py
|-- app.py
|-- config/
|   `-- trusted_domains.json
|-- data/
|   `-- phishing.csv
|-- docs/
|   |-- ablation_study.md
|   |-- dataset.md
|   |-- deployment.md
|   `-- model_card.md
|-- model/
|   |-- phishing_model.pkl
|   |-- nlp_model.pkl
|   |-- hybrid_model.pkl
|   |-- model_config.json
|   |-- model_evaluation_report.csv
|   |-- training_metadata.json
|   `-- reliability_curve.png
|-- src/
|   |-- features.py
|   |-- nlp_features.py
|   |-- predict.py
|   |-- scam_message.py
|   |-- security_layers.py
|   `-- train_model.py
|-- tests/
`-- requirements.txt
```

## Detection Approach

BharatShield uses two URL models:

- A Random Forest model trained on handcrafted lexical URL features
- A Logistic Regression model trained on lexical features plus TF-IDF character n-grams

The model scores are blended using weights stored in `model/model_config.json`. Security rules then calibrate the score for trusted official domains, suspicious TLDs, IP-address URLs, shortened links, redirect links, and other high-risk URL patterns.

For scam messages, the rule engine checks whether the text asks for sensitive information, creates urgency, threatens account/KYC blocking, requests payment, mentions remote-access tools, or contains suspicious links. If links are found, the URL detector scans them too.

## Current Model Report

The saved evaluation report is available at:

```text
model/model_evaluation_report.csv
```

Dataset hash, split sizes, overlap checks, package versions, and confusion counts are stored in:

```text
model/training_metadata.json
```

The current saved report shows the hybrid URL model performing strongest among the standalone ML models, with high recall for phishing detection. The final calibrated system intentionally favors recall because missing a fraud attempt is usually worse than showing an extra warning.

More details are documented in:

- `docs/model_card.md`
- `docs/dataset.md`
- `docs/ablation_study.md`
- `docs/deployment.md`

Latest retrained final-system metrics:

| Metric | Value |
| --- | ---: |
| Accuracy | 93.94% |
| Domain-Macro Accuracy | 91.17% |
| Precision | 81.14% |
| Recall | 91.75% |
| F1 Score | 86.12% |
| ROC-AUC | 97.86% |
| PR-AUC | 94.58% |
| False Positive Rate | 5.49% |
| False Positives | 897 |
| False Negatives | 347 |

## Setup

Create and activate a virtual environment:

```bash
py -m venv .venv
.venv\Scripts\activate
```

Install dependencies:

```bash
py -m pip install -r requirements.txt
```

## Run the Streamlit App

```bash
streamlit run app.py
```

## Run the API

```bash
uvicorn api:app --reload
```

Open the API documentation:

```text
http://127.0.0.1:8000/docs
```

Main API routes:

```text
GET  /health
POST /scan
POST /scan-message
```

The API rejects empty inputs and oversized inputs. Current limits are exposed by:

```text
GET /health
```

## Run with Docker

Build the image:

```bash
docker build -t bharatshield .
```

Run the API:

```bash
docker run --rm -p 8000:8000 bharatshield
```

Then open:

```text
http://127.0.0.1:8000/docs
```

## Run Tests

```bash
py -m unittest discover -s tests
```

## Retrain the Models

```bash
py src/train_model.py
```

Retraining writes updated model artifacts and evaluation files to the `model/` directory.

## Limitations

- The confidence score is a calibrated project score, not a guaranteed real-world probability.
- The exact dataset source and license are still unverified and must be added before formal submission.
- Results come from one dataset and should also be checked on an independent, time-separated dataset.
- Trusted-domain logic must be reviewed regularly because real services and hosting platforms change.
- Scam-message rules cover common Indian banking/payment patterns but cannot cover every social-engineering style.
- The project does not perform live web reputation lookup, WHOIS checks, DNS checks, or page-content analysis.
- This is suitable for learning, demos, and portfolio use, but not for production fraud blocking without more validation.
