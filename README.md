# BharatShield

[![Tests](https://github.com/Arnav212003/BharatShield/actions/workflows/tests.yml/badge.svg)](https://github.com/Arnav212003/BharatShield/actions/workflows/tests.yml)

BharatShield is a final-year computer science project for screening phishing
URLs and scam-style messages. The URL scanner combines lexical features with
TF-IDF character features and two machine-learning models. The message scanner
uses readable rules for OTP, PIN, payment, urgency, KYC, and social-engineering
patterns.

This is an educational warning tool. It is not a replacement for a browser,
bank, or production fraud-detection system.

## Features

- URL risk classification with a risk score and readable reasons
- Separate handling for explicit HTTP, explicit HTTPS, and scheme-less URLs
- Rule-based scam message detection and embedded-link scanning
- Static trusted-domain and redirect-link checks
- Streamlit interface and FastAPI endpoints
- Domain-separated train, validation, and test splits
- Saved metrics, confusion matrices, reliability curve, and feature importance
- Dataset hash, duplicate counts, split checks, and dependency versions
- Docker image running as a non-root user with a health check
- Unit tests, compilation checks, Ruff linting, and mypy checks in GitHub Actions

## Project Structure

```text
BharatShield/
|-- .github/workflows/tests.yml
|-- api.py
|-- app.py
|-- config/trusted_domains.json
|-- data/
|   |-- README.md
|   `-- provenance.json
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
|   `-- evaluation PNG files
|-- src/
|   |-- features.py
|   |-- nlp_features.py
|   |-- predict.py
|   |-- scam_message.py
|   |-- security_layers.py
|   `-- train_model.py
|-- tests/
|-- ui/
|-- Dockerfile
|-- LICENSE
|-- pyproject.toml
|-- requirements.txt
|-- requirements-api.txt
|-- requirements-core.txt
|-- requirements-dev.txt
`-- requirements-train.txt
```

The training CSV is local-only and ignored by Git because its original source
and license have not been verified. See `data/README.md` before retraining.

## Detection Approach

The URL pipeline has two models:

1. A Random Forest trained on 22 lexical URL features.
2. Logistic Regression trained on the lexical features plus TF-IDF character
   n-grams.

The validation split chooses the blend weights, alert threshold, and one of the
candidate score-adjustment policies. The final test split is used only after
those choices are fixed. For the current model, validation selected equal model
weights, a `0.50` alert threshold, and `no_adjustment`. Candidate pattern
bonuses and reductions are therefore disabled. A separate fixed guard caps
clean, exact allowlisted hosts at `0.20`; redirects, user-hosted pages, HTTP
URLs, and `@`-symbol URLs are excluded from that guard.

The message scanner is rule-based. It is not presented as a trained NLP model.

## Current Evaluation

The test set has 20,532 rows: 16,325 safe and 4,207 phishing URLs. It contains
8,710 root domains, with zero root-domain or normalized-URL overlap with the
training and validation splits.

Current final-system test metrics:

| Metric | Value |
| --- | ---: |
| Accuracy | 95.20% |
| Domain-Macro Accuracy | 92.97% |
| Precision | 86.75% |
| Recall | 90.40% |
| F1 Score | 88.53% |
| ROC-AUC | 98.13% |
| PR-AUC | 95.06% |
| False Positive Rate | 3.56% |
| False Positives | 581 |
| False Negatives | 404 |

At an assumed phishing prevalence of 1%, the same test recall and false-positive
rate imply an estimated precision of 20.42%. This estimate is included to show
why precision from a 20.49%-phishing test set should not be treated as a fixed
real-world property.

### Change From The Previous Saved Model

| Metric | Before | Current |
| --- | ---: | ---: |
| Accuracy | 93.94% | 95.20% |
| Precision | 81.14% | 86.75% |
| Recall | 91.75% | 90.40% |
| F1 Score | 86.12% | 88.53% |
| False Positives | 897 | 581 |
| False Negatives | 347 | 404 |

The selected threshold reduced false positives and improved precision and F1,
but recall fell by 1.35 percentage points and false negatives increased by 57.
Both sides of that trade-off are reported.

Full results and reproducibility details are stored in:

```text
model/model_evaluation_report.csv
model/training_metadata.json
```

## Setup

Use Python 3.11.9, which matches the saved model metadata and CI.

```bash
py -3.11 -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

`requirements.txt` installs the Streamlit runtime. Other environments use:

| File | Purpose |
| --- | --- |
| `requirements-api.txt` | FastAPI and Docker runtime |
| `requirements-train.txt` | Model training and plots |
| `requirements-dev.txt` | All dependencies used by tests and CI |

## Run The App

```bash
streamlit run app.py
```

## Run The API

```bash
python -m pip install -r requirements-api.txt
uvicorn api:app --reload
```

Open `http://127.0.0.1:8000/docs` for the generated API documentation.

Main routes:

```text
GET  /health
POST /scan
POST /scan-message
```

The health route reports model readiness, model generation time, input limits,
and the active safe/suspicious cutoff.

## Run Tests

```bash
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m mypy api.py src
python -m compileall -q api.py app.py src tests
python -m unittest discover -s tests
```

GitHub Actions runs the same checks on pushes and pull requests to `main`.

## Retrain The Models

First place a legally obtained two-column dataset at `data/phishing.csv` and
record its real provenance in `data/provenance.json`.

```bash
python -m pip install -r requirements-train.txt
python -m src.train_model
```

To write candidate artifacts without replacing the working model, set
`BHARATSHIELD_MODEL_DIR` to another directory before running training.

## Docker

```bash
docker build -t bharatshield .
docker run --rm -p 8000:8000 bharatshield
```

The image contains only API/runtime dependencies and runs as an unprivileged
user. More public-deployment notes are in `docs/deployment.md`.

## Limitations

- Dataset source and license remain unverified. The raw CSV is not distributed
  by the current project tree, and the code license does not cover that data.
- Saved model artifacts were trained from that unverified dataset hash. Confirm
  data rights before commercial or public production use.
- Results come from one reproducible domain-group split, not an independent
  time-separated dataset.
- The score-certainty value is a cutoff-distance heuristic, not a probability.
- Readable reasons are rule-based explanations of observed URL/message signals;
  they are not per-prediction SHAP explanations of the model.
- The trusted-domain list is static and must be maintained.
- There is no live reputation, WHOIS, DNS, certificate, or page-content lookup.
- Public deployments still need gateway-level rate limiting, HTTPS, monitoring,
  and authentication where appropriate.

## License

The project code and documentation are available under the MIT License in
`LICENSE`. Third-party datasets are not covered by that license.
