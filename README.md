# BharatShield

[![Tests](https://github.com/Arnav212003/BharatShield/actions/workflows/tests.yml/badge.svg)](https://github.com/Arnav212003/BharatShield/actions/workflows/tests.yml)

BharatShield checks links and messages for phishing and common Indian scams
(fake KYC, electricity disconnection, "digital arrest", lottery, task jobs and
so on). It is my final-year computer science project.

- **URL scanner:** two machine learning models plus a few clear rules
  (brand impersonation, IP addresses, redirects, short links, free hosting).
- **Message scanner:** readable rules for OTP/PIN requests and 14 scam patterns,
  in English and Hinglish. Links inside the message go through the URL scanner.
- Streamlit app, FastAPI service, Docker image, and GitHub Actions CI.

It is a second opinion, not a guarantee. It does not open the link or look up
the domain online.

## Results

Measured on an **external test set**: phishing URLs first seen *after* the
training cutoff date (Sep 15 to Oct 20, 2026) from websites the model never saw,
mixed with normal pages and homepages from sites it never saw.

| | Precision | Recall | F1 | False positive rate |
| --- | ---: | ---: | ---: | ---: |
| External test (35,988 URLs) | 89.7% | 92.0% | 90.8% | 3.7% |
| Internal test (83,974 URLs, unseen sites) | 93.2% | 93.1% | 93.1% | 2.4% |

Normal web pages are flagged 1.9% of the time; random homepages from the
Tranco list 8.0% (some of those really are spam sites). Simple checks that
the first version got wrong now work:

| URL | Version 1 | Now |
| --- | --- | --- |
| `google.com` | Phishing, 100 | Safe, 20 |
| `amazon.in` | Phishing, 100 | Safe, 20 |
| `https://sbi-kyc-update.com` | Phishing, 92 | Phishing, 100 |
| `https://accounts.google.com.evil.tk` | Phishing, 77 | Phishing, 100 |

The [model card](docs/model_card.md) has the full numbers, the internal test,
and what the rules change.

## The bug that changed this project

The first version scored **99.58%** accuracy on the PhiUSIIL dataset. Then I
typed `google.com` into the app and it said phishing, 100%.

It turned out every legitimate URL in PhiUSIIL looks exactly like
`https://www.<domain>`, and nothing else. The model had learned "no `https://www.`
means phishing". Without that shortcut the same approach dropped to about 0.67
F1 on fresh phishing.

What I changed:

1. The model never sees `http://`, `https://` or `www.` now. A unit test checks
   that `google.com`, `http://google.com` and `https://www.google.com` get the
   same score.
2. New training data with real web pages that have paths (Common Crawl) and
   dated phishing (OpenPhish).
3. A time-based external test, so the reported number is for phishing the model
   could not have seen.

Details: [docs/dataset.md](docs/dataset.md).

## How a URL is scored

```text
URL ──> canonical key ──┬─> 17 URL features ──> gradient boosting ──┐
(no scheme, no www)     │                                           ├─> blend ──> ML score
                        └─> TF-IDF char 3-5 grams ─> logistic reg. ─┘
                                                                         │
config/trusted_domains.json ──> rules (brand, IP, @, redirect, ...) <─────┘
                                                                         │
                                                  Safe / Suspicious / Phishing + reasons
```

- **Models:** gradient boosted trees on 17 numeric features (length, path depth,
  digits, entropy of the domain name, keywords, ...) and logistic regression on
  the same features plus TF-IDF character n-grams. Validation picks the blend
  weight and the two cutoffs.
- **Rules that change the score:** brand name on a domain that is not the brand's
  (`sbi-kyc-update.com`, `paypa1.com`), IP address host, `@` trick, punycode,
  redirect to another site. Short links are never "Safe". Pages on free hosting
  (github.io, pages.dev, ...) stay "Suspicious" unless a brand is misused.
- **Trusted list:** about 70 Indian and global sites plus every `.gov.in`,
  `.nic.in` and `.bank.in` domain. A trusted domain behind a redirect, an IP or
  an `@` is not trusted.
- **Reasons:** every result explains itself, for example *"Uses the name 'sbi'
  but is not its official website"*.

## Project structure

```text
BharatShield/
|-- app.py                   Streamlit app
|-- api.py                   FastAPI service
|-- config/trusted_domains.json
|-- data/                    sources.json, dataset_summary.json (data files are local)
|-- docs/                    dataset.md, model_card.md, deployment.md
|-- model/                   trained models, config, reports and charts
|-- scripts/
|   |-- download_data.py     download the five data sources
|   `-- build_dataset.py     build train and external test sets
|-- src/
|   |-- url_utils.py         parsing, validation, canonical key
|   |-- features.py          the 17 URL features
|   |-- nlp_features.py      TF-IDF settings
|   |-- security_layers.py   trusted list, brand check, rules, reasons
|   |-- predict.py           load models and score a URL
|   |-- scam_message.py      message rules
|   |-- evaluation.py        metrics and cutoff selection
|   `-- train_model.py       training and evaluation
|-- tests/                   unit tests (+ tests/data/sample_messages.csv)
`-- ui/style.py
```

## Setup

Python 3.11.

```bash
py -3.11 -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt
```

| File | For |
| --- | --- |
| `requirements.txt` | Streamlit app |
| `requirements-api.txt` | FastAPI and Docker |
| `requirements-train.txt` | Training and charts |
| `requirements-dev.txt` | Everything, plus test tools |

## Run

```bash
streamlit run app.py
```

API:

```bash
python -m pip install -r requirements-api.txt
uvicorn api:app --reload
```

Open `http://127.0.0.1:8000/docs`. Routes: `GET /health`, `POST /scan`,
`POST /scan-message`.

```bash
curl -X POST http://127.0.0.1:8000/scan -H "Content-Type: application/json" \
     -d "{\"url\": \"https://sbi-kyc-update.com/login\"}"
```

Docker:

```bash
docker build -t bharatshield .
docker run --rm -p 8000:8000 bharatshield
```

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m mypy .
python -m unittest discover -s tests
```

GitHub Actions runs the same checks on every push and pull request to `main`.

## Retrain

```bash
python -m pip install -r requirements-train.txt
python -m scripts.download_data     # ~260 MB, needs git for the OpenPhish history
python -m scripts.build_dataset     # --cutoff 2026-09-15 by default
python -m src.train_model           # about 10 minutes on a laptop
```

## Limitations

- URL only. No page content, WHOIS, domain age, DNS or certificate checks.
  A phishing page on an ordinary-looking domain (`www.wbdrcw.com`) is hard to
  catch from the URL alone.
- Phishing changes fast. The model should be retrained every few weeks.
- Free hosting pages have almost no legitimate examples in the data, so a normal
  `name.github.io` page shows as "Suspicious".
- The trusted list and brand list are maintained by hand.
- The message scanner is rule-based. I wrote the sample messages myself and
  tuned the rules on them, so there is no independent accuracy number for it.
- Most phishing in the feeds is global, not India-specific.

## Credits and license

Code is MIT licensed (see `LICENSE`). Data comes from Common Crawl, Majestic
Million (CC BY 3.0), Tranco (Le Pochat et al., NDSS 2019), the OpenPhish
community feed (non-commercial use) and Phishing.Database (MIT). The data files
are not included in this repository. See [data/README.md](data/README.md).
