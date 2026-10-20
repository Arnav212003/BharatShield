# BharatShield

[![Tests](https://github.com/Arnav212003/BharatShield/actions/workflows/tests.yml/badge.svg)](https://github.com/Arnav212003/BharatShield/actions/workflows/tests.yml)

**Live demo: <https://bharatshield-arnav.streamlit.app>**

BharatShield checks links and messages for phishing and common Indian scams
(fake KYC, electricity disconnection, "digital arrest", lottery, task jobs and
so on). It is my final-year computer science project.

- **URL scanner:** two machine learning models plus a few clear rules
  (brand impersonation, IP addresses, redirects, short links, free hosting).
- **Message scanner:** readable rules for OTP/PIN requests and 14 scam
  patterns, in English and Hinglish. Links inside the message go through the
  URL scanner.
- Streamlit app, FastAPI service, Docker image, and GitHub Actions CI.

It is a second opinion, not a guarantee. It only looks at the URL text: it does
not open the page or look up the domain online.

## Results

Numbers from `model/model_evaluation_report.csv`, final system (ML + rules),
safe cutoff 0.50:

| Test set | Rows | Precision | Recall | F1 | False positive rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| External (time-separated, unseen sites) | 35,988 | 89.67% | 91.95% | 90.80% | 3.71% |
| Internal (site-grouped split) | 83,974 | 93.21% | 93.08% | 93.14% | 2.40% |

The **external** test is the one to quote. Its phishing URLs were first seen
on OpenPhish between Sep 15 and Oct 20, 2026, after every phishing URL used for
training, and come from sites the model never saw. The legitimate side is
held-out Common Crawl pages (flagged 1.88% of the time) and Tranco homepages
(flagged 7.96%, partly because Tranco also lists spam sites).

Simple checks that the first version got wrong:

| URL | Version 1 | Now |
| --- | --- | --- |
| `google.com` | Phishing, 100 | Safe, 20 |
| `http://www.google.com` | Phishing, 100 | Safe, 20 |
| `amazon.in` | Phishing, 100 | Safe, 20 |
| `https://www.flipkart.com/` | Suspicious, 53 | Safe, 12 |
| `https://sbi-kyc-update.com` | Phishing, 92 | Phishing, 100 |
| `https://accounts.google.com.evil.tk` | Phishing, 77 | Phishing, 100 |

More detail: [model card](docs/model_card.md), [ablation study](docs/ablation_study.md),
[dataset notes](docs/dataset.md).

## The bug that changed this project

The first version was trained on the PhiUSIIL dataset and scored **99.58%**
accuracy on its test split. Then I typed `google.com` into the app and it said
phishing, 100%.

Every legitimate URL in PhiUSIIL looks exactly like `https://www.<domain>`.
None of them use `http://`, have a path, or skip `www.`. The model had learned
"not `https://www.something` = phishing".

What I changed:

1. The model never sees `http://`, `https://` or `www.`. A unit test checks that
   `google.com`, `http://google.com` and `https://www.google.com` get the same
   features and the same score.
2. New training data with real web pages that have paths (Common Crawl),
   popular homepages (Majestic Million) and dated phishing (OpenPhish,
   Phishing.Database). PhiUSIIL is no longer used.
3. A time-separated external test, so the reported number is for phishing the
   model could not have seen.

## How a URL is scored

```text
URL ──> canonical key ──┬─> 17 URL features ──> gradient boosting ──────┐ x 0.3
(no scheme, no www)     │                                                ├─> ML score
                        └─> 17 features + TF-IDF char 3-5 grams ─> LR ───┘ x 0.7
                                                                         │
config/trusted_domains.json ──> rules (brand, IP, @, redirect, ...) <────┘
                                                                         │
                     Safe (< 0.50) / Suspicious / Phishing (>= 0.80) + reasons
```

- **Models:** `HistGradientBoostingClassifier` on 17 numeric features (length,
  path depth, digits, entropy of the domain name, keywords, ...) and
  `LogisticRegression` on the same features plus 50,000 TF-IDF character
  n-grams. The 0.3 / 0.7 blend weights and the 0.50 / 0.80 cutoffs were picked
  on the validation split.
- **Rules that change the score:** a brand name on a domain that is not the
  brand's (`sbi-kyc-update.com`, `paypa1.com`), an IP address host, the `@`
  trick, punycode, and a redirect to another site. Short links and brand misuse
  are never "Safe". Pages on free hosting (github.io, pages.dev, ...) stay
  "Suspicious" unless a brand is misused.
- **Trusted list:** 72 Indian and global sites plus every `.gov.in`, `.nic.in`
  and `.bank.in` domain. A trusted domain behind a redirect, an IP or an `@` is
  not trusted.
- **Reasons:** every result explains itself, for example *"Uses the name 'sbi'
  but is not its official website"*.

## Project structure

```text
BharatShield/
|-- app.py                   Streamlit app
|-- api.py                   FastAPI service
|-- config/trusted_domains.json
|-- data/                    sources.json, dataset_summary.json (data files stay local)
|-- docs/                    dataset.md, model_card.md, ablation_study.md, deployment.md
|-- model/                   trained models, config, reports and charts
|-- scripts/
|   |-- download_data.py     download the five data sources
|   `-- build_dataset.py     build the training set and the external test set
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

Docker and deployment notes: [docs/deployment.md](docs/deployment.md).

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
python -m scripts.download_data     # about 263 MB, needs git for the OpenPhish history
python -m scripts.build_dataset     # --cutoff 2026-09-15 by default
python -m src.train_model           # about 10 minutes on a laptop
```

Downloading on a later date gives newer feeds, so the numbers will move a
little. See [data/README.md](data/README.md).

## Limitations

- **URL only.** No page content is fetched, and there is no WHOIS, domain age,
  DNS, certificate or live reputation lookup. A phishing page on an
  ordinary-looking or hacked domain is hard to catch from the URL alone.
- **Hand-maintained lists.** The trusted list, brand list and free hosting list
  in `config/trusted_domains.json` are edited by hand. A real brand site missing
  from the brand list can be flagged.
- **Free hosting.** There are almost no legitimate free-hosting pages in the
  data, so a normal `name.github.io` page shows as "Suspicious".
- **External test construction.** The legitimate side is "presumed legitimate"
  (Common Crawl pages, Tranco homepages). Phishing.Database has no dates, so
  the time split is strict only for OpenPhish. Most feed phishing is global,
  not India-specific.
- **Message scanner is rule-based.** I wrote the sample messages myself and
  tuned the rules on them, so there is no independent accuracy number for it.
- **Phishing changes fast.** The model should be retrained every few weeks.

## Credits and license

Code is MIT licensed (see `LICENSE`). Data comes from Common Crawl, Majestic
Million (CC BY 3.0), Tranco (Le Pochat et al., NDSS 2019), the OpenPhish
community feed (non-commercial use only) and Phishing.Database (MIT). The data
files are not included in this repository.
