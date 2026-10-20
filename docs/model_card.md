# BharatShield Model Card

Values on this page come from `model/model_config.json`,
`model/model_evaluation_report.csv` and `model/training_metadata.json`
(models generated 2026-10-20 18:55 UTC).

## What it is for

A student project that gives a second opinion on a link or message before a
user opens it or shares anything. It is not meant for automatic blocking,
banking decisions, or replacing browser safe browsing.

## URL models

| Part | What it is |
| --- | --- |
| Input | Canonical URL key: no scheme, no `www.`, lower case, sorted query |
| Model 1 | `HistGradientBoostingClassifier` on 17 numeric URL features (300 iterations, learning rate 0.1, 63 leaf nodes, balanced class weights) |
| Model 2 | `LogisticRegression` (C = 4, balanced class weights) on the same 17 features (MaxAbs scaled) + TF-IDF character 3-5 grams (`char_wb`, 50,000 features) |
| Blend | 0.3 x model 1 + 0.7 x model 2 |
| Cutoffs | Safe below 0.50, Suspicious from 0.50, Phishing from 0.80 |
| Rules | Fixed (below), not learned |

The 17 features: URL length, host length, path length, host dots, host
hyphens, host digits, subdomain count, path depth, query parameters, path
digits, percent signs, longest path word, has `@`, IP address, keyword count,
suspicious TLD, domain name entropy.

Choices made on the validation split only (test sets were not used):

- Blend weight: highest PR-AUC over weights 0.0 to 1.0.
- Safe cutoff: highest F1 with recall >= 90% (validation precision 92.62%,
  recall 91.31%, FPR 2.58%).
- Phishing cutoff: lowest cutoff with precision >= 98%.

### Rules

| Rule | Effect on the score |
| --- | --- |
| Brand name on a non-official domain (`sbi-kyc-update.com`, `paypa1.com`) | +0.30, and at least Suspicious |
| IP address as host | +0.25 |
| `@` in the address (`paypal.com@evil.com`) | +0.25 |
| Punycode host (`xn--`) | +0.15 |
| Redirect to another site in the query | +0.15 |
| URL shortener | At least Suspicious |
| Free hosting tenant without a brand match | At most Suspicious |
| Trusted list (72 sites) or `.gov.in` / `.nic.in` / `.bank.in` | At most 0.20 (Safe) |

A trusted domain behind a redirect, an IP or an `@` is not treated as trusted.
Not using HTTPS is shown as a warning but does not change the score, because
in the old data the scheme was a shortcut, not a real signal.

## Results

### External test (the number to quote)

35,988 URLs, 25.9% phishing. Phishing first seen on OpenPhish between
2026-09-15 and 2026-10-20 (after all training phishing), from sites never seen
in training, plus held-out Common Crawl pages and Tranco homepages from sites
never seen in training.

| System | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ML blend | 89.83% | 91.93% | 90.87% | 3.64% | 98.50% | 97.09% |
| Final system (ML + rules) | 89.67% | 91.95% | 90.80% | 3.71% | 97.96% | 94.60% |

95% Wilson intervals for the final system: recall 91.38% to 92.49%, FPR 3.49%
to 3.94%. Confusion matrix: TN 25,670, FP 988, FN 751, TP 8,579.

By source (final system):

| Slice | Rows | Flagged |
| --- | ---: | ---: |
| OpenPhish phishing | 9,330 | 91.95% (recall) |
| Phishing on free hosting | 6,320 | 99.95% (recall) |
| Common Crawl pages | 18,658 | 1.88% (false positives) |
| Tranco homepages | 8,000 | 7.96% (false positives) |
| Legitimate pages on free hosting | 180 | 11.11% (false positives) |

The Tranco rate is partly label noise (Tranco also ranks spam and gambling
domains), but it is still the weakest part.

### Internal test

Site-grouped split of the training sources, 83,974 URLs:

| Model | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: |
| Gradient boosting alone | 83.47% | 84.92% | 84.19% | 5.96% |
| Logistic regression alone | 91.82% | 91.43% | 91.62% | 2.89% |
| ML blend | 93.30% | 93.05% | 93.17% | 2.37% |
| Final system | 93.21% | 93.08% | 93.14% | 2.40% |

[ablation_study.md](ablation_study.md) explains what each part adds, including
the finding that the rules do not improve the overall numbers.

### Before and after on simple inputs

| URL | Version 1 (PhiUSIIL) | Now |
| --- | --- | --- |
| `google.com` | Phishing, 100 | Safe, 20 |
| `http://www.google.com` | Phishing, 100 | Safe, 20 |
| `amazon.in` | Phishing, 100 | Safe, 20 |
| `https://www.flipkart.com/` | Suspicious, 53 | Safe, 12 |
| `https://sbi-kyc-update.com` | Phishing, 92 | Phishing, 100 |
| `https://accounts.google.com.evil.tk` | Phishing, 77 | Phishing, 100 |
| `https://g00gle.com` | Phishing, 74 | Suspicious, 50 |

## Message scanner

Rule-based, no machine learning (`src/scam_message.py`). It checks requests for
OTP, UPI PIN, PIN, CVV, passwords, card details and Aadhaar/PAN, plus 14
patterns: urgency, account/KYC threats, lottery and reward bait, "scan QR to
receive money", remote access apps, payment requests, family emergency,
electricity disconnection, parcel/customs, fake police or "digital arrest",
task jobs, investment, instant loans, and "move to WhatsApp/Telegram". Hinglish
phrases are included (*turant*, *bijli kat jayega*, *naya number*, *paise
bhejo*). Status: Low Risk below 35, Suspicious from 35, Likely Fraud from 70.
Links in a message are scored by the URL system.

`tests/data/sample_messages.csv` has 98 messages (50 scam, 48 normal) that I
wrote. With link scanning all 98 are classified correctly, but the rules were
tuned on these same messages, so this is a regression check and not an
accuracy number. I did not find a public labelled dataset of Indian scam SMS
to test on.

## Limitations

- **URL only.** No page content is fetched; no WHOIS, domain age, DNS,
  certificate or live reputation lookup. Phishing on ordinary-looking or hacked
  domains is the main source of misses.
- **The trusted list does real work.** The ML score alone is sometimes high for
  well-known sites (`amazon.in` 61, `hdfcbank.com/personal/login` 94). The
  trusted list fixes those, but a site not on the list gets no such help.
- **Hand-maintained lists.** Trusted sites, brands and free hosting platforms
  in `config/trusted_domains.json` are edited by hand. Brand prefix matching
  causes some false alarms (see the ablation study).
- **Free hosting.** Normal pages on free hosting platforms show as Suspicious.
- **External test construction.** Legitimate URLs are presumed legitimate;
  the time split is strict only for OpenPhish; feed phishing is mostly global.
- **Message scanner** is rule-based and has no independent accuracy number.
- **Drift.** Phishing changes quickly, so the model needs regular retraining.

## Reproduce

```bash
python -m scripts.download_data
python -m scripts.build_dataset
python -m src.train_model
```

Seed 42, Python 3.11.9, pandas 2.3.3, NumPy 1.26.4, scikit-learn 1.8.0,
tldextract 5.3.1. Settings, split sizes and all metrics are written to
`model/training_metadata.json`; raw file hashes to `data/sources.json`.
Downloading on a later date gives newer feeds, so the numbers will move a
little.
