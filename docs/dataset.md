# Dataset Notes

## Why the dataset changed

Version 1 of BharatShield was trained on the
[PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil%2Bphishing%2Burl%2Bdataset)
v2 (CC BY 4.0) and scored 99.58% accuracy on its own test split. But in the app
it called `google.com`, `http://www.google.com` and `amazon.in` phishing with a
score of 100.

Counting URL shapes in the PhiUSIIL file (134,850 legitimate, 100,945
phishing) explained why:

| What the URL looks like | Legitimate | Phishing |
| --- | ---: | ---: |
| Starts with `http://` | 0 | 51,749 |
| Has a path (`/something`) | 0 | 28,684 |
| Ends with `/` | 0 | 36,813 |
| Does not start with `www.` | 0 | 59,199 |

Every legitimate URL in PhiUSIIL is exactly `https://www.<domain>`. So the model
learned "anything that does not look like `https://www.something` is
phishing". That rule gives 99% on PhiUSIIL and fails on real links.
PhiUSIIL is not used any more. [ablation_study.md](ablation_study.md) compares
the parts of the current system (each model, the blend, and the rules) on the
internal and external tests, and lists the validation choices.

## What the model sees now

The URL model never sees the scheme (`http://`, `https://`) or a leading `www.`.
Every URL is turned into a canonical key first (`src/url_utils.py`):

```text
HTTPS://WWW.Example.co.in/Login/?b=2&a=1   ->   example.co.in/login?a=1&b=2
```

This is the same form as the SURT keys in the Common Crawl index, so crawl
pages and feed phishing URLs are written the same way. A unit test checks that
`google.com`, `http://google.com` and `https://www.google.com` give exactly the
same features.

## Training set

Built by `scripts/build_dataset.py` (counts from `data/dataset_summary.json`):

| Source | Label | Rows | Notes |
| --- | --- | ---: | --- |
| Common Crawl index, CC-MAIN-2026-39 | legitimate | 249,999 | Real pages with paths and queries |
| Majestic Million | legitimate | 59,982 | Random sample of homepages, so bare domains are not all phishing |
| OpenPhish, first seen 2026-07-02 to 2026-09-14 | phishing | 33,831 | Dated, from the feed's Git history |
| Phishing.Database | phishing | 76,060 | Random sample of 80,000 links; undated |
| **Total** | | **419,872** | 26.2% phishing |

Tranco is not used for training.

Cleaning:

1. "Legitimate" rows whose host also appears in a phishing feed are dropped
   (362 Common Crawl, 11 Majestic), because such hosts are often hacked sites.
2. Phishing.Database rows from any site that also appears in the test-period
   OpenPhish URLs are dropped, since that list has no dates.
3. Keys with both labels are dropped (0 in this build), then duplicate keys.

## Splits

**Internal test.** `data/train.csv` is split 60/20/20 with `StratifiedGroupKFold`
(seed 42): 251,924 train, 83,974 validation, 83,974 test rows. The group is
the site: the registered domain, or the full hostname for free hosting tenants
(`name.github.io`). `model/training_metadata.json` records 0 shared groups
between train and test and between train and validation.

**External test.** `data/external_test.csv` is built separately and is never
used for training or for choosing any setting:

| Part | Rows | How it is kept separate |
| --- | ---: | --- |
| OpenPhish phishing first seen 2026-09-15 to 2026-10-20 | 9,330 | Newer than all training phishing, one URL per site, no site from training |
| Common Crawl pages | 18,658 | 10% of crawl sites held out before training, one URL per site |
| Tranco homepages | 8,000 | Random sample, no site from training (280 Tranco rows on phishing hosts dropped first) |

`data/dataset_summary.json` records 0 test sites and 0 test URLs in the
training data.

## Known problems with the data

- **Presumed legitimate.** Tranco ranks any domain that gets traffic, including
  spam, gambling and tracking domains. Some flagged Tranco homepages are really
  sketchy (for example `acheter-followers-instagram.com`,
  `microsoftdownloaderonline.com`), so the 7.96% Tranco false positive rate is
  probably too pessimistic. Common Crawl can also contain bad pages.
- **Partial time split.** Phishing.Database has no dates, so the time split is
  strict only for OpenPhish.
- **Free hosting.** The crawl sample has very few legitimate pages on free
  hosting (180 in the external test), so the model treats those platforms as
  risky.
- **Not India-specific.** OpenPhish and Phishing.Database are mostly global.
  Fake Indian bank KYC or electricity bill sites are a small part of them.
- **Snapshots.** The feeds change daily. Running the scripts on a later date
  gives different data and slightly different numbers.

## Repository history

An older CSV with an unknown license is still in old Git commits. Removing it
needs a history rewrite and force-push, which has not been done.
