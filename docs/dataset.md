# Dataset Notes

This note documents the dataset as it exists in this repository. The exact original download link/source should be added before final submission if the file was collected from an external website.

## Provenance Status

| Field | Current value |
| --- | --- |
| Source | Unverified |
| License | Unknown |
| SHA-256 | `b1a7c26b354632c80817e10af154c4e5007f9480fb43a8ac2730491500fa2780` |

The hash identifies the exact file used for the saved models. It does not establish ownership or licensing. The project should not claim a public source until the original download page is confirmed.

## File

```text
data/phishing.csv
```

## Columns

| Column | Meaning |
| --- | --- |
| `URL` | URL string used for feature extraction |
| `Label` | `good` for safe URLs and `bad` for phishing or unsafe URLs |

## Current Size

The raw CSV contains 549,346 rows:

| Label | Count |
| --- | ---: |
| `good` | 392,924 |
| `bad` | 156,422 |

After conflicting and duplicate normalized URLs are removed, 501,444 unique rows remain: 392,867 safe and 108,577 phishing. Training then takes a reproducible 100,000-row sample containing 78,492 safe and 21,508 phishing URLs.

## Training Cleanup

`src/train_model.py` performs these steps before training:

1. Keeps the first two columns and normalizes them as `url` and `label`.
2. Converts known safe labels to `0` and unsafe labels to `1`.
3. Removes rows with missing URL or label values.
4. Builds a normalized URL key by removing scheme, `www.`, and trailing slash.
5. Removes duplicate URLs and URLs that appear with conflicting labels.
6. Samples 100,000 rows for training speed and reproducibility.
7. Splits data by root domain, so the same domain does not appear on both train and test sides.

## Important Limitation

Most URLs in this CSV do not include `http://` or `https://`. The HTTPS feature is `1` only when the original URL explicitly starts with `https://`; it is `0` for HTTP and scheme-less input. A missing scheme remains neutral in the explanation layer because it does not prove that a site uses HTTP.

## Why Domain-Based Split Is Used

A normal random split can accidentally put similar URLs from the same domain in both training and testing. That makes the model look better than it really is. BharatShield uses a domain-based split to reduce this memorization problem.

The saved split contains 62,189 training rows, 17,279 validation rows, and 20,532 test rows. Domain and normalized-URL overlap between all three splits is zero. The largest test domain still contributes 13.41% of test rows, so the project reports domain-macro accuracy alongside normal row-level accuracy.

The full machine-readable record is stored in `model/training_metadata.json`.
