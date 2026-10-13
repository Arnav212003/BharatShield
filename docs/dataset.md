# Dataset Notes

This note documents the dataset as it exists in this repository. The exact original download link/source should be added before final submission if the file was collected from an external website.

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

Most URLs in this CSV do not include `http://` or `https://`. Because of that, the HTTPS feature is less useful during training. The project still keeps the feature because users may enter full URLs in the app/API.

## Why Domain-Based Split Is Used

A normal random split can accidentally put similar URLs from the same domain in both training and testing. That makes the model look better than it really is. BharatShield uses a domain-based split to reduce this memorization problem.
