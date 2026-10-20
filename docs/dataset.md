# Dataset Notes

This document records only facts supported by the local file and training
metadata. The original download page and license have not been identified, so
the source is marked unverified instead of being guessed.

## Provenance

| Field | Current value |
| --- | --- |
| Source | Unverified |
| License | Unknown |
| Redistribution allowed | No |
| SHA-256 | `b1a7c26b354632c80817e10af154c4e5007f9480fb43a8ac2730491500fa2780` |

The hash identifies the exact file used for the saved model. It does not prove
ownership, origin, or permission to redistribute the data.

`data/phishing.csv` is now ignored and removed from the current Git index. A
local copy is still needed for retraining. This does not remove older copies
from existing Git history; doing that would require a coordinated history
rewrite and force-push, which is intentionally outside this change.

The MIT license covers project code and documentation, not this dataset.

## Expected File

The first two CSV columns are treated as URL and label. The local file used for
the current model had 549,346 raw rows:

| Raw label | Count |
| --- | ---: |
| `good` | 392,924 |
| `bad` | 156,422 |

Supported labels are listed in `data/README.md`.

## Cleanup And Sampling

Training performs these steps in a fixed order:

1. Remove rows with missing or unsupported labels.
2. Normalize a comparison key by removing scheme, `www.`, and trailing slash.
3. Remove every normalized URL that has conflicting labels.
4. Keep one copy of each remaining normalized URL.
5. Take a reproducible 100,000-row sample with seed `42`.
6. Split by root domain into train, validation, and test sets.

The cleanup removed 47,902 duplicate/conflicting rows. Before sampling, 501,444
unique rows remained: 392,867 safe and 108,577 phishing. The sample contains
78,492 safe and 21,508 phishing URLs.

## Saved Splits

| Split | Rows | Safe | Phishing | Phishing share | Unique domains |
| --- | ---: | ---: | ---: | ---: | ---: |
| Train | 62,189 | 48,647 | 13,542 | 21.78% | 27,868 |
| Validation | 17,279 | 13,520 | 3,759 | 21.75% | 6,968 |
| Test | 20,532 | 16,325 | 4,207 | 20.49% | 8,710 |

Root-domain overlap and normalized-URL overlap are zero for every split pair.
The largest test domain contributes 13.41% of test rows, so domain-macro
accuracy is reported alongside row-level accuracy.

## Scheme Limitation

Only 0.018% of sampled URLs explicitly use HTTP and 0.002% explicitly use
HTTPS; 99.978% have no scheme. The HTTPS feature is therefore `1` only for an
explicit `https://` prefix and `0` for HTTP or scheme-less input. A missing
scheme does not produce the human-readable "No HTTPS" reason because absence
of a scheme is not proof that the real site uses HTTP.

## Reproducibility Record

`model/training_metadata.json` contains the file hash, cleanup counts, split
counts, overlap checks, chosen validation policy, model settings, and exact
model-sensitive package versions.
