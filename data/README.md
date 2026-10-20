# Training Data

The current model does **not** use `data/phishing.csv` (the old PhiUSIIL or
unverified CSV). It is trained only on the files built by the two scripts
below. The data files are not stored in Git because they are large and some
sources do not allow sharing.

```bash
python -m scripts.download_data    # raw files into data/raw/ (about 263 MB)
python -m scripts.build_dataset    # data/train.csv and data/external_test.csv
```

Tracked in Git:

| File | What it records |
| --- | --- |
| `sources.json` | Source URL, terms, download time, size and SHA-256 of every raw file |
| `dataset_summary.json` | Row counts, cutoff date, cleaning counts and leakage checks of the last build |

Local only (ignored by Git): `data/raw/`, `data/train.csv`,
`data/external_test.csv`, and any old `data/phishing.csv` or `data/legacy/`.

## Sources

The current files were downloaded on 2026-10-20.

| Source | Raw file | Used for | Terms |
| --- | --- | --- | --- |
| [Common Crawl](https://commoncrawl.org/) index, CC-MAIN-2026-39 | `cc-cluster.idx` | Legitimate pages with paths (training and external test) | [Terms of use](https://commoncrawl.org/terms-of-use) |
| [Majestic Million](https://majestic.com/reports/majestic-million) | `majestic_million.csv` | Legitimate homepages (training only) | CC BY 3.0 |
| [Tranco](https://tranco-list.eu/) top 1M | `tranco-top-1m.csv.zip` | Legitimate homepages (**external test only**) | Cite Le Pochat et al., NDSS 2019 |
| [OpenPhish](https://openphish.com/) community feed, from 2026-07-01 | `openphish_history.tsv` | Phishing with first-seen dates (training before the cutoff, external test after) | Non-commercial use only |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) | `phishing-links-ACTIVE.txt` | Extra phishing links (training only) | MIT |

The OpenPhish file is built from the Git history of the free feed: every
commit is one snapshot, and a URL's first-seen date is the first commit that
contains it (53,118 unique URLs).

## What build_dataset.py does

1. Turns every URL into a canonical key (no scheme, no `www.`, lower case,
   sorted query) and a site group (registered domain, or the full hostname for
   free hosting tenants).
2. Drops "legitimate" rows whose host appears in a phishing feed
   (362 Common Crawl, 11 Majestic, 280 Tranco rows in the last build).
3. Splits OpenPhish at the cutoff date (default `2026-09-15`).
4. Holds out 10% of Common Crawl sites for the external test.
5. Training set: 249,999 Common Crawl + 59,982 Majestic + 33,831 OpenPhish
   (before the cutoff) + 76,060 Phishing.Database = 419,872 rows.
6. External test: 9,330 OpenPhish (on or after the cutoff) + 18,658 Common
   Crawl + 8,000 Tranco = 35,988 rows, one URL per site, no site from training.

The legitimate sources are "presumed legitimate": popular or crawled does not
mean safe. See [docs/dataset.md](../docs/dataset.md) for why these sources
replaced PhiUSIIL.
