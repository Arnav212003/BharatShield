"""Build the training set and the external test set from data/raw/.

    python -m scripts.build_dataset

Outputs (ignored by Git):
    data/train.csv            key, label, source, group
    data/external_test.csv    url, label, source, group, first_seen
    data/dataset_summary.json counts and leakage checks (tracked)

The external test is kept apart in two ways:
1. Time: OpenPhish URLs first seen on or after --cutoff are test only.
2. Site: no test URL shares a site group (registered domain, or tenant
   host on free hosting) with any training URL.
"""

import argparse
import csv
import json
import os
import zipfile

import pandas as pd

from src.security_layers import USER_CONTENT_ROOTS
from src.url_utils import (
    canonical_key,
    is_ip_address,
    key_hostname,
    site_group,
    surt_to_key,
    validate_url_text,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")

SEED = 42
CC_TRAIN_ROWS = 250_000
CC_TEST_GROUP_SHARE = 0.10
MAJESTIC_ROWS = 60_000
PHISHING_DATABASE_ROWS = 80_000
TRANCO_TEST_ROWS = 8_000


def raw_path(name):
    return os.path.join(RAW_DIR, name)


def load_common_crawl():
    surts = pd.read_csv(
        raw_path("cc-cluster.idx"),
        sep="\t",
        header=None,
        usecols=[0],
        names=["line"],
        quoting=csv.QUOTE_NONE,
        encoding="utf-8",
        encoding_errors="replace",
    )["line"]
    keys = surts.str.rsplit(" ", n=1).str[0].map(surt_to_key)
    keys = keys[~keys.str.endswith("robots.txt")]

    frame = pd.DataFrame({"key": keys, "label": 0, "source": "common_crawl"})
    return frame


def load_majestic():
    domains = pd.read_csv(raw_path("majestic_million.csv"), usecols=["Domain"])["Domain"]
    domains = domains.sample(n=MAJESTIC_ROWS, random_state=SEED)

    return pd.DataFrame({"key": domains.str.lower(), "label": 0, "source": "majestic"})


def load_openphish():
    feed = pd.read_csv(
        raw_path("openphish_history.tsv"),
        sep="\t",
        quoting=csv.QUOTE_NONE,
        dtype=str,
    )

    return pd.DataFrame({
        "url": feed["url"],
        "key": feed["url"].map(canonical_key),
        "label": 1,
        "source": "openphish",
        "first_seen": feed["first_seen"],
    })


def load_phishing_database():
    with open(raw_path("phishing-links-ACTIVE.txt"), "r", encoding="utf-8", errors="replace") as file:
        urls = [
            line.strip()
            for line in file
            if line.lower().startswith(("http://", "https://"))
        ]

    urls = pd.Series(urls).sample(n=PHISHING_DATABASE_ROWS, random_state=SEED)

    return pd.DataFrame({"key": urls.map(canonical_key), "label": 1, "source": "phishing_database"})


def load_tranco():
    with zipfile.ZipFile(raw_path("tranco-top-1m.csv.zip")) as archive:
        with archive.open(archive.namelist()[0]) as file:
            tranco = pd.read_csv(file, header=None, names=["rank", "domain"])

    return pd.DataFrame({
        "url": tranco["domain"].str.lower(),
        "key": tranco["domain"].str.lower(),
        "label": 0,
        "source": "tranco",
    })


def add_host_and_group(frame):
    frame = frame[frame["key"].fillna("") != ""].copy()
    frame["host"] = frame["key"].map(key_hostname)
    frame = frame[~frame["host"].map(is_ip_address)]
    frame["group"] = frame["host"].map(lambda host: site_group(host, USER_CONTENT_ROOTS))
    return frame


def is_valid_url(text):
    try:
        validate_url_text(text)
        return True
    except ValueError:
        return False


def remove_conflicts(frame):
    # the same key with both labels cannot be learned, drop it completely
    conflict = frame.groupby("key")["label"].transform("nunique") > 1
    return frame[~conflict].drop_duplicates("key"), int(conflict.sum())


def pick_test_groups(groups, share, seed=SEED):
    unique = pd.Series(sorted(set(groups)))
    return set(unique.sample(frac=share, random_state=seed))


def main():
    parser = argparse.ArgumentParser(description="Build BharatShield training data.")
    parser.add_argument(
        "--cutoff",
        default="2026-09-15",
        help="OpenPhish URLs first seen on or after this date are test only",
    )
    args = parser.parse_args()

    print("Loading sources...")
    common_crawl = add_host_and_group(load_common_crawl())
    majestic = add_host_and_group(load_majestic())
    openphish = add_host_and_group(load_openphish())
    phishing_db = add_host_and_group(load_phishing_database())
    tranco = add_host_and_group(load_tranco())

    # a "legitimate" page on a host that is in a phishing feed is not
    # trustworthy as a label (often a hacked site), so leave it out
    phishing_hosts = set(openphish["host"]) | set(phishing_db["host"])
    noisy_counts = {}

    for name, frame in [("common_crawl", common_crawl), ("majestic", majestic), ("tranco", tranco)]:
        noisy_counts[name] = int(frame["host"].isin(phishing_hosts).sum())

    common_crawl = common_crawl[~common_crawl["host"].isin(phishing_hosts)]
    majestic = majestic[~majestic["host"].isin(phishing_hosts)]
    tranco = tranco[~tranco["host"].isin(phishing_hosts)]

    is_new = openphish["first_seen"] >= args.cutoff
    openphish_old = openphish[~is_new]
    openphish_new = openphish[is_new]

    cc_test_groups = pick_test_groups(common_crawl["group"], CC_TEST_GROUP_SHARE)
    cc_test = common_crawl[common_crawl["group"].isin(cc_test_groups)]
    cc_train = common_crawl[~common_crawl["group"].isin(cc_test_groups)]
    cc_train = cc_train.sample(n=min(CC_TRAIN_ROWS, len(cc_train)), random_state=SEED)

    # Phishing.Database has no dates, so drop anything from sites that
    # only show up in the test period
    phishing_db = phishing_db[~phishing_db["group"].isin(set(openphish_new["group"]))]

    columns = ["key", "label", "source", "group"]
    train = pd.concat([
        cc_train[columns],
        majestic[columns],
        openphish_old[columns],
        phishing_db[columns],
    ])
    train, conflict_rows = remove_conflicts(train)
    train = train.sample(frac=1, random_state=SEED).reset_index(drop=True)
    train_groups = set(train["group"])

    # external test: one URL per site, nothing from a training site
    test_phishing = openphish_new[~openphish_new["group"].isin(train_groups)]
    test_phishing = test_phishing.drop_duplicates("group")
    test_phishing = test_phishing[test_phishing["url"].map(is_valid_url)]

    test_pages = cc_test[~cc_test["group"].isin(train_groups)].drop_duplicates("group")
    test_pages = test_pages.sample(
        n=min(2 * len(test_phishing), len(test_pages)),
        random_state=SEED,
    )
    test_pages = test_pages.assign(url=test_pages["key"])

    test_homepages = tranco[~tranco["group"].isin(train_groups)].drop_duplicates("group")
    test_homepages = test_homepages.sample(n=TRANCO_TEST_ROWS, random_state=SEED)

    test = pd.concat([
        test_phishing[["url", "label", "source", "group", "first_seen"]],
        test_pages[["url", "label", "source", "group"]],
        test_homepages[["url", "label", "source", "group"]],
    ])
    test = test[test["url"].map(is_valid_url)].reset_index(drop=True)

    os.makedirs(DATA_DIR, exist_ok=True)
    train.to_csv(os.path.join(DATA_DIR, "train.csv"), index=False)
    test.to_csv(os.path.join(DATA_DIR, "external_test.csv"), index=False)

    summary = {
        "cutoff": args.cutoff,
        "seed": SEED,
        "train_rows": int(len(train)),
        "train_counts": {
            f"{source}_{'phishing' if label else 'legitimate'}": int(count)
            for (source, label), count in train.groupby(["source", "label"]).size().items()
        },
        "external_test_rows": int(len(test)),
        "external_test_counts": test.groupby("source").size().astype(int).to_dict(),
        "openphish_first_seen": {
            "train_from": str(openphish_old["first_seen"].min()),
            "train_to": str(openphish_old["first_seen"].max()),
            "test_from": str(test_phishing["first_seen"].min()),
            "test_to": str(test_phishing["first_seen"].max()),
        },
        "cleaning": {
            "legitimate_rows_dropped_for_phishing_host": noisy_counts,
            "conflicting_key_rows_dropped": conflict_rows,
        },
        "leakage_checks": {
            "test_groups_in_train": len(set(test["group"]) & train_groups),
            "test_keys_in_train": int(test["url"].map(canonical_key).isin(set(train["key"])).sum()),
        },
    }

    with open(os.path.join(DATA_DIR, "dataset_summary.json"), "w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)
        file.write("\n")

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
