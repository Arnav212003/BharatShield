"""Download the raw data sources used to build the training data.

Files go to data/raw/ (ignored by Git). data/sources.json records where
each file came from, when, its license or terms, and its SHA-256 hash.

    python -m scripts.download_data
"""

import argparse
import hashlib
import json
import os
import subprocess
import urllib.request
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
SOURCES_FILE = os.path.join(BASE_DIR, "data", "sources.json")

USER_AGENT = "BharatShield student project (+https://github.com/Arnav212003/BharatShield)"

SOURCES = {
    "common_crawl": {
        "file": "cc-cluster.idx",
        "url": "https://data.commoncrawl.org/cc-index/collections/{crawl}/indexes/cluster.idx",
        "label": "legitimate (presumed)",
        "terms": "https://commoncrawl.org/terms-of-use",
        "note": "Index of every ~3000th URL in the crawl. Used as normal web pages.",
    },
    "majestic_million": {
        "file": "majestic_million.csv",
        "url": "https://downloads.majestic.com/majestic_million.csv",
        "label": "legitimate (presumed)",
        "terms": "CC BY 3.0, https://majestic.com/reports/majestic-million",
        "note": "Top 1M domains by backlinks. Used as normal homepages.",
    },
    "tranco": {
        "file": "tranco-top-1m.csv.zip",
        "url": "https://tranco-list.eu/top-1m.csv.zip",
        "label": "legitimate (presumed), external test only",
        "terms": "https://tranco-list.eu/ (cite Le Pochat et al., NDSS 2019)",
        "note": "Top 1M domains. Only used for the external test.",
    },
    "phishing_database": {
        "file": "phishing-links-ACTIVE.txt",
        "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
        "label": "phishing",
        "terms": "MIT License, https://github.com/Phishing-Database/Phishing.Database",
        "note": "Community list of active phishing links. No dates.",
    },
    "openphish": {
        "file": "openphish_history.tsv",
        "url": "https://github.com/openphish/public_feed",
        "label": "phishing",
        "terms": "Non-commercial use only, https://openphish.com/terms.html",
        "note": "Built from the Git history of the free feed, so every URL has a first-seen date.",
    },
}


def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def download(url, destination):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    with urllib.request.urlopen(request, timeout=300) as response:
        final_url = response.geturl()

        with open(destination, "wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)

    return final_url


def git(*args, cwd=None):
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout


def build_openphish_history(destination, since):
    """Each commit of the feed is one snapshot. The first commit where a URL
    appears is used as its first-seen date."""
    repo_dir = os.path.join(RAW_DIR, "openphish_repo")

    if os.path.exists(repo_dir):
        git("fetch", "-q", f"--shallow-since={since}", "origin", cwd=repo_dir)
        git("reset", "-q", "--hard", "FETCH_HEAD", cwd=repo_dir)
    else:
        git(
            "clone",
            "-q",
            f"--shallow-since={since}",
            SOURCES["openphish"]["url"] + ".git",
            repo_dir,
        )

    commits = git("log", "--reverse", "--format=%H %cI", "--", "feed.txt", cwd=repo_dir)
    seen = set()
    rows = 0

    with open(destination, "w", encoding="utf-8", newline="\n") as output:
        output.write("first_seen\turl\n")

        for line in commits.splitlines():
            commit, date = line.split(" ", 1)
            feed = git("show", f"{commit}:feed.txt", cwd=repo_dir)

            for url in feed.split():
                if url not in seen:
                    seen.add(url)
                    output.write(f"{date}\t{url}\n")
                    rows += 1

    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--crawl", default="CC-MAIN-2026-39", help="Common Crawl crawl id")
    parser.add_argument(
        "--openphish-since",
        default="2026-07-01",
        help="Oldest OpenPhish feed snapshot to read",
    )
    parser.add_argument("--only", nargs="*", choices=list(SOURCES), help="Download only these")
    args = parser.parse_args()

    os.makedirs(RAW_DIR, exist_ok=True)

    if os.path.exists(SOURCES_FILE):
        with open(SOURCES_FILE, "r", encoding="utf-8") as file:
            records = json.load(file)
    else:
        records = {}

    for name, source in SOURCES.items():
        if args.only and name not in args.only:
            continue

        path = os.path.join(RAW_DIR, source["file"])
        print("Downloading", name, "...")

        record: dict[str, object] = {
            key: value for key, value in source.items() if key != "url"
        }

        if name == "openphish":
            record["rows"] = build_openphish_history(path, args.openphish_since)
            record["source_url"] = source["url"]
            record["since"] = args.openphish_since
        else:
            url = source["url"].format(crawl=args.crawl)
            record["source_url"] = download(url, path)

            if name == "common_crawl":
                record["crawl"] = args.crawl

        record["retrieved_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        record["sha256"] = sha256_file(path)
        size = os.path.getsize(path)
        record["bytes"] = size
        records[name] = record

        print("  saved", source["file"], f"({size // 1024} KB)")

    with open(SOURCES_FILE, "w", encoding="utf-8") as file:
        json.dump(records, file, indent=2)
        file.write("\n")

    print("Wrote", os.path.relpath(SOURCES_FILE, BASE_DIR))


if __name__ == "__main__":
    main()
