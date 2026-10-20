import math
import re
from collections import Counter

from .url_utils import canonical_key, domain_parts, is_ip_address, key_hostname

# Every feature is computed on the canonical key (no scheme, no www).
# Older versions used an HTTPS feature, but in the old dataset every
# legitimate URL started with https://www., so the model learned that
# shortcut instead of learning what phishing looks like.
FEATURE_NAMES = [
    "URL Length",
    "Host Length",
    "Path Length",
    "Host Dots",
    "Host Hyphens",
    "Host Digits",
    "Subdomain Count",
    "Path Depth",
    "Query Parameters",
    "Path Digits",
    "Percent Signs",
    "Longest Path Word",
    "Has @ Symbol",
    "IP Address",
    "Keyword Count",
    "Suspicious TLD",
    "Domain Name Entropy",
]


SUSPICIOUS_WORDS = [
    "login",
    "logon",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "wallet",
    "banking",
    "reward",
    "bonus",
    "gift",
    "claim",
    "refund",
    "kyc",
    "otp",
    "unlock",
    "suspend",
    "billing",
    "invoice",
    "support",
]

# cheap TLDs that show up a lot in phishing feeds
SUSPICIOUS_TLDS = [
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "xyz",
    "top",
    "icu",
    "cyou",
    "buzz",
    "sbs",
    "cfd",
    "bond",
    "rest",
    "click",
    "link",
    "work",
    "fit",
    "live",
    "online",
    "site",
    "shop",
    "vip",
]


def entropy(text):
    # how random the letters look, "xk2q9vz" scores higher than "google"
    if not text:
        return 0.0

    counts = Counter(text)
    total = len(text)

    return -sum(n / total * math.log2(n / total) for n in counts.values())


def keyword_count(text):
    words = set(re.split(r"[^a-z0-9]+", text))
    count = 0

    for word in SUSPICIOUS_WORDS:
        # short words like otp/kyc only as a full word, so "hotpot" is fine
        if len(word) <= 3:
            count += word in words
        else:
            count += word in text

    return count


def has_suspicious_tld(suffix):
    return suffix.split(".")[-1] in SUSPICIOUS_TLDS


def extract_features_from_key(key):
    host = key_hostname(key)
    rest = key[len(host):]
    path, _, query = rest.partition("?")
    parts = domain_parts(host)

    path_words = re.split(r"[/._=&?-]", rest)

    return [
        len(key),
        len(host),
        len(rest),
        host.count("."),
        host.count("-"),
        sum(char.isdigit() for char in host),
        len(parts.subdomain.split(".")) if parts.subdomain else 0,
        path.count("/"),
        len(query.split("&")) if query else 0,
        sum(char.isdigit() for char in rest),
        key.count("%"),
        max((len(word) for word in path_words), default=0),
        1 if "@" in key else 0,
        1 if is_ip_address(host) else 0,
        keyword_count(key),
        1 if has_suspicious_tld(parts.suffix) else 0,
        round(entropy(parts.domain), 4),
    ]


def extract_features(url):
    return extract_features_from_key(canonical_key(url))


def feature_values_to_dict(features):
    if len(features) != len(FEATURE_NAMES):
        raise ValueError("Feature values do not match the feature names.")

    return dict(zip(FEATURE_NAMES, features, strict=True))
