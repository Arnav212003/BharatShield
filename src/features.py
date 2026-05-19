import re
from urllib.parse import urlparse

import tldextract


def has_ip_address(url):
    pattern = r"(\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(pattern, url) else 0


def is_short_url(url):
    extracted = tldextract.extract(url.lower())

    domain = ".".join(
        part for part in [extracted.domain, extracted.suffix] if part
    )

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "shorturl.at",
        "rebrand.ly",
        "tiny.cc",
        "lnkd.in"
    ]

    return 1 if domain in shorteners else 0


def has_suspicious_keyword(url):
    suspicious_words = [
        "login",
        "verify",
        "free",
        "bank",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "signin",
        "payment",
        "wallet",
        "reward",
        "bonus",
        "gift",
        "otp",
        "kyc",
        "limited",
        "urgent",
        "claim",
        "support"
    ]

    return 1 if any(word in url.lower() for word in suspicious_words) else 0


def has_suspicious_tld(url):
    suspicious_tlds = [
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "xyz",
        "top",
        "work",
        "click",
        "link",
        "fit",
        "rest"
    ]

    extracted = tldextract.extract(url.lower())
    suffix = extracted.suffix.lower()

    return 1 if suffix in suspicious_tlds else 0


def extract_features(url):
    url = str(url).strip()
    url_lower = url.lower()

    parsed_url = urlparse(url_lower)
    extracted = tldextract.extract(url_lower)

    domain = extracted.domain
    subdomain = extracted.subdomain
    suffix = extracted.suffix

    full_domain = ".".join(
        part for part in [subdomain, domain, suffix] if part
    )

    features = [
        len(url_lower),                                      # 1. URL length
        len(domain),                                         # 2. Domain length
        len(full_domain),                                    # 3. Full domain length

        url_lower.count("."),                                # 4. Dots count
        url_lower.count("-"),                                # 5. Hyphen count
        url_lower.count("/"),                                # 6. Slash count
        url_lower.count("?"),                                # 7. Question mark count
        url_lower.count("="),                                # 8. Equal symbol count
        url_lower.count("@"),                                # 9. @ symbol count
        url_lower.count("%"),                                # 10. Percent symbol count

        sum(char.isdigit() for char in url_lower),           # 11. Digit count
        sum(not char.isalnum() for char in url_lower),        # 12. Special character count

        1 if parsed_url.scheme == "https" else 0,            # 13. HTTPS present
        1 if "@" in url_lower else 0,                         # 14. Has @ symbol
        has_suspicious_keyword(url_lower),                   # 15. Suspicious keyword
        has_ip_address(url_lower),                           # 16. IP address used
        is_short_url(url_lower),                             # 17. Short URL used
        has_suspicious_tld(url_lower),                       # 18. Suspicious TLD

        1 if parsed_url.query else 0,                         # 19. Query present
        len(subdomain.split(".")) if subdomain else 0,        # 20. Subdomain count
        1 if "-" in domain else 0,                            # 21. Hyphen in domain
        1 if any(char.isdigit() for char in domain) else 0     # 22. Digit in domain
    ]

    return features