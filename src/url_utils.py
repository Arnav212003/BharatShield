import ipaddress
import re
from urllib.parse import urlsplit

import tldextract

# use the suffix list bundled with tldextract, so results do not change
# with a network download or a local cache
DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

SCHEME_PATTERN = re.compile(r"^([a-z][a-z0-9+.-]*)://", re.IGNORECASE)
WWW_PATTERN = re.compile(r"^www\d*\.")


def get_explicit_scheme(url):
    match = SCHEME_PATTERN.match(str(url).strip())
    return match.group(1).lower() if match else ""


def add_scheme(url):
    # only so urlsplit can find the hostname, the model never sees it
    url = str(url).strip()

    if get_explicit_scheme(url):
        return url

    if url.startswith("//"):
        return "http:" + url

    return "http://" + url


def split_url(url):
    try:
        parts = urlsplit(add_scheme(url))
        _ = parts.port
        return parts
    except ValueError:
        return None


def get_hostname(url):
    parts = split_url(url)

    if parts is None:
        return ""

    return (parts.hostname or "").strip(".").lower()


def strip_www(hostname):
    return WWW_PATTERN.sub("", hostname)


def is_ip_address(hostname):
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    # hex (0x7f000001) and plain decimal (2130706433) IPs also work in browsers
    return bool(
        re.fullmatch(r"0x[0-9a-f]+", hostname)
        or re.fullmatch(r"\d{8,10}", hostname)
    )


def domain_parts(hostname):
    return DOMAIN_EXTRACTOR(hostname)


def registered_domain(hostname):
    parts = domain_parts(hostname)

    if parts.suffix and parts.domain:
        return f"{parts.domain}.{parts.suffix}"

    return hostname


def host_matches(hostname, root):
    return hostname == root or hostname.endswith("." + root)


def site_group(hostname, shared_roots=()):
    # pages on free hosting (name.github.io, name.pages.dev) belong to
    # different people, so each tenant is its own group
    for root in shared_roots:
        if hostname != root and hostname.endswith("." + root):
            return strip_www(hostname)

    return registered_domain(hostname)


def canonical_key(url):
    """URL without scheme and www, lower case, sorted query.

    This matches the SURT keys of the Common Crawl index, so crawl URLs
    and phishing feed URLs look the same to the model.
    """
    parts = split_url(url)

    if parts is None or not parts.hostname:
        return ""

    hostname = strip_www(parts.hostname.strip(".").lower())
    path = re.sub(r"/{2,}", "/", parts.path.lower()).rstrip("/")
    query = parts.query.lower()

    key = hostname + path

    if query:
        key += "?" + "&".join(sorted(query.split("&")))

    return key


def surt_to_key(surt):
    # "in,co,example)/path?b=2&a=1" -> "example.co.in/path?a=1&b=2"
    host_part, _, rest = surt.partition(")")
    host_part = host_part.split(":")[0]
    hostname = strip_www(".".join(reversed(host_part.split(","))))

    path, _, query = rest.partition("?")
    key = hostname + path.rstrip("/")

    if query:
        key += "?" + "&".join(sorted(query.split("&")))

    return key


def key_hostname(key):
    return re.split(r"[/?]", key, maxsplit=1)[0]


def validate_url_text(url, max_length=2048):
    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if len(url) > max_length:
        raise ValueError(f"URL cannot be longer than {max_length} characters.")

    if any(char.isspace() for char in url):
        raise ValueError("URL cannot contain spaces.")

    scheme = get_explicit_scheme(url)

    if scheme and scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    # catches mailto:, javascript: and similar, but allows example.com:8080
    prefix = re.match(r"^([a-z][a-z0-9+.-]*):(?!\d)", url, re.IGNORECASE)

    if prefix and not scheme and "." not in prefix.group(1):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    parts = split_url(url)

    if parts is None:
        raise ValueError("URL contains an invalid port or host.")

    hostname = (parts.hostname or "").strip(".")

    if not hostname:
        raise ValueError("URL must contain a valid hostname.")

    if is_ip_address(hostname):
        return url

    extracted = domain_parts(hostname)

    if not extracted.domain or not extracted.suffix:
        raise ValueError("URL must contain a valid public domain.")

    return url
