from sklearn.feature_extraction.text import TfidfVectorizer

REPLACEMENTS = {
    "https://": "",
    "http://": "",
    "www.": "",
    "/": " ",
    "-": " ",
    "_": " ",
    ".": " ",
    "?": " ",
    "=": " ",
    "&": " ",
    "%": " ",
    "@": " ",
}


def clean_url_text(url):
    """
    Clean a URL before passing it to the TF-IDF vectorizer.
    """

    url = str(url).lower().strip()

    for old_value, new_value in REPLACEMENTS.items():
        url = url.replace(old_value, new_value)

    return url


def create_nlp_vectorizer():
    """
    Create the TF-IDF vectorizer used for URL text analysis.

    Character n-grams work well for phishing URLs because attackers
    often slightly modify genuine-looking words such as:
    google -> g00gle
    paypal -> paypa1
    """

    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=5000,
        lowercase=True,
    )

    return vectorizer


def transform_urls_for_nlp(urls, vectorizer):
    """
    Transform URLs using an already trained TF-IDF vectorizer.
    """

    cleaned_urls = []

    for url in urls:
        cleaned_urls.append(clean_url_text(url))

    return vectorizer.transform(cleaned_urls)


def fit_transform_urls_for_nlp(urls, vectorizer):
    """
    Fit the TF-IDF vectorizer only on training data
    and then transform the same data.
    """

    cleaned_urls = []

    for url in urls:
        cleaned_urls.append(clean_url_text(url))

    return vectorizer.fit_transform(cleaned_urls)