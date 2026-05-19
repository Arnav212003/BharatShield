from sklearn.feature_extraction.text import TfidfVectorizer


def clean_url_text(url):
    """
    Converts URL into clean lowercase text for NLP processing.
    """
    url = str(url).lower().strip()

    replacements = {
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
        "@": " "
    }

    for old, new in replacements.items():
        url = url.replace(old, new)

    return url


def create_nlp_vectorizer():
    """
    Creates TF-IDF vectorizer using character n-grams.
    Character n-grams are useful for phishing URL pattern detection.
    """
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=5000,
        lowercase=True
    )

    return vectorizer


def transform_urls_for_nlp(urls, vectorizer):
    """
    Converts URLs into NLP TF-IDF features.
    """
    cleaned_urls = [clean_url_text(url) for url in urls]
    return vectorizer.transform(cleaned_urls)


def fit_transform_urls_for_nlp(urls, vectorizer):
    """
    Fits vectorizer on URLs and converts them into NLP TF-IDF features.
    """
    cleaned_urls = [clean_url_text(url) for url in urls]
    return vectorizer.fit_transform(cleaned_urls)