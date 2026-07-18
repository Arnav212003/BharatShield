from sklearn.feature_extraction.text import TfidfVectorizer

# convert all URL separators into spaces
# so TF-IDF gets clean tokens to work with
_REPLACEMENTS = {
    "https://": "", "http://": "", "www.": "",
    "/": " ", "-": " ", "_": " ", ".": " ",
    "?": " ", "=": " ", "&": " ", "%": " ", "@": " "
}


def clean_url_text(url):
    url = str(url).lower().strip()
    for old, new in _REPLACEMENTS.items():
        url = url.replace(old, new)
    return url


def create_nlp_vectorizer():
    # char n-grams because phishing URLs use odd spellings
    # like "paypa1" or "g00gle" - word level tokens miss these
    return TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=5000,
        lowercase=True
    )


def transform_urls_for_nlp(urls, vectorizer):
    return vectorizer.transform([clean_url_text(u) for u in urls])


def fit_transform_urls_for_nlp(urls, vectorizer):
    # fit only on training data, never on test data (avoids data leakage)
    return vectorizer.fit_transform([clean_url_text(u) for u in urls])