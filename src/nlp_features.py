from sklearn.feature_extraction.text import TfidfVectorizer


def create_nlp_vectorizer():
    """
    TF-IDF over character n-grams of the canonical URL key.

    Character n-grams catch small changes that word tokens miss,
    for example paypa1, g00gle or sbi-kyc-upd8.
    """
    return TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=50000,
        sublinear_tf=True,
        lowercase=True,
    )
