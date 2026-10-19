import unittest

from src.features import extract_features
from src.security_layers import (
    FEATURE_NAMES,
    apply_risk_rules,
    get_reasons_from_features,
    is_redirect_link,
    is_trusted_domain,
    risk_score_to_result,
)


def feature_map(url):
    return dict(zip(FEATURE_NAMES, extract_features(url), strict=True))


class TestSecurityLayers(unittest.TestCase):

    def test_explicit_https_sets_https_feature(self):
        features = feature_map("https://example.com/login")

        self.assertEqual(features["HTTPS"], 1)
        self.assertEqual(features["Suspicious Keyword"], 1)

    def test_explicit_http_clears_https_feature(self):
        url = "http://example.com/login"
        features = feature_map(url)
        reasons = get_reasons_from_features(url, list(features.values()))

        self.assertEqual(features["HTTPS"], 0)
        self.assertIn("No HTTPS found", reasons)

    def test_url_without_scheme_is_not_assumed_https(self):
        url = "example.com/login"
        features = feature_map("example.com/login")
        reasons = get_reasons_from_features(url, list(features.values()))

        self.assertEqual(features["HTTPS"], 0)
        self.assertEqual(features["Suspicious Keyword"], 1)
        self.assertNotIn("No HTTPS found", reasons)

    def test_ip_address_url_is_flagged(self):
        features = feature_map("http://192.168.1.10/login")

        self.assertEqual(features["HTTPS"], 0)
        self.assertEqual(features["IP Address"], 1)

    def test_google_redirect_link_is_not_trusted(self):
        url = "https://www.google.com/url?q=https://fraud-example.xyz/login"

        self.assertTrue(is_redirect_link(url))
        self.assertFalse(is_trusted_domain(url))

    def test_user_content_host_is_not_trusted(self):
        self.assertFalse(
            is_trusted_domain("https://docs.google.com/forms/d/e/fake-form")
        )

    def test_clean_official_domain_is_trusted(self):
        self.assertTrue(is_trusted_domain("https://accounts.google.com"))

    def test_clean_trusted_domain_is_capped_below_alert_threshold(self):
        url = "https://accounts.google.com"
        features = extract_features(url)
        reasons = get_reasons_from_features(url, features)

        adjusted = apply_risk_rules(
            raw_ml_risk=0.82,
            features=features,
            reasons=reasons,
            trusted=True,
        )

        self.assertEqual(adjusted, 0.20)

    def test_trusted_domain_cap_does_not_raise_a_low_score(self):
        url = "https://accounts.google.com"
        features = extract_features(url)
        reasons = get_reasons_from_features(url, features)

        adjusted = apply_risk_rules(
            raw_ml_risk=0.10,
            features=features,
            reasons=reasons,
            trusted=True,
        )

        self.assertEqual(adjusted, 0.10)

    def test_http_trusted_domain_is_not_capped(self):
        url = "http://accounts.google.com"
        features = extract_features(url)
        reasons = get_reasons_from_features(url, features)

        adjusted = apply_risk_rules(
            raw_ml_risk=0.82,
            features=features,
            reasons=reasons,
            trusted=True,
        )

        self.assertEqual(adjusted, 0.82)

    def test_github_homepage_is_trusted_but_user_pages_are_not(self):
        self.assertTrue(is_trusted_domain("https://github.com"))
        self.assertFalse(is_trusted_domain("https://name.github.io/login"))

    def test_risk_score_boundaries(self):
        self.assertEqual(risk_score_to_result(20), "Safe URL")
        self.assertEqual(risk_score_to_result(45), "Suspicious URL")
        self.assertEqual(risk_score_to_result(80), "Phishing/Fraud URL")


if __name__ == "__main__":
    unittest.main()
