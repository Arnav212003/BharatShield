import os
import sys
import unittest


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)

from features import extract_features
from security_layers import (
    FEATURE_NAMES,
    apply_confidence_calibration,
    get_reasons_from_features,
    is_redirect_link,
    is_trusted_domain,
    risk_score_to_result,
)


def feature_map(url):
    return dict(zip(FEATURE_NAMES, extract_features(url)))


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

    def test_trusted_clean_domain_caps_risk(self):
        url = "https://accounts.google.com"
        features = extract_features(url)
        reasons = get_reasons_from_features(url, features)

        calibrated = apply_confidence_calibration(
            raw_ml_risk=0.82,
            features=features,
            reasons=reasons,
            trusted=True,
        )

        self.assertLessEqual(calibrated, 0.18)

    def test_risk_score_boundaries(self):
        self.assertEqual(risk_score_to_result(20), "Safe URL")
        self.assertEqual(risk_score_to_result(45), "Suspicious URL")
        self.assertEqual(risk_score_to_result(80), "Phishing/Fraud URL")


if __name__ == "__main__":
    unittest.main()
