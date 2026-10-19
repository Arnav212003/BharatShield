import unittest

from src.predict import predict_url, predict_url_details


class TestPredictUrl(unittest.TestCase):

    def test_empty_url_is_rejected(self):
        with self.assertRaises(ValueError):
            predict_url("")

    def test_clean_trusted_domain_is_safe(self):
        result, risk_score, reasons, score_certainty = predict_url(
            "https://accounts.google.com"
        )

        self.assertEqual(result, "Safe URL")
        self.assertLess(risk_score, 50)
        self.assertIn("Trusted official domain detected", reasons)
        self.assertGreaterEqual(score_certainty, 0)
        self.assertLessEqual(score_certainty, 100)

    def test_http_trusted_domain_is_not_automatically_safe(self):
        details = predict_url_details("http://accounts.google.com")

        self.assertNotEqual(details["risk_score"], 20)
        self.assertIn("No HTTPS found", details["reasons"])

    def test_trusted_redirect_is_not_automatically_safe(self):
        details = predict_url_details(
            "https://www.google.com/url?q=https://fraud-example.xyz/login"
        )

        self.assertFalse(details["trusted_domain"])

    def test_obvious_phishing_pattern_is_not_safe(self):
        result, risk_score, reasons, score_certainty = predict_url(
            "http://192.168.1.10/login/verify-account"
        )

        self.assertIn(result, {"Suspicious URL", "Phishing/Fraud URL"})
        self.assertGreaterEqual(risk_score, 35)
        self.assertIn("IP address used in URL", reasons)
        self.assertGreaterEqual(score_certainty, 50)

    def test_prediction_details_use_named_features(self):
        details = predict_url_details("https://example.com/login")

        self.assertIn("URL Length", details["features"])
        self.assertEqual(details["explicit_scheme"], "https")
        self.assertIn("score_certainty", details)

    def test_plain_text_is_not_accepted_as_a_url(self):
        with self.assertRaises(ValueError):
            predict_url("hello")

    def test_unsupported_scheme_is_rejected(self):
        with self.assertRaises(ValueError):
            predict_url("ftp://example.com/file")

    def test_non_web_scheme_without_slashes_is_rejected(self):
        with self.assertRaises(ValueError):
            predict_url("mailto:help@example.com")

    def test_scheme_less_url_with_url_in_query_is_accepted(self):
        details = predict_url_details(
            "example.com/redirect?next=https://other.example/path"
        )

        self.assertEqual(details["root_domain"], "example.com")
        self.assertEqual(details["explicit_scheme"], "")


if __name__ == "__main__":
    unittest.main()
