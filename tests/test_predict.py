import os
import sys
import unittest


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)

from predict import predict_url


class TestPredictUrl(unittest.TestCase):

    def test_empty_url_is_rejected(self):
        with self.assertRaises(ValueError):
            predict_url("")

    def test_clean_trusted_domain_is_safe(self):
        result, risk_score, reasons, confidence = predict_url(
            "https://accounts.google.com"
        )

        self.assertEqual(result, "Safe URL")
        self.assertLessEqual(risk_score, 18)
        self.assertIn("Trusted official domain detected", reasons)
        self.assertGreaterEqual(confidence, 50)

    def test_obvious_phishing_pattern_is_not_safe(self):
        result, risk_score, reasons, confidence = predict_url(
            "http://192.168.1.10/login/verify-account"
        )

        self.assertIn(result, {"Suspicious URL", "Phishing/Fraud URL"})
        self.assertGreaterEqual(risk_score, 35)
        self.assertIn("IP address used in URL", reasons)
        self.assertGreaterEqual(confidence, 50)


if __name__ == "__main__":
    unittest.main()
