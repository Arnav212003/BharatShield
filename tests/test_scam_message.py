import unittest

from src.scam_message import analyze_scam_message, extract_urls


class TestScamMessage(unittest.TestCase):

    def test_normal_message(self):
        result = analyze_scam_message(
            "Your package will arrive tomorrow."
        )
        self.assertEqual(result["status"], "Low Risk")

    def test_safe_otp_message(self):
        result = analyze_scam_message(
            "Your OTP is 458921. Never share your OTP with anyone."
        )
        self.assertEqual(result["status"], "Low Risk")

    def test_fraud_otp_message(self):
        result = analyze_scam_message(
            "Send your OTP immediately to verify your account."
        )
        self.assertEqual(result["status"], "Likely Fraud")

    def test_url_extraction(self):
        urls = extract_urls(
            "Verify your account at https://example.com/login"
        )
        self.assertEqual(
            urls,
            ["https://example.com/login"]
        )

    def test_shortened_url_extraction(self):
        urls = extract_urls(
            "Track reward here bit.ly/claim-now before midnight."
        )

        self.assertEqual(
            urls,
            ["https://bit.ly/claim-now"]
        )

    def test_remote_access_request(self):
        result = analyze_scam_message(
            "Install AnyDesk app for KYC verification and share your OTP."
        )

        self.assertEqual(result["status"], "Likely Fraud")
        self.assertIn("remote_access", result["signals"])

    def test_suspicious_link_message(self):
        def fake_predictor(url):
            return (
                "Phishing/Fraud URL",
                85,
                ["Suspicious keyword found"],
                94.5,
            )

        message = (
            "Your SBI KYC has expired. "
            "Verify immediately at sbi-update.xyz "
            "and enter your OTP."
        )

        result = analyze_scam_message(
            message,
            url_predictor=fake_predictor,
        )

        self.assertEqual(result["status"], "Likely Fraud")
        self.assertGreaterEqual(result["risk_score"], 70)


if __name__ == "__main__":
    unittest.main()
