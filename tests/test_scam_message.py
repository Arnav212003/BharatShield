import os
import unittest

import pandas as pd

from src.scam_message import SUSPICIOUS_CUTOFF, analyze_scam_message, extract_urls

SAMPLE_PATH = os.path.join(os.path.dirname(__file__), "data", "sample_messages.csv")


class TestScamMessage(unittest.TestCase):

    def test_normal_message(self):
        result = analyze_scam_message("Your package will arrive tomorrow.")
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
        self.assertEqual(
            extract_urls("Verify your account at https://example.com/login"),
            ["https://example.com/login"],
        )

    def test_shortened_url_extraction(self):
        self.assertEqual(
            extract_urls("Track reward here bit.ly/claim-now before midnight."),
            ["https://bit.ly/claim-now"],
        )

    def test_remote_access_request(self):
        result = analyze_scam_message(
            "Install AnyDesk app for KYC verification and share your OTP."
        )

        self.assertEqual(result["status"], "Likely Fraud")
        self.assertIn("remote_access", result["signals"])

    def test_indian_scam_types(self):
        cases = {
            "utility_disconnection": "Aapka bijli connection aaj raat kat jayega. Turant 9123456780 par call karein.",
            "family_emergency": "Hi papa this is my new number, I had an accident, send 15000 urgently.",
            "reward_bait": "Congratulations! You have won Rs 25 lakh in KBC lucky draw.",
            "authority_threat": "CBI officer here. You are under digital arrest for money laundering.",
            "job_task_scam": "Part time job, work from home and earn Rs 3000 daily by liking videos.",
            "investment_scam": "Double your money in 30 days. Guaranteed return.",
            "qr_to_receive": "Scan this QR code to receive Rs 4500 refund now.",
        }

        for signal, message in cases.items():
            with self.subTest(signal=signal):
                result = analyze_scam_message(message)
                self.assertIn(signal, result["signals"])
                self.assertNotEqual(result["status"], "Low Risk")

    def test_rupee_word_boundary(self):
        # "users" contains "rs", it must not look like a payment request
        result = analyze_scam_message("Please send the list of users to the team.")
        self.assertNotIn("payment_request", result["signals"])

    def test_maintenance_notice_is_not_a_threat(self):
        result = analyze_scam_message(
            "Power supply will be shut down tomorrow from 10 am to 2 pm for maintenance."
        )
        self.assertEqual(result["status"], "Low Risk")

    def test_suspicious_link_message(self):
        def fake_predictor(url):
            return "Phishing/Fraud URL", 85, ["Uses the name 'sbi'"]

        result = analyze_scam_message(
            "Your SBI KYC has expired. Verify immediately at sbi-update.xyz and enter your OTP.",
            url_predictor=fake_predictor,
        )

        self.assertEqual(result["status"], "Likely Fraud")
        self.assertEqual(result["url_results"][0]["risk_score"], 85)

    def test_broken_link_scan_does_not_crash(self):
        def failing_predictor(url):
            raise RuntimeError("model missing")

        result = analyze_scam_message("Check example.com", url_predictor=failing_predictor)
        self.assertIn("error", result["url_results"][0])

    def test_sample_messages_without_link_scanning(self):
        # These examples were written by hand and the rules were tuned on
        # them, so this is a regression check, not an accuracy benchmark.
        # Two scam messages in the file are only caught by the URL model.
        samples = pd.read_csv(SAMPLE_PATH)
        flagged = samples["message"].map(
            lambda text: analyze_scam_message(text)["risk_score"] >= SUSPICIOUS_CUTOFF
        )
        wrong = int((flagged.astype(int) != samples["label"]).sum())

        self.assertLessEqual(wrong, 2)
        self.assertFalse(flagged[samples["label"] == 0].any(), "a normal message was flagged")


if __name__ == "__main__":
    unittest.main()
