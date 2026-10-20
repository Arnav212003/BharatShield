import unittest

from src.predict import predict_url, predict_url_batch, predict_url_details


class TestPredictUrl(unittest.TestCase):

    def test_empty_url_is_rejected(self):
        with self.assertRaises(ValueError):
            predict_url("")

    def test_scheme_does_not_change_the_ml_score(self):
        # the old model called google.com phishing only because it had no https://
        scores = {
            url: predict_url_details(url)["ml_risk_score"]
            for url in ["google.com", "http://google.com", "https://www.google.com"]
        }

        self.assertEqual(len(set(scores.values())), 1, scores)

    def test_trusted_sites_are_safe_with_or_without_scheme(self):
        for url in [
            "google.com",
            "http://www.google.com",
            "amazon.in",
            "https://www.flipkart.com/",
            "hdfcbank.com/personal/login",
            "https://uidai.gov.in",
        ]:
            with self.subTest(url=url):
                result, risk_score, reasons = predict_url(url)
                self.assertEqual(result, "Safe URL")
                self.assertLess(risk_score, 50)

    def test_phishing_patterns_are_not_safe(self):
        for url in [
            "https://sbi-kyc-update.com/login.php",
            "https://secure-hdfcbank-login.in/verify",
            "https://onlinesbi.sbi.kyc-verify.net/login",
            "https://accounts.google.com.evil.tk/signin",
            "http://192.168.1.10/login/verify-account",
            "https://sbi-yono-reward.pages.dev/",
        ]:
            with self.subTest(url=url):
                result, _, _ = predict_url(url)
                self.assertNotEqual(result, "Safe URL")

    def test_trusted_redirect_is_not_trusted(self):
        details = predict_url_details("https://www.google.com/url?q=https://fraud-example.xyz/login")

        self.assertIsNone(details["trusted_match"])
        self.assertIn("redirect", details["rules_applied"])

    def test_details_have_named_features_and_both_scores(self):
        details = predict_url_details("https://example.com/login")

        self.assertIn("URL Length", details["features"])
        self.assertEqual(details["explicit_scheme"], "https")
        self.assertTrue(0 <= details["ml_risk_score"] <= 100)
        self.assertTrue(0 <= details["lexical_risk"] <= 1)
        self.assertTrue(details["reasons"])

    def test_batch_scores_match_single_predictions(self):
        urls = ["https://example.com/about", "http://example.com/login", "bit.ly/abc"]
        batch = predict_url_batch(urls)

        for index, url in enumerate(urls):
            details = predict_url_details(url)
            self.assertEqual(round(batch.iloc[index]["final_risk"] * 100), details["risk_score"])

    def test_bad_inputs_are_rejected(self):
        for url in ["hello", "ftp://example.com/file", "mailto:help@example.com"]:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    predict_url(url)


if __name__ == "__main__":
    unittest.main()
