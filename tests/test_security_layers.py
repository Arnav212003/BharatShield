import unittest

from src.security_layers import (
    PHISHING_CUTOFF,
    SAFE_CUTOFF,
    TRUSTED_MAX_RISK,
    apply_rules,
    build_reasons,
    check_url,
    find_impersonated_brand,
    get_redirect_target,
    get_trusted_match,
    risk_to_result,
)


class TestTrustedList(unittest.TestCase):

    def test_trusted_roots_and_subdomains(self):
        for url in ["https://www.hdfcbank.com/login", "amazon.in", "http://netbanking.hdfcbank.com"]:
            with self.subTest(url=url):
                self.assertEqual(get_trusted_match(url), "trusted_root")

    def test_government_and_bank_suffixes(self):
        for url in ["https://uidai.gov.in", "incometax.gov.in/iec/foportal", "https://sbi.bank.in"]:
            with self.subTest(url=url):
                self.assertEqual(get_trusted_match(url), "trusted_suffix")

    def test_lookalikes_are_not_trusted(self):
        for url in [
            "https://hdfcbank.com.evil.tk",
            "https://hdfcbank-login.com",
            "https://sites.google.com/view/sbi-kyc",
            "https://www.google.com/url?q=https://evil.xyz/login",
            "http://amazon.in@evil.com",
            "https://fakegov.in",
        ]:
            with self.subTest(url=url):
                self.assertIsNone(get_trusted_match(url))


class TestBrandImpersonation(unittest.TestCase):

    def test_brand_on_other_domain_is_found(self):
        cases = {
            "https://sbi-kyc-update.com/login": "sbi",
            "https://onlinesbi.sbi.kyc-verify.net": "onlinesbi",
            "https://hdfcbank-netbanking.in": "hdfc",
            "https://accounts.google.com.evil.tk/signin": "google",
            "https://paypa1.com/signin": "paypal",
            "https://g00gle-security.com": "google",
            "https://paytm-reward.pages.dev": "paytm",
        }

        for url, brand in cases.items():
            with self.subTest(url=url):
                self.assertEqual(find_impersonated_brand(url), brand)

    def test_official_and_unrelated_sites_are_not_flagged(self):
        for url in [
            "https://www.onlinesbi.sbi",
            "https://www.sbicard.com",
            "https://www.hdfcergo.com",
            "https://www.icicidirect.com",
            "https://www.pineapple-recipes.com",
            "https://github.io",
            "https://my-portfolio.github.io",
            "https://www.outlookindia.com",
        ]:
            with self.subTest(url=url):
                self.assertIsNone(find_impersonated_brand(url))


class TestRedirect(unittest.TestCase):

    def test_redirect_to_other_site(self):
        self.assertEqual(
            get_redirect_target("https://www.google.com/url?q=https://evil.xyz/login"),
            "evil.xyz",
        )
        self.assertEqual(get_redirect_target("example.com/go?next=evil.xyz/login"), "evil.xyz")

    def test_same_site_or_normal_query_is_not_a_redirect(self):
        self.assertIsNone(get_redirect_target("https://example.com/a?next=https://example.com/b"))
        self.assertIsNone(get_redirect_target("https://example.com/search?q=cricket"))


class TestApplyRules(unittest.TestCase):

    def test_trusted_site_is_capped(self):
        risk, applied = apply_rules(0.9, check_url("https://www.amazon.in/dp/B0CX59"))

        self.assertEqual(risk, TRUSTED_MAX_RISK)
        self.assertIn("trusted", applied)

    def test_brand_impersonation_adds_risk(self):
        risk, applied = apply_rules(0.4, check_url("https://sbi-kyc-update.com"))

        self.assertAlmostEqual(risk, 0.7)
        self.assertIn("brand_impersonation", applied)

    def test_brand_misuse_is_never_safe(self):
        risk, _ = apply_rules(0.05, check_url("https://g00gle.com"))

        self.assertEqual(risk_to_result(risk), "Suspicious URL")

    def test_shortener_is_never_safe(self):
        risk, applied = apply_rules(0.05, check_url("https://bit.ly/abc"))

        self.assertEqual(risk, SAFE_CUTOFF)
        self.assertIn("shortener", applied)

    def test_shortener_alone_stays_suspicious(self):
        risk, applied = apply_rules(0.99, check_url("https://bit.ly/abc"))

        self.assertEqual(risk_to_result(risk), "Suspicious URL")
        self.assertIn("shortener_cap", applied)

    def test_shortener_with_at_trick_can_be_phishing(self):
        risk, applied = apply_rules(0.7, check_url("http://sbi.co.in@bit.ly/abc"))

        self.assertEqual(risk_to_result(risk), "Phishing/Fraud URL")
        self.assertNotIn("shortener_cap", applied)

    def test_free_hosting_alone_stays_suspicious(self):
        risk, applied = apply_rules(0.99, check_url("https://my-portfolio.github.io"))

        self.assertLess(risk, PHISHING_CUTOFF)
        self.assertEqual(risk_to_result(risk), "Suspicious URL")
        self.assertIn("free_hosting_cap", applied)

    def test_free_hosting_with_brand_can_be_phishing(self):
        risk, _ = apply_rules(0.9, check_url("https://sbi-yono-reward.pages.dev"))

        self.assertEqual(risk_to_result(risk), "Phishing/Fraud URL")

    def test_risk_stays_between_0_and_1(self):
        risk, _ = apply_rules(0.95, check_url("http://paypal.com@192.168.1.5/?u=https://x.xyz"))

        self.assertLessEqual(risk, 1.0)

    def test_reasons_mention_http_but_score_ignores_it(self):
        http_risk, _ = apply_rules(0.3, check_url("http://example.com/page"))
        https_risk, _ = apply_rules(0.3, check_url("https://example.com/page"))

        self.assertEqual(http_risk, https_risk)
        self.assertIn(
            "Not using HTTPS (connection is not encrypted)",
            build_reasons(0.3, check_url("http://example.com/page")),
        )

    def test_trusted_domain_with_high_ml_score(self):
        trusted_reasons = build_reasons(0.9, check_url("https://www.hdfcbank.com"))
        other_reasons = build_reasons(0.9, check_url("https://example.com"))

        self.assertIn(
            "URL model scored it as risky, but the trusted list marks it as an official site",
            trusted_reasons,
        )
        self.assertNotIn("URL model: pattern is similar to known phishing links", trusted_reasons)
        self.assertIn("URL model: pattern is similar to known phishing links", other_reasons)


if __name__ == "__main__":
    unittest.main()
