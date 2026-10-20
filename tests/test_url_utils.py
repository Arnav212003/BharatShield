import unittest

from src.features import FEATURE_NAMES, extract_features, keyword_count
from src.url_utils import (
    canonical_key,
    get_explicit_scheme,
    is_ip_address,
    site_group,
    surt_to_key,
    validate_url_text,
)


class TestCanonicalKey(unittest.TestCase):

    def test_scheme_and_www_are_removed(self):
        for url in [
            "google.com",
            "http://google.com",
            "https://www.google.com",
            "HTTPS://WWW.GOOGLE.COM/",
            "//google.com",
        ]:
            with self.subTest(url=url):
                self.assertEqual(canonical_key(url), "google.com")

    def test_path_and_query_are_normalized(self):
        self.assertEqual(
            canonical_key("https://Example.com/A//B/?z=1&a=2#top"),
            "example.com/a/b?a=2&z=1",
        )

    def test_common_crawl_surt_gives_the_same_key(self):
        self.assertEqual(
            surt_to_key("in,co,example)/login?b=2&a=1"),
            canonical_key("https://www.example.co.in/login?a=1&b=2"),
        )
        self.assertEqual(surt_to_key("com,example,www)/"), "example.com")

    def test_userinfo_trick_keeps_the_real_host(self):
        self.assertEqual(canonical_key("http://paypal.com@evil.com/x"), "evil.com/x")


class TestSiteGroup(unittest.TestCase):

    def test_normal_site_uses_registered_domain(self):
        self.assertEqual(site_group("mail.google.com", ["github.io"]), "google.com")

    def test_free_hosting_tenant_is_its_own_group(self):
        self.assertEqual(site_group("arnav.github.io", ["github.io"]), "arnav.github.io")
        self.assertEqual(site_group("github.io", ["github.io"]), "github.io")


class TestValidation(unittest.TestCase):

    def test_valid_urls(self):
        for url in ["example.com", "https://example.co.in/a", "http://192.168.1.10/x", "example.com:8080/x"]:
            with self.subTest(url=url):
                self.assertEqual(validate_url_text(url), url)

    def test_invalid_urls(self):
        for url in ["", "hello", "ftp://example.com", "mailto:a@example.com", "a b.com", "javascript:alert(1)"]:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    validate_url_text(url)

    def test_explicit_scheme(self):
        self.assertEqual(get_explicit_scheme("HTTP://x.com"), "http")
        self.assertEqual(get_explicit_scheme("x.com"), "")

    def test_ip_formats(self):
        self.assertTrue(is_ip_address("192.168.0.1"))
        self.assertTrue(is_ip_address("0x7f000001"))
        self.assertTrue(is_ip_address("2130706433"))
        self.assertFalse(is_ip_address("example.com"))


class TestFeatures(unittest.TestCase):

    def test_feature_count_matches_names(self):
        self.assertEqual(len(extract_features("https://example.com/a?b=1")), len(FEATURE_NAMES))

    def test_scheme_does_not_change_features(self):
        # the old model learned "no https = phishing", this must not come back
        base = extract_features("example.com/login")

        for url in ["http://example.com/login", "https://www.example.com/login/"]:
            with self.subTest(url=url):
                self.assertEqual(extract_features(url), base)

    def test_short_keywords_need_a_full_word(self):
        self.assertEqual(keyword_count("hotpot.com/menu"), 0)
        self.assertEqual(keyword_count("example.com/otp/verify"), 2)


if __name__ == "__main__":
    unittest.main()
