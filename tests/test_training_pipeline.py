import unittest

import pandas as pd

from src.features import FEATURE_NAMES, extract_features
from src.train_model import (
    make_key,
    pick_decision_settings,
    precision_at_prevalence,
    split_by_domain,
)


class TestTrainingPipeline(unittest.TestCase):

    def test_url_key_removes_common_format_differences(self):
        urls = pd.Series([
            "HTTPS://WWW.Example.com/path/",
            "example.com/path",
        ])

        keys = make_key(urls)

        self.assertEqual(keys.iloc[0], "example.com/path")
        self.assertEqual(keys.iloc[1], "example.com/path")

    def test_domain_split_keeps_domains_separate(self):
        rows = []

        for number in range(12):
            domain = f"site-{number}.example"

            for page in range(2):
                rows.append({
                    "url": f"{domain}/page-{page}",
                    "label": number % 2,
                    "key": f"{domain}/page-{page}",
                    "domain": domain,
                })

        data = pd.DataFrame(rows)
        first, second = split_by_domain(data, test_size=0.25)

        self.assertEqual(len(first) + len(second), len(data))
        self.assertFalse(set(first["domain"]) & set(second["domain"]))

    def test_precision_at_prevalence_uses_recall_and_false_positive_rate(self):
        precision = precision_at_prevalence(
            recall=0.90,
            fpr=0.05,
            prevalence=0.01,
        )

        self.assertAlmostEqual(precision, 0.153846, places=5)

    def test_decision_settings_are_selected_from_given_validation_rows(self):
        urls = pd.Series([
            "https://safe-one.com",
            "https://safe-two.com",
            "http://bad-login.xyz/verify",
            "http://192.168.1.10/login",
        ])
        lexical = pd.DataFrame(
            [extract_features(url) for url in urls],
            columns=FEATURE_NAMES,
        )
        labels = pd.Series([0, 0, 1, 1])
        raw_scores = [0.10, 0.20, 0.65, 0.80]

        selected, candidates = pick_decision_settings(
            urls,
            lexical,
            raw_scores,
            labels,
        )

        self.assertIn(selected, candidates)
        self.assertGreater(len(candidates), 1)
        self.assertGreaterEqual(selected["recall"], 0.90)


if __name__ == "__main__":
    unittest.main()
