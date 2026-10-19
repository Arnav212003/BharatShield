import os
import sys
import unittest

import pandas as pd


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)

from train_model import make_key, split_by_domain


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


if __name__ == "__main__":
    unittest.main()
