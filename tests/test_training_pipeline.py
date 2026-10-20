import unittest

import numpy as np
import pandas as pd

from scripts.build_dataset import pick_test_groups, remove_conflicts
from src.evaluation import (
    binary_metrics,
    pick_blend_weight,
    pick_phishing_cutoff,
    pick_safe_cutoff,
    wilson_interval,
)
from src.train_model import split_by_site


def toy_data(rows=400):
    random = np.random.default_rng(0)
    groups = [f"site{i % 80}.com" for i in range(rows)]
    labels = [1 if int(group[4:-4]) % 3 == 0 else 0 for group in groups]

    return pd.DataFrame({
        "key": [f"{group}/page{i}" for i, group in enumerate(groups)],
        "label": labels,
        "group": groups,
        "noise": random.random(rows),
    })


class TestSplit(unittest.TestCase):

    def test_no_site_is_in_two_splits(self):
        train, val, test = split_by_site(toy_data())

        self.assertFalse(set(train["group"]) & set(test["group"]))
        self.assertFalse(set(train["group"]) & set(val["group"]))
        self.assertFalse(set(val["group"]) & set(test["group"]))
        self.assertEqual(len(train) + len(val) + len(test), 400)

    def test_every_split_has_both_classes(self):
        for part in split_by_site(toy_data()):
            self.assertEqual(part["label"].nunique(), 2)


class TestDatasetHelpers(unittest.TestCase):

    def test_conflicting_keys_are_removed(self):
        frame = pd.DataFrame({
            "key": ["a.com", "a.com", "b.com", "b.com", "c.com"],
            "label": [0, 1, 1, 1, 0],
        })
        cleaned, dropped = remove_conflicts(frame)

        self.assertEqual(sorted(cleaned["key"]), ["b.com", "c.com"])
        self.assertEqual(dropped, 2)

    def test_test_groups_are_repeatable(self):
        groups = [f"g{i}" for i in range(100)]

        self.assertEqual(pick_test_groups(groups, 0.1), pick_test_groups(groups, 0.1))
        self.assertEqual(len(pick_test_groups(groups, 0.1)), 10)


class TestEvaluation(unittest.TestCase):

    def test_binary_metrics(self):
        result = binary_metrics([0, 0, 1, 1], [0.1, 0.6, 0.7, 0.2], 0.5)

        self.assertEqual((result["tn"], result["fp"], result["fn"], result["tp"]), (1, 1, 1, 1))
        self.assertAlmostEqual(result["precision"], 0.5)
        self.assertAlmostEqual(result["recall"], 0.5)
        self.assertAlmostEqual(result["fpr"], 0.5)

    def test_wilson_interval(self):
        low, high = wilson_interval(90, 100)

        self.assertLess(low, 0.9)
        self.assertGreater(high, 0.9)
        self.assertIsNone(wilson_interval(0, 0))

    def test_cutoff_choices(self):
        labels = np.array([0] * 50 + [1] * 50)
        scores = np.r_[np.linspace(0, 0.45, 50), np.linspace(0.55, 1, 50)]

        safe = pick_safe_cutoff(labels, scores)
        phishing = pick_phishing_cutoff(labels, scores, safe["threshold"])

        self.assertEqual(safe["f1"], 1.0)
        self.assertGreater(phishing["threshold"], safe["threshold"])

    def test_blend_weight_prefers_better_model(self):
        labels = np.array([0, 0, 1, 1])
        good = np.array([0.1, 0.2, 0.8, 0.9])
        bad = np.array([0.9, 0.8, 0.2, 0.1])

        self.assertGreater(pick_blend_weight(labels, good, bad), 0.5)
        self.assertLess(pick_blend_weight(labels, bad, good), 0.5)


if __name__ == "__main__":
    unittest.main()
