import csv
import json
import os
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.abspath(os.getenv("BHARATSHIELD_MODEL_DIR", os.path.join(BASE_DIR, "model")))
SUMMARY_PATH = os.path.join(BASE_DIR, "data", "dataset_summary.json")


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


class TestModelArtifacts(unittest.TestCase):

    def test_required_files_exist(self):
        for file_name in [
            "phishing_model.pkl",
            "nlp_model.pkl",
            "hybrid_model.pkl",
            "model_config.json",
            "model_evaluation_report.csv",
            "training_metadata.json",
        ]:
            path = os.path.join(MODEL_DIR, file_name)

            with self.subTest(file_name=file_name):
                self.assertTrue(os.path.exists(path))
                self.assertGreater(os.path.getsize(path), 0)

    def test_model_files_are_small_enough_for_git(self):
        for file_name in ["phishing_model.pkl", "nlp_model.pkl", "hybrid_model.pkl"]:
            size_mb = os.path.getsize(os.path.join(MODEL_DIR, file_name)) / 1024 / 1024

            with self.subTest(file_name=file_name):
                self.assertLess(size_mb, 50)

    def test_config_is_valid(self):
        config = load_json(os.path.join(MODEL_DIR, "model_config.json"))

        self.assertAlmostEqual(config["lexical_weight"] + config["hybrid_weight"], 1.0, places=5)
        self.assertLess(0, config["safe_cutoff"])
        self.assertLess(config["safe_cutoff"], config["phishing_cutoff"])
        self.assertLessEqual(config["phishing_cutoff"], 1)

    def test_report_has_internal_and_external_rows(self):
        with open(os.path.join(MODEL_DIR, "model_evaluation_report.csv"), encoding="utf-8") as file:
            rows = list(csv.DictReader(file))

        datasets = {row["Dataset"] for row in rows}
        self.assertEqual(datasets, {"internal", "external"})

        for row in rows:
            self.assertTrue({"Precision", "Recall", "F1 Score", "FPR", "TP", "FP"} <= row.keys())

    def test_no_leakage_between_train_and_test(self):
        metadata = load_json(os.path.join(MODEL_DIR, "training_metadata.json"))

        self.assertEqual(metadata["split"]["shared_groups_train_test"], 0)
        self.assertEqual(metadata["split"]["shared_groups_train_validation"], 0)
        self.assertEqual(metadata["dataset"]["leakage_checks"]["test_groups_in_train"], 0)
        self.assertEqual(metadata["dataset"]["leakage_checks"]["test_keys_in_train"], 0)

    def test_external_phishing_is_newer_than_training_phishing(self):
        summary = load_json(SUMMARY_PATH)
        dates = summary["openphish_first_seen"]

        self.assertLess(dates["train_to"], summary["cutoff"])
        self.assertGreaterEqual(dates["test_from"], summary["cutoff"])


if __name__ == "__main__":
    unittest.main()
