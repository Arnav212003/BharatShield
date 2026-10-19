import csv
import hashlib
import json
import os
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_DIR = os.path.abspath(
    os.getenv("BHARATSHIELD_MODEL_DIR", MODEL_DIR)
)
DATA_PATH = os.path.abspath(
    os.getenv(
        "BHARATSHIELD_DATA_PATH",
        os.path.join(BASE_DIR, "data", "phishing.csv"),
    )
)


class TestModelArtifacts(unittest.TestCase):

    def test_required_model_files_exist(self):
        required_files = [
            "phishing_model.pkl",
            "nlp_model.pkl",
            "hybrid_model.pkl",
            "model_config.json",
            "model_evaluation_report.csv",
            "training_metadata.json",
        ]

        for file_name in required_files:
            path = os.path.join(MODEL_DIR, file_name)

            with self.subTest(file_name=file_name):
                self.assertTrue(os.path.exists(path))
                self.assertGreater(os.path.getsize(path), 0)

    def test_model_weights_are_valid(self):
        path = os.path.join(MODEL_DIR, "model_config.json")

        with open(path, "r", encoding="utf-8") as file:
            config = json.load(file)

        lexical_weight = float(config["lexical_weight"])
        hybrid_weight = float(config["hybrid_weight"])

        self.assertGreaterEqual(lexical_weight, 0.0)
        self.assertLessEqual(lexical_weight, 1.0)
        self.assertGreaterEqual(hybrid_weight, 0.0)
        self.assertLessEqual(hybrid_weight, 1.0)
        self.assertAlmostEqual(lexical_weight + hybrid_weight, 1.0, places=5)
        self.assertGreater(float(config["safe_cutoff"]), 0.0)
        self.assertLess(
            float(config["safe_cutoff"]),
            float(config["phishing_cutoff"]),
        )
        self.assertIn("risk_policy_name", config)
        self.assertIn("risk_policy", config)
        self.assertLess(
            float(config["trusted_domain_max_risk"]),
            float(config["safe_cutoff"]),
        )

    def test_evaluation_report_has_core_metrics(self):
        path = os.path.join(MODEL_DIR, "model_evaluation_report.csv")

        with open(path, "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            rows = list(reader)

        self.assertGreaterEqual(len(rows), 3)

        required_columns = {
            "Model",
            "Accuracy",
            "Domain-Macro Accuracy",
            "Precision",
            "Recall",
            "F1 Score",
            "ROC-AUC",
            "Est. Precision at 1% Prevalence",
            "FP",
            "FN",
        }

        self.assertTrue(required_columns.issubset(reader.fieldnames))

    def test_training_metadata_records_split_checks(self):
        path = os.path.join(MODEL_DIR, "training_metadata.json")

        with open(path, "r", encoding="utf-8") as file:
            metadata = json.load(file)

        self.assertEqual(metadata["dataset"]["provenance_status"], "unverified")
        self.assertEqual(len(metadata["dataset"]["sha256"]), 64)
        self.assertFalse(metadata["dataset"]["redistribution_allowed"])
        self.assertEqual(metadata["training"]["seed"], 42)
        self.assertEqual(metadata["training"]["feature_count"], 22)
        self.assertEqual(len(metadata["training"]["feature_names"]), 22)

        if os.path.exists(DATA_PATH):
            digest = hashlib.sha256()

            with open(DATA_PATH, "rb") as file:
                for chunk in iter(lambda: file.read(1024 * 1024), b""):
                    digest.update(chunk)

            self.assertEqual(
                metadata["dataset"]["sha256"],
                digest.hexdigest(),
            )

        for overlap in metadata["overlap_checks"].values():
            self.assertEqual(overlap, 0)

        self.assertGreater(metadata["splits"]["test"]["rows"], 0)
        self.assertGreater(len(metadata["evaluation"]), 0)
        self.assertEqual(
            metadata["decision_policy_selection"]["split"],
            "validation",
        )
        self.assertGreater(
            metadata["decision_policy_selection"]["evaluated_candidate_count"],
            1,
        )
        self.assertEqual(metadata["versions"]["python"], "3.11.9")


if __name__ == "__main__":
    unittest.main()
