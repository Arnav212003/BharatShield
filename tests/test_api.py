import unittest

from fastapi.testclient import TestClient

from api import app


class TestBharatShieldApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        body = response.json()

        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["model_ready"])
        self.assertIsNotNone(body["model_generated_at_utc"])
        self.assertGreater(body["safe_cutoff"], 0)
        self.assertGreaterEqual(body["max_url_length"], 100)
        self.assertGreaterEqual(body["max_message_length"], 100)

    def test_scan_rejects_empty_url(self):
        response = self.client.post("/scan", json={"url": "   "})

        self.assertEqual(response.status_code, 400)

    def test_scan_rejects_too_long_url(self):
        response = self.client.post(
            "/scan",
            json={"url": "https://example.com/" + ("a" * 2100)},
        )

        self.assertEqual(response.status_code, 422)

    def test_scan_recognizes_trusted_url(self):
        response = self.client.post(
            "/scan",
            json={"url": "https://accounts.google.com"},
        )

        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["result"], "Safe URL")
        self.assertTrue(body["trusted_domain"])
        self.assertIn("score_certainty", body)
        self.assertNotIn("confidence", body)

    def test_scan_rejects_text_without_a_public_domain(self):
        response = self.client.post("/scan", json={"url": "not-a-url"})

        self.assertEqual(response.status_code, 400)

    def test_scan_message_endpoint(self):
        response = self.client.post(
            "/scan-message",
            json={"message": "Your parcel will arrive tomorrow."},
        )

        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["status"], "Low Risk")

    def test_scan_message_rejects_too_long_message(self):
        response = self.client.post(
            "/scan-message",
            json={"message": "hello " * 700},
        )

        self.assertEqual(response.status_code, 422)

    def test_openapi_has_scan_response_schema(self):
        schema = self.client.get("/openapi.json").json()
        response = schema["paths"]["/scan"]["post"]["responses"]["200"]

        self.assertIn("schema", response["content"]["application/json"])


if __name__ == "__main__":
    unittest.main()
