import unittest

from fastapi.testclient import TestClient

from api import app


class TestBharatShieldApi(unittest.TestCase):
    client: TestClient

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_endpoint(self):
        response = self.client.get("/health")
        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["model_ready"])
        self.assertIsNotNone(body["model_generated_at_utc"])
        self.assertLess(body["safe_cutoff"], body["phishing_cutoff"])

    def test_scan_rejects_empty_url(self):
        response = self.client.post("/scan", json={"url": "   "})
        self.assertEqual(response.status_code, 400)

    def test_scan_rejects_too_long_url(self):
        response = self.client.post("/scan", json={"url": "https://example.com/" + "a" * 2100})
        self.assertEqual(response.status_code, 422)

    def test_scan_trusted_url(self):
        response = self.client.post("/scan", json={"url": "https://accounts.google.com"})
        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["result"], "Safe URL")
        self.assertEqual(body["trusted_match"], "trusted_root")

    def test_scan_brand_impersonation(self):
        response = self.client.post("/scan", json={"url": "https://hdfcbank-kyc-update.com/login"})
        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["impersonated_brand"], "hdfc")
        self.assertNotEqual(body["result"], "Safe URL")

    def test_scan_rejects_text_without_a_public_domain(self):
        response = self.client.post("/scan", json={"url": "not-a-url"})
        self.assertEqual(response.status_code, 400)

    def test_scan_message_endpoint(self):
        response = self.client.post("/scan-message", json={"message": "Your parcel will arrive tomorrow."})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "Low Risk")

    def test_scan_message_with_link(self):
        response = self.client.post(
            "/scan-message",
            json={"message": "Your Netflix payment failed. Update billing at https://netflix-billing-update.com/account"},
        )
        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(body["status"], "Low Risk")
        self.assertEqual(len(body["url_results"]), 1)

    def test_scan_message_rejects_too_long_message(self):
        response = self.client.post("/scan-message", json={"message": "hello " * 700})
        self.assertEqual(response.status_code, 422)

    def test_openapi_has_scan_response_schema(self):
        schema = self.client.get("/openapi.json").json()
        response = schema["paths"]["/scan"]["post"]["responses"]["200"]

        self.assertIn("schema", response["content"]["application/json"])


if __name__ == "__main__":
    unittest.main()
