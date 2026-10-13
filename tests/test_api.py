import os
import sys
import unittest

from fastapi.testclient import TestClient


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

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

        self.assertEqual(response.status_code, 400)

    def test_scan_trusted_url(self):
        response = self.client.post(
            "/scan",
            json={"url": "https://accounts.google.com"},
        )

        body = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["result"], "Safe URL")
        self.assertTrue(body["trusted_domain"])

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

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
