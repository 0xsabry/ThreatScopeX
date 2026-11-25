"""Current Flask application smoke test.

Imports the actual ``app`` object from ``app.py`` and uses Flask's
built-in test client. No server is launched and no external API is
called.

Covers:
- ``GET /`` returns HTTP 200 with an HTML response and the security
  headers applied by ``core.security.SecurityHeaders``.
- ``POST /api/upload`` without an upload file returns the documented
  400 response (``{"error": "No file provided"}``).
- ``GET /api/results`` with no analysis yet returns 404.
"""

import unittest

from app import app


class TestFlaskApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_index_returns_html_200(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.content_type)
        self.assertTrue(response.data.startswith(b"<!DOCTYPE html>"))

    def test_security_headers_present(self):
        response = self.client.get("/")
        self.assertEqual(
            response.headers.get("X-Content-Type-Options"), "nosniff"
        )
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        csp = response.headers.get("Content-Security-Policy", "")
        self.assertTrue(
            csp.startswith("default-src 'self'"),
            f"unexpected Content-Security-Policy: {csp!r}",
        )

    def test_upload_without_file_returns_400(self):
        response = self.client.post("/api/upload", data={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"error": "No file provided"})

    def test_results_without_analysis_returns_404(self):
        response = self.client.get("/api/results")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.get_json(), {"error": "No analysis results available"}
        )


if __name__ == "__main__":
    unittest.main()
