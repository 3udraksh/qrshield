from tests.test_base import IsolatedTestCase
from unittest import mock
import io
import os
import cv2
import numpy as np
import app
import analyzer


class WebRoutesTestCase(IsolatedTestCase):
    """
    Tier 1 characterization tests for Flask application routes and helpers.
    """

    def setUp(self):
        super().setUp()
        self.client = app.app.test_client()

        # Mock heavy network components so route testing is instantaneous
        self.mock_tls_patcher = mock.patch.object(analyzer, "get_tls_certificate")
        self.mock_tls = self.mock_tls_patcher.start()
        self.mock_tls.return_value = {"retrieved": False, "certificate": None, "error": "Mocked"}
        self.addCleanup(self.mock_tls_patcher.stop)

        self.mock_redir_patcher = mock.patch.object(analyzer, "follow_redirect_chain")
        self.mock_redir = self.mock_redir_patcher.start()
        self.mock_redir.side_effect = lambda url, **kwargs: {
            "chain": [], "final_url": url, "completed": True,
            "redirect_count": 0, "loop_detected": False, "max_redirects_reached": False, "error": None
        }
        self.addCleanup(self.mock_redir_patcher.stop)

        self.mock_ai_patcher = mock.patch.object(analyzer, "generate_ai_explanation")
        self.mock_ai = self.mock_ai_patcher.start()
        self.mock_ai.return_value = {"status": "AVAILABLE", "explanation": "Route test AI explanation."}
        self.addCleanup(self.mock_ai_patcher.stop)

    def test_allowed_extensions(self):
        """Verify ALLOWED_EXTENSIONS configuration."""
        self.assertIn(".png", app.ALLOWED_EXTENSIONS)
        self.assertIn(".jpg", app.ALLOWED_EXTENSIONS)
        self.assertIn(".jpeg", app.ALLOWED_EXTENSIONS)
        self.assertNotIn(".gif", app.ALLOWED_EXTENSIONS)
        self.assertNotIn(".exe", app.ALLOWED_EXTENSIONS)

    def test_analyze_image_quality(self):
        """Verify image quality diagnostics."""
        res_none = app.analyze_image_quality(None)
        self.assertFalse(res_none["valid"])
        self.assertEqual(res_none["quality"], "INVALID")

        small_img = np.full((100, 100, 3), 128, dtype=np.uint8)
        res_small = app.analyze_image_quality(small_img)
        self.assertTrue(res_small["valid"])
        self.assertEqual(res_small["quality"], "LOW")

        good_img = np.zeros((300, 300, 3), dtype=np.uint8)
        good_img[:150, :] = 200
        res_good = app.analyze_image_quality(good_img)
        self.assertTrue(res_good["valid"])
        self.assertEqual(res_good["quality"], "GOOD")

    def test_get_index_route(self):
        """GET / returns HTTP 200 and main scan form."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn("QRShield", html)
        self.assertIn("Analyze a URL", html)
        self.assertIn("Analyze a QR Code", html)

    def test_post_url_analysis(self):
        """POST / with URL analyzes destination and renders results."""
        res = self.client.post("/", data={"url": "https://example.com"})
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn("Security Analysis", html)
        self.assertIn("https://example.com", html)
        self.assertIn("LOW RISK", html)

    def test_post_qr_image_invalid_extension(self):
        """POST / with non-image file extension returns error message."""
        data = {
            "qr_image": (io.BytesIO(b"not an image"), "payload.txt")
        }
        res = self.client.post("/", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn("Invalid image type", html)

    def test_post_qr_image_empty_file(self):
        """POST / with 0-byte file returns error message."""
        data = {
            "qr_image": (io.BytesIO(b""), "empty.png")
        }
        res = self.client.post("/", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn("The uploaded image is empty", html)

    def test_post_qr_image_corrupt_data(self):
        """POST / with corrupt bytes under .png extension returns error."""
        data = {
            "qr_image": (io.BytesIO(b"corrupt non-image binary payload"), "corrupt.png")
        }
        res = self.client.post("/", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn("The uploaded file is not a valid readable image", html)

    def test_post_qr_image_too_large(self):
        """POST / with file exceeding 5MB returns error message."""
        large_bytes = b"0" * (app.MAX_UPLOAD_SIZE + 1024)
        data = {
            "qr_image": (io.BytesIO(large_bytes), "toolarge.png")
        }
        res = self.client.post("/", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn("Image is too large", html)

    def test_post_qr_image_no_qr_detected(self):
        """POST / with valid image containing no QR code returns error message."""
        img = np.full((300, 300, 3), 255, dtype=np.uint8)
        _, img_encoded = cv2.imencode(".png", img)
        data = {
            "qr_image": (io.BytesIO(img_encoded.tobytes()), "blank.png")
        }
        res = self.client.post("/", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn("No readable QR code was detected", html)

    def test_post_qr_image_valid_demo_qr(self):
        """POST / with demo QR code successfully decodes and renders results."""
        demo_qr_path = "demo_qr/campus_safe.png"
        if os.path.exists(demo_qr_path):
            with open(demo_qr_path, "rb") as f:
                image_bytes = f.read()

            data = {
                "qr_image": (io.BytesIO(image_bytes), "campus_safe.png")
            }
            res = self.client.post("/", data=data, content_type="multipart/form-data")
            self.assertEqual(res.status_code, 200)
            html = res.data.decode("utf-8")
            self.assertIn("Security Analysis", html)
            self.assertIn("Decoded Content:", html)

    def test_get_dashboard_route(self):
        """GET /dashboard returns HTTP 200 and dashboard view."""
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn("QRShield Dashboard", html)
        self.assertIn("Total Scans", html)

    def test_export_report_empty_content_returns_400(self):
        """POST /export-report with empty content returns HTTP 400."""
        res = self.client.post("/export-report", data={"content": ""})
        self.assertEqual(res.status_code, 400)
        self.assertIn("No analysis result available", res.data.decode("utf-8"))

    def test_export_report_with_content(self):
        """POST /export-report triggers export logic without writing to workspace root."""
        with mock.patch("app.export_security_report") as mock_export, \
             mock.patch("app.send_file") as mock_send_file:
            mock_send_file.return_value = app.app.response_class(
                '{"report_type": "QRShield Security Report"}',
                mimetype="application/json"
            )
            res = self.client.post("/export-report", data={"content": "https://example.com"})
            self.assertEqual(res.status_code, 200)
            mock_export.assert_called_once()
            mock_send_file.assert_called_once()
