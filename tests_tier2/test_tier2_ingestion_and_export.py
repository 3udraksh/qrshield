from tests.test_base import IsolatedTestCase
from unittest import mock
import io
import os
import app
import analyzer


class Tier2IngestionAndExportTestCase(IsolatedTestCase):
    """
    Tier 2 characterization for in-memory QR decoding and cached report export.
    """

    def setUp(self):
        super().setUp()
        self.client = app.app.test_client()

        # Mock heavy external components
        self.mock_tls = mock.patch.object(analyzer, "get_tls_certificate", return_value={"retrieved": False, "certificate": None, "error": "Mocked"})
        self.mock_tls.start()
        self.addCleanup(self.mock_tls.stop)

        self.mock_redir = mock.patch.object(analyzer, "follow_redirect_chain", side_effect=lambda url, **kwargs: {
            "chain": [], "final_url": url, "completed": True, "redirect_count": 0, "loop_detected": False, "max_redirects_reached": False, "error": None
        })
        self.mock_redir.start()
        self.addCleanup(self.mock_redir.stop)

        self.mock_ai = mock.patch.object(analyzer, "generate_ai_explanation", return_value={"status": "AVAILABLE", "explanation": "Mock AI explanation"})
        self.mock_ai.start()
        self.addCleanup(self.mock_ai.stop)

    def test_export_report_reuses_cached_scan_without_reanalysis(self):
        """Exporting a report for an already analyzed URL uses cache and avoids analyze_url re-execution."""
        # Step 1: Perform the initial scan
        res_initial = self.client.post("/", data={"url": "https://cached-example.com"})
        self.assertEqual(res_initial.status_code, 200)

        # Step 2: Export report for that same URL, verifying analyze_url is NOT invoked
        with mock.patch("app.analyze_url") as mock_analyze, \
             mock.patch("app.export_security_report") as mock_export, \
             mock.patch("app.send_file") as mock_send_file:
            mock_send_file.return_value = app.app.response_class('{}', mimetype="application/json")

            res_export = self.client.post("/export-report", data={"content": "https://cached-example.com"})
            self.assertEqual(res_export.status_code, 200)
            # Must NOT re-analyze
            mock_analyze.assert_not_called()
            mock_export.assert_called_once()
            mock_send_file.assert_called_once()

    def test_in_memory_qr_ingestion_leaves_zero_disk_artifacts(self):
        """Uploading a QR image decodes in memory without writing temporary files to UPLOAD_FOLDER."""
        demo_qr_path = "demo_qr/campus_safe.png"
        self.assertTrue(os.path.exists(demo_qr_path), "Demo QR fixture must exist")

        with open(demo_qr_path, "rb") as f:
            image_bytes = f.read()

        initial_files = os.listdir(app.UPLOAD_FOLDER)

        data = {
            "qr_image": (io.BytesIO(image_bytes), "test_qr.png")
        }
        res = self.client.post("/", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Security Analysis", res.data.decode("utf-8"))

        # Zero temporary files created in upload folder
        current_files = os.listdir(app.UPLOAD_FOLDER)
        self.assertEqual(initial_files, current_files)

    def test_export_report_uses_isolated_temporary_filepath(self):
        """Report export creates isolated temporary file, preventing shared root file collisions."""
        with mock.patch("app.export_security_report") as mock_export, \
             mock.patch("app.send_file") as mock_send_file:
            mock_send_file.return_value = app.app.response_class('{}', mimetype="application/json")

            res = self.client.post("/export-report", data={"content": "https://isolated-test.example"})
            self.assertEqual(res.status_code, 200)

            # Export must use a unique temp path, not fixed 'qrshield_security_report.json' in cwd
            called_path = mock_export.call_args[0][1]
            self.assertNotEqual(called_path, "qrshield_security_report.json")
            self.assertIn("qrshield_report_", called_path)
