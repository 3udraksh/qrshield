from tests.test_base import IsolatedTestCase
import json
import os
import app


class ScanHistoryTestCase(IsolatedTestCase):
    """
    Tier 1 unit tests for scan history persistence, capping, corruption recovery, and math.
    """

    def test_save_scan_history_structure_and_persistence(self):
        """Saving a scan records expected keys to the isolated history file."""
        sample_result = {
            "url": "https://example.com/test",
            "content_type": "URL",
            "risk": "LOW RISK",
            "score": 10
        }
        app.save_scan_history(sample_result)

        self.assertTrue(os.path.exists(self.temp_history_file))
        with open(self.temp_history_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(len(data), 1)
        entry = data[0]
        self.assertEqual(entry["content"], "https://example.com/test")
        self.assertEqual(entry["content_type"], "URL")
        self.assertEqual(entry["risk"], "LOW RISK")
        self.assertEqual(entry["score"], 10)
        self.assertIn("timestamp", entry)

    def test_scan_history_capping_at_max_history(self):
        """History is capped at exactly 20 items (MAX_HISTORY)."""
        for i in range(25):
            res = {
                "url": f"https://example.com/item_{i}",
                "content_type": "URL",
                "risk": "LOW RISK",
                "score": i
            }
            app.save_scan_history(res)

        with open(self.temp_history_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(len(data), 20)
        # Most recent scan is at index 0
        self.assertEqual(data[0]["content"], "https://example.com/item_24")
        self.assertEqual(data[-1]["content"], "https://example.com/item_5")

    def test_corrupted_history_recovery(self):
        """Corrupted JSON in history file is caught safely and does not crash save or views."""
        with open(self.temp_history_file, "w", encoding="utf-8") as f:
            f.write("{invalid json content---")

        # Saving a new record should recover gracefully by resetting to [new_entry]
        sample_result = {
            "url": "https://example.com/recovered",
            "content_type": "URL",
            "risk": "LOW RISK",
            "score": 0
        }
        app.save_scan_history(sample_result)

        with open(self.temp_history_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["content"], "https://example.com/recovered")

    def test_dashboard_aggregation_math(self):
        """Verify dashboard statistics calculation using Flask test client."""
        # Seed test history file with 4 known records
        seed_data = [
            {"timestamp": "2026-09-28 14:10:06", "content": "http://a.com", "content_type": "URL", "risk": "LOW RISK", "score": 10},
            {"timestamp": "2026-09-28 14:11:06", "content": "http://b.com", "content_type": "URL", "risk": "CAUTION", "score": 40},
            {"timestamp": "2026-09-28 14:12:06", "content": "http://c.com", "content_type": "URL", "risk": "HIGH RISK", "score": 70},
            {"timestamp": "2026-09-28 14:13:06", "content": "WIFI:S:Guest", "content_type": "WIFI", "risk": "LOW RISK", "score": 0}
        ]
        with open(self.temp_history_file, "w", encoding="utf-8") as f:
            json.dump(seed_data, f)

        client = app.app.test_client()
        response = client.get("/dashboard")
        self.assertEqual(response.status_code, 200)

        html = response.data.decode("utf-8")
        # Total Scans = 4
        self.assertIn("Total Scans", html)
        self.assertIn("4", html)
        # Average score: (10 + 40 + 70 + 0) / 4 = 30.0
        self.assertIn("30.0/100", html)
        # Highest score = 70
        self.assertIn("70/100", html)
