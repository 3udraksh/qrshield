"""
QRShield Application Services: ScanService, HistoryService, ReportService
"""

import os
import json
import tempfile
from datetime import datetime
import cv2
import numpy as np
from qrshield.explainability import export_security_report
from qrshield.privacy import redact_sensitive_payload


class HistoryService:
    """Service managing scan history persistence, filtering, and aggregation."""

    @staticmethod
    def load_history(filepath):
        """Safely load history list from JSON file with corruption recovery and sample tagging."""
        if not filepath or not os.path.exists(filepath):
            return []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, list):
                    return []
                for scan in data:
                    if isinstance(scan, dict) and "is_sample" not in scan:
                        ts = str(scan.get("timestamp", ""))
                        scan["is_sample"] = ts.startswith("2026-09")
                return data
        except (json.JSONDecodeError, OSError):
            return []

    @staticmethod
    def save_scan(result, filepath, max_history=20):
        """Persist scan summary to history file, capping at max_history."""
        if not isinstance(result, dict) or not filepath:
            return

        history = HistoryService.load_history(filepath)
        raw_content = result.get("url")
        safe_content = result.get("safe_content") or redact_sensitive_payload(raw_content)

        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "content": safe_content if safe_content is not None else raw_content,
            "content_type": result.get("content_type"),
            "risk": result.get("risk"),
            "score": result.get("score"),
            "is_sample": False
        }
        history.insert(0, entry)
        history = history[:max_history]

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=4, ensure_ascii=False)
        except OSError:
            pass

    @staticmethod
    def clear_history(filepath):
        """Reset scan history to an empty list."""
        if not filepath:
            return False
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump([], f, indent=4, ensure_ascii=False)
            return True
        except OSError:
            return False

    @staticmethod
    def filter_history(history, query=None, risk_filter=None, type_filter=None):
        """Filter scan records by keyword search, risk category, and content type."""
        if not isinstance(history, list):
            return []

        filtered = list(history)

        if query and isinstance(query, str) and query.strip():
            q_clean = query.strip().lower()
            filtered = [
                scan for scan in filtered
                if q_clean in str(scan.get("content", "")).lower()
                or q_clean in str(scan.get("content_type", "")).lower()
                or q_clean in str(scan.get("risk", "")).lower()
            ]

        if risk_filter and isinstance(risk_filter, str) and risk_filter.strip().upper() not in ("", "ALL"):
            rf = risk_filter.strip().upper()
            filtered = [
                scan for scan in filtered
                if str(scan.get("risk", "")).upper() == rf
            ]

        if type_filter and isinstance(type_filter, str) and type_filter.strip().upper() not in ("", "ALL"):
            tf = type_filter.strip().upper()
            filtered = [
                scan for scan in filtered
                if str(scan.get("content_type", "")).upper() == tf
            ]

        return filtered

    @staticmethod
    def compute_dashboard_metrics(history, filtered_history=None):
        """Aggregate statistical metrics from scan history for dashboard rendering."""
        total_scans = len(history)
        low_risk = sum(1 for scan in history if scan.get("risk") == "LOW RISK")
        caution = sum(1 for scan in history if scan.get("risk") == "CAUTION")
        high_risk = sum(1 for scan in history if scan.get("risk") == "HIGH RISK")
        sample_scans = sum(1 for scan in history if scan.get("is_sample") is True)
        live_scans = total_scans - sample_scans

        scores = [
            scan.get("score")
            for scan in history
            if isinstance(scan.get("score"), (int, float))
        ]
        average_score = (
            round(sum(scores) / len(scores), 2)
            if scores
            else 0
        )

        today = datetime.now().date()
        scans_today = 0
        scans_last_7_days = 0

        for scan in history:
            try:
                scan_date = datetime.strptime(
                    scan.get("timestamp", ""),
                    "%Y-%m-%d %H:%M:%S"
                ).date()
                days_old = (today - scan_date).days
                if days_old == 0:
                    scans_today += 1
                if 0 <= days_old < 7:
                    scans_last_7_days += 1
            except (TypeError, ValueError):
                continue

        content_types = {}
        for scan in history:
            content_type = scan.get("content_type", "UNKNOWN")
            content_types[content_type] = content_types.get(content_type, 0) + 1

        most_common_content_type = (
            max(content_types, key=content_types.get)
            if content_types
            else "N/A"
        )
        highest_score = max(scores) if scores else 0

        display_history = filtered_history if filtered_history is not None else history

        return {
            "history": display_history,
            "total_scans": total_scans,
            "filtered_scans": len(display_history),
            "low_risk": low_risk,
            "caution": caution,
            "high_risk": high_risk,
            "sample_scans": sample_scans,
            "live_scans": live_scans,
            "average_score": average_score,
            "scans_today": scans_today,
            "scans_last_7_days": scans_last_7_days,
            "most_common_content_type": most_common_content_type,
            "highest_score": highest_score
        }


class ScanService:
    """Service managing image decoding, quality evaluation, and scan invocation."""

    @staticmethod
    def analyze_image_quality(image):
        """Evaluate image brightness, contrast, and resolution diagnostics."""
        if image is None:
            return {
                "valid": False,
                "width": 0,
                "height": 0,
                "brightness": None,
                "contrast": None,
                "quality": "INVALID"
            }

        height, width = image.shape[:2]
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        brightness = float(gray.mean())
        contrast = float(gray.std())

        if width < 200 or height < 200:
            quality = "LOW"
        elif brightness < 40 or brightness > 215:
            quality = "LOW"
        elif contrast < 25:
            quality = "LOW"
        else:
            quality = "GOOD"

        return {
            "valid": True,
            "width": width,
            "height": height,
            "brightness": round(brightness, 2),
            "contrast": round(contrast, 2),
            "quality": quality
        }

    @staticmethod
    def decode_qr_with_preprocessing(image):
        """Attempt QR decoding on original image and preprocessed variations."""
        detector = cv2.QRCodeDetector()
        images = [
            image,
            cv2.cvtColor(image, cv2.COLOR_BGR2GRAY),
            cv2.rotate(image, cv2.ROTATE_90_CLOCKWISE),
            cv2.rotate(image, cv2.ROTATE_90_COUNTERCLOCKWISE)
        ]

        decoded_codes = []
        for candidate in images:
            multi_found, decoded_info, _, _ = detector.detectAndDecodeMulti(candidate)
            if multi_found and decoded_info:
                for text in decoded_info:
                    if text and text.strip():
                        cleaned = text.strip()
                        if cleaned not in decoded_codes:
                            decoded_codes.append(cleaned)
            else:
                decoded_text, _, _ = detector.detectAndDecode(candidate)
                if decoded_text and decoded_text.strip():
                    cleaned = decoded_text.strip()
                    if cleaned not in decoded_codes:
                        decoded_codes.append(cleaned)

        return decoded_codes


class ReportService:
    """Service managing scan caching and report export generation."""

    def __init__(self, max_cache_size=50):
        self._cache = {}
        self._max_cache_size = max_cache_size

    def cache_result(self, result):
        """Store scan result in bounded in-memory cache keyed by URL/content."""
        if not isinstance(result, dict):
            return
        url = result.get("url")
        if url:
            if len(self._cache) >= self._max_cache_size:
                oldest_key = next(iter(self._cache))
                self._cache.pop(oldest_key, None)
            self._cache[url] = result

    def get_cached_result(self, content):
        """Retrieve pre-computed result for content if cached."""
        return self._cache.get(content)

    def export_temporary_report(self, result, export_func=None):
        """
        Generate temporary security report file on disk.
        Returns the path to the created file.
        """
        if export_func is None:
            export_func = export_security_report

        with tempfile.NamedTemporaryFile(
            mode="w",
            prefix="qrshield_report_",
            suffix=".json",
            delete=False,
            encoding="utf-8"
        ) as temp_file:
            filepath = temp_file.name

        export_func(result, filepath)
        return filepath
