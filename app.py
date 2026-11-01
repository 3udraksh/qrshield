"""
QRShield Flask Application

Web interface providing interactive QR image and URL vulnerability analysis,
historical scan telemetry, and security report generation.
"""

from flask import Flask, render_template, request, send_file, after_this_request
from analyzer import analyze_url, export_security_report
from qrshield.services import HistoryService, ScanService, ReportService

import cv2
import numpy as np
import os
import tempfile


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
MAX_UPLOAD_SIZE = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}

HISTORY_FILE = "scan_history.json"
MAX_HISTORY = 20

# Service instances
report_service = ReportService(max_cache_size=50)
_SCAN_RESULT_CACHE = report_service._cache
_MAX_CACHE_SIZE = 50

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Module-level delegates for backward compatibility with existing tests
def _cache_scan_result(result):
    """Cache the most recent scan result by URL/content."""
    report_service.cache_result(result)


def _get_cached_scan_result(content):
    """Retrieve a pre-computed scan result if available."""
    return report_service.get_cached_result(content)


def decode_qr_with_preprocessing(image):
    """Try QR decoding on the original image and variations."""
    return ScanService.decode_qr_with_preprocessing(image)


def analyze_image_quality(image):
    """Analyze basic image properties that can affect QR decoding."""
    return ScanService.analyze_image_quality(image)


def save_scan_history(result):
    """Save a successful scan's essential metadata."""
    HistoryService.save_scan(
        result,
        filepath=globals().get("HISTORY_FILE", HISTORY_FILE),
        max_history=globals().get("MAX_HISTORY", MAX_HISTORY)
    )


@app.route("/dashboard", methods=["GET"])
def dashboard():
    history = HistoryService.load_history(globals().get("HISTORY_FILE", HISTORY_FILE))
    metrics = HistoryService.compute_dashboard_metrics(history)

    return render_template(
        "dashboard.html",
        **metrics
    )


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        # ----------------------------------------------
        # URL input
        # ----------------------------------------------
        url = request.form.get("url", "").strip()

        if url:
            result = analyze_url(url)
            save_scan_history(result)
            _cache_scan_result(result)

        # ----------------------------------------------
        # QR image input
        # ----------------------------------------------
        qr_file = request.files.get("qr_image")

        if qr_file and qr_file.filename:
            original_filename = qr_file.filename
            extension = os.path.splitext(original_filename)[1].lower()

            if extension not in ALLOWED_EXTENSIONS:
                error = (
                    "Invalid image type. Please upload "
                    "a PNG, JPG, or JPEG image."
                )
            else:
                qr_file.seek(0, os.SEEK_END)
                file_size = qr_file.tell()
                qr_file.seek(0)

                if file_size > MAX_UPLOAD_SIZE:
                    error = (
                        "Image is too large. "
                        "Maximum allowed size is 5 MB."
                    )
                elif file_size == 0:
                    error = (
                        "The uploaded image is empty."
                    )
                else:
                    file_bytes = qr_file.read()
                    nparr = np.frombuffer(file_bytes, np.uint8)
                    image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

                    if image is None:
                        error = (
                            "The uploaded file is not a valid "
                            "readable image."
                        )
                    else:
                        image_quality = analyze_image_quality(image)

                        try:
                            decoded_codes = decode_qr_with_preprocessing(image)

                            if len(decoded_codes) > 1:
                                error = (
                                    f"Multiple QR codes detected "
                                    f"({len(decoded_codes)}). "
                                    "Please upload an image "
                                    "containing one QR code "
                                    "at a time."
                                )
                            elif len(decoded_codes) == 1:
                                result = analyze_url(decoded_codes[0])
                                save_scan_history(result)
                                _cache_scan_result(result)
                            else:
                                if image_quality["quality"] == "LOW":
                                    error = (
                                        "No readable QR code "
                                        "was detected. Image "
                                        "quality may be affecting "
                                        "QR decoding."
                                    )
                                else:
                                    error = (
                                        "No readable QR code "
                                        "was detected in the "
                                        "uploaded image."
                                    )
                        except cv2.error:
                            error = (
                                "QR decoding failed because "
                                "the image could not be processed."
                            )
                        except Exception:
                            error = (
                                "An unexpected error occurred "
                                "while processing the QR code."
                            )

    history = HistoryService.load_history(globals().get("HISTORY_FILE", HISTORY_FILE))

    return render_template(
        "index.html",
        result=result,
        error=error,
        history=history
    )


@app.route("/export-report", methods=["POST"])
def export_report():
    content = request.form.get("content", "").strip()

    if not content:
        return "No analysis result available.", 400

    result = _get_cached_scan_result(content)

    if result is None:
        result = analyze_url(content)
        _cache_scan_result(result)

    with tempfile.NamedTemporaryFile(
        mode="w",
        prefix="qrshield_report_",
        suffix=".json",
        delete=False,
        encoding="utf-8"
    ) as temp_file:
        filepath = temp_file.name

    export_security_report(
        result,
        filepath
    )

    @after_this_request
    def cleanup_report_file(response):
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except OSError:
            pass
        return response

    return send_file(
        filepath,
        as_attachment=True,
        download_name="qrshield_security_report.json",
        mimetype="application/json"
    )


if __name__ == "__main__":
    app.run(debug=False)
