"""
QRShield Configuration and Runtime Environment Settings
"""

import os


class Config:
    """Central configuration for QRShield security engine and Flask application."""

    # Server Settings
    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(24).hex())
    DEBUG = os.getenv("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")

    # Ingestion & Uploads
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
    MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", 5 * 1024 * 1024))  # 5 MB
    ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}

    # Persistence & Cache
    HISTORY_FILE = os.getenv("HISTORY_FILE", "scan_history.json")
    MAX_HISTORY = int(os.getenv("MAX_HISTORY", "20"))
    MAX_CACHE_SIZE = int(os.getenv("MAX_CACHE_SIZE", "50"))

    # Privacy & Redaction
    REDACT_SENSITIVE_DATA = os.getenv("REDACT_SENSITIVE_DATA", "1").lower() in ("1", "true", "yes")

    # Local Analysis Mode (Zero external network egress for user privacy)
    LOCAL_MODE = os.getenv("QRSHIELD_LOCAL_MODE", "1").lower() in ("1", "true", "yes")

    # Threat Intelligence & AI API Keys
    URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "")
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

    # Feature Toggles
    ENABLE_EXTERNAL_REPUTATION = bool(
        not LOCAL_MODE and (URLHAUS_AUTH_KEY or GOOGLE_SAFE_BROWSING_API_KEY)
    )
    ENABLE_GEMINI = bool(not LOCAL_MODE and GEMINI_API_KEY)


def get_integration_status():
    """Return dictionary of configured integrations and privacy modes for UI display."""
    return {
        "local_mode": Config.LOCAL_MODE,
        "urlhaus_configured": bool(Config.URLHAUS_AUTH_KEY),
        "safe_browsing_configured": bool(Config.GOOGLE_SAFE_BROWSING_API_KEY),
        "gemini_configured": bool(Config.GEMINI_API_KEY),
        "redaction_active": Config.REDACT_SENSITIVE_DATA
    }
