"""
QRShield Privacy and Sensitive Credential Redaction Module
"""

import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

SENSITIVE_QUERY_PARAMS = {
    "token", "password", "pwd", "pass", "secret", "key",
    "api_key", "apikey", "auth", "access_token", "session",
    "session_id", "pin", "credential", "auth_token"
}


def redact_wifi_payload(payload):
    """
    Redact the password field in Wi-Fi QR payloads (e.g. P:secret123;).
    Returns redacted string preserving SSID and encryption type.
    """
    if not payload or not isinstance(payload, str) or not payload.startswith("WIFI:"):
        return payload

    return re.sub(
        r"(;P:)(.*?)(;|$)",
        r"\g<1>[REDACTED]\3",
        payload,
        flags=re.IGNORECASE
    )


def redact_url_sensitive_params(url):
    """
    Redact sensitive query parameter values (e.g., token, password, secret) in URLs.
    """
    if not url or not isinstance(url, str):
        return url

    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url

        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        redacted_pairs = []

        for k, v in pairs:
            if k.lower() in SENSITIVE_QUERY_PARAMS or any(s in k.lower() for s in ["token", "secret", "pass", "key"]):
                redacted_pairs.append((k, "[REDACTED]"))
            else:
                redacted_pairs.append((k, v))

        new_query = urlencode(redacted_pairs)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    except Exception:
        return url


def redact_vcard_payload(payload):
    """
    Sanitize sensitive telephone digits in vCard payloads for display and reports.
    Preserves structural headers while masking private phone digits.
    """
    if not payload or not isinstance(payload, str) or "BEGIN:VCARD" not in payload:
        return payload

    def mask_tel(match):
        header = match.group(1)
        raw_number = match.group(2).strip()
        prefix = raw_number[:3] if len(raw_number) >= 3 else ""
        return f"{header}{prefix}-***-****"

    return re.sub(
        r"(TEL[^:]*:)([+\d\s().-]+)",
        mask_tel,
        payload,
        flags=re.IGNORECASE
    )


def redact_sensitive_payload(content):
    """
    Sanitize sensitive information across various QR payload types.
    """
    if not content or not isinstance(content, str):
        return content

    if content.startswith("WIFI:"):
        return redact_wifi_payload(content)

    if content.startswith(("http://", "https://")):
        return redact_url_sensitive_params(content)

    if "BEGIN:VCARD" in content:
        return redact_vcard_payload(content)

    return content
