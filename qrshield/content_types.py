"""
QRShield Content Type Detection and Payload Analyzers
"""

import re
import urllib.parse


def detect_qr_content_type(content):
    """
    Identify the basic type of data decoded from a QR code.
    """
    if not content:
        return "EMPTY"

    content = content.strip()

    if content.lower().startswith(("http://", "https://")):
        return "URL"
    if content.upper().startswith("WIFI:"):
        return "WIFI"
    if content.upper().startswith("BEGIN:VCARD"):
        return "VCARD"
    if content.lower().startswith("mailto:"):
        return "EMAIL"
    if content.lower().startswith("tel:"):
        return "PHONE"
    if content.lower().startswith("sms:"):
        return "SMS"
    if content.lower().startswith("geo:"):
        return "GEOLOCATION"

    return "TEXT"


def analyze_wifi_qr(content):
    """
    Extract basic security information from a Wi-Fi QR payload.
    """
    if not content or not content.upper().startswith("WIFI:"):
        return {
            "valid": False,
            "authentication": None,
            "ssid": None,
            "hidden": False,
            "open_network": False,
            "unknown_security": False,
            "finding": None
        }

    data = content[5:].rstrip(";")
    fields = {}

    for item in data.split(";"):
        if ":" not in item:
            continue
        key, value = item.split(":", 1)
        fields[key.upper()] = value

    authentication = fields.get("T", "").upper()
    ssid = fields.get("S")
    hidden = fields.get("H", "").lower() == "true"

    open_network = authentication == "NOPASS"
    unknown_security = authentication == ""

    finding = None
    if open_network:
        finding = (
            "Wi-Fi QR code describes an open network "
            "without password-based authentication."
        )
    elif unknown_security:
        finding = (
            "Wi-Fi QR code does not specify an authentication type."
        )

    return {
        "valid": True,
        "authentication": authentication or "UNKNOWN",
        "ssid": ssid,
        "hidden": hidden,
        "open_network": open_network,
        "unknown_security": unknown_security,
        "finding": finding
    }


def analyze_vcard_qr(content):
    """
    Extract basic security-relevant information from a vCard QR payload.
    """
    if not content or not content.upper().startswith("BEGIN:VCARD"):
        return {
            "valid": False,
            "name": None,
            "phone": None,
            "email": None,
            "urls": [],
            "finding": None
        }

    lines = content.splitlines()
    name = None
    phone = None
    email = None
    urls = []

    for line in lines:
        upper_line = line.upper()
        if upper_line.startswith("FN:"):
            name = line[3:].strip()
        elif upper_line.startswith("TEL:"):
            phone = line[4:].strip()
        elif upper_line.startswith("EMAIL:"):
            email = line[6:].strip()
        elif upper_line.startswith(("URL:", "URL;")):
            value = line.split(":", 1)[1].strip()
            if value:
                urls.append(value)

    finding = None
    if urls:
        finding = (
            "vCard QR code contains a web URL that should be "
            "reviewed before opening."
        )

    return {
        "valid": True,
        "name": name,
        "phone": phone,
        "email": email,
        "urls": urls,
        "finding": finding
    }


def extract_embedded_urls(content):
    """
    Extract HTTP/HTTPS URLs embedded inside non-URL QR content.
    """
    if not content:
        return []

    urls = re.findall(
        r'https?://[^\s<>"\']+',
        content,
        re.IGNORECASE
    )

    return [
        url.rstrip(".,;:!?)]}")
        for url in urls
    ]


def analyze_message_qr(content, content_type):
    """
    Extract security-relevant information from EMAIL or SMS QR content.
    """
    if not content or content_type not in ("EMAIL", "SMS"):
        return {
            "valid": False,
            "recipient": None,
            "message": None,
            "urls": [],
            "finding": None
        }

    recipient = None
    message = None

    if content_type == "EMAIL":
        data = content[7:]  # remove mailto:
        if "?" in data:
            recipient, query = data.split("?", 1)
            params = urllib.parse.parse_qs(query)
            message = params.get("body", [None])[0]
        else:
            recipient = data

    elif content_type == "SMS":
        data = content[4:]  # remove sms:
        if "?" in data:
            recipient, query = data.split("?", 1)
            params = urllib.parse.parse_qs(query)
            message = params.get("body", [None])[0]
        else:
            recipient = data

    urls = extract_embedded_urls(content)
    finding = None

    if urls:
        finding = (
            f"{content_type} QR code contains a web URL "
            "that should be reviewed before opening."
        )

    return {
        "valid": True,
        "recipient": recipient,
        "message": message,
        "urls": urls,
        "finding": finding
    }
