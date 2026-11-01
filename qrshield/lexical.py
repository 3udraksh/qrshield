"""
QRShield Lexical Analysis, Shannon Entropy, and URL Obfuscation Engine
"""

import math
import ipaddress
from urllib.parse import unquote


def calculate_entropy(value):
    """
    Calculate Shannon entropy for a string.
    Higher entropy can indicate a less human-readable or highly randomized string.
    """
    if not value:
        return 0.0

    frequency = {}
    for character in value:
        frequency[character] = frequency.get(character, 0) + 1

    entropy = 0.0
    length = len(value)

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def decode_url_layers(url, max_layers=3):
    """
    Repeatedly percent-decode a URL and record each representation.
    """
    layers = [url]
    current = url

    for _ in range(max_layers):
        decoded = unquote(current)
        if decoded == current:
            break
        layers.append(decoded)
        current = decoded

    return layers


def is_ip_address(hostname):
    """
    Determine whether the hostname is an IPv4 or IPv6 address.
    """
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_hostname_structure(hostname):
    """
    Analyze hostname structure for suspicious subdomain patterns.
    """
    if not hostname:
        return {
            "subdomain_count": 0,
            "labels": [],
            "suspicious_subdomain": False,
            "reasons": []
        }

    hostname = hostname.lower().strip(".")
    labels = hostname.split(".")
    subdomains = labels[:-2] if len(labels) >= 2 else []

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "signin",
        "support",
        "bank",
        "wallet",
        "payment"
    ]

    suspicious_subdomains = [
        label for label in subdomains
        if any(keyword in label for keyword in suspicious_keywords)
    ]

    reasons = []
    if len(subdomains) >= 3:
        reasons.append("Multiple subdomain levels detected")

    if suspicious_subdomains:
        reasons.append("Security-sensitive keywords appear in subdomains")

    return {
        "subdomain_count": len(subdomains),
        "labels": labels,
        "suspicious_subdomain": bool(suspicious_subdomains),
        "suspicious_subdomains": suspicious_subdomains,
        "reasons": reasons
    }


def analyze_punycode(hostname):
    """
    Analyze a hostname for punycode/Internationalised domain names (IDN).
    """
    if not hostname:
        return {
            "detected": False,
            "labels": [],
            "punycode_labels": []
        }

    hostname = hostname.lower().strip(".")
    labels = hostname.split(".")
    punycode_labels = [label for label in labels if label.startswith("xn--")]

    return {
        "detected": bool(punycode_labels),
        "labels": labels,
        "punycode_labels": punycode_labels
    }


def analyze_port(parsed):
    """
    Analyze the explicit port used by a URL.
    """
    try:
        port = parsed.port
    except ValueError:
        return {
            "explicit": True,
            "port": None,
            "valid": False,
            "reason": "Invalid port specification"
        }

    if port is None:
        return {
            "explicit": False,
            "port": None,
            "valid": True,
            "reason": "No explicit port"
        }

    default_ports = {
        "http": 80,
        "https": 443
    }

    expected_port = default_ports.get(parsed.scheme.lower())

    return {
        "explicit": True,
        "port": port,
        "valid": True,
        "default": port == expected_port,
        "expected_port": expected_port,
        "reason": (
            "Default port"
            if port == expected_port
            else "Non-default port"
        )
    }


def analyze_path_query_deception(parsed):
    """
    Analyze URL path and query components for deception indicators.
    """
    path = parsed.path or ""
    query = parsed.query or ""

    security_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "password",
        "credential",
        "payment",
        "wallet",
        "bank"
    ]

    path_lower = path.lower()
    suspicious_path_keywords = [
        keyword for keyword in security_keywords
        if keyword in path_lower
    ]

    redirect_keywords = [
        "redirect",
        "url",
        "target",
        "next",
        "return",
        "returnurl",
        "continue",
        "dest",
        "destination"
    ]

    query_lower = query.lower()
    redirect_parameters = [
        keyword for keyword in redirect_keywords
        if f"{keyword}=" in query_lower
    ]

    return {
        "path": path,
        "query": query,
        "suspicious_path_keywords": suspicious_path_keywords,
        "redirect_parameters": redirect_parameters,
        "suspicious": bool(suspicious_path_keywords or redirect_parameters)
    }


def analyze_obfuscation_combination(
    decoding_count=0,
    userinfo_detected=False,
    suspicious_subdomain=False,
    punycode_detected=False,
    non_default_port=False,
    suspicious_path=False,
    redirect_parameters=False
):
    """
    Analyze combinations of URL obfuscation and deception indicators.
    """
    indicators = []

    if decoding_count > 0:
        indicators.append("URL decoding")
    if userinfo_detected:
        indicators.append("userinfo / @")
    if suspicious_subdomain:
        indicators.append("suspicious subdomain")
    if punycode_detected:
        indicators.append("Punycode / IDN")
    if non_default_port:
        indicators.append("non-default port")
    if suspicious_path:
        indicators.append("suspicious path")
    if redirect_parameters:
        indicators.append("redirect parameter")

    count = len(indicators)

    if count >= 4:
        level = "high"
    elif count >= 2:
        level = "medium"
    else:
        level = "low"

    return {
        "count": count,
        "level": level,
        "indicators": indicators
    }
