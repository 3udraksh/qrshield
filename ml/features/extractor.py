"""
QRShield Feature Extraction Subsystem (Schema v2)
Extracts 28 rich static lexical, domain, obfuscation, and structural features from URL strings.
Preserves backward compatibility with Schema v1 (9 features).
"""

import math
import re
from urllib.parse import urlparse, parse_qs, unquote
import pandas as pd
import numpy as np

# Keyword lists aligned with QRShield security indicators
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "account", "admin", "update", "banking",
    "secure", "webscr", "signin", "wallet", "confirm", "support",
    "auth", "password", "security", "portal", "suspended", "service"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".work",
    ".rest", ".live", ".sbs", ".cfd", ".shop", ".click",
    ".buzz", ".icu", ".monster", ".homes", ".cam"
}

REDIRECT_PARAM_NAMES = {"url", "redirect", "next", "dest", "destination", "return", "r", "u", "link", "goto"}

SCHEMA_V1_COLUMNS = [
    "URL Length",
    "Hostname Length",
    "Subdomain Count",
    "Path Depth",
    "Query Parameters",
    "Percent Encoded Characters",
    "Hostname Hyphens",
    "Hostname Digits",
    "Hostname Entropy"
]

SCHEMA_V2_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "path_depth",
    "query_param_count",
    "digit_count",
    "digit_ratio",
    "letter_count",
    "letter_ratio",
    "special_char_count",
    "special_char_ratio",
    "url_entropy",
    "hostname_entropy",
    "hostname_hyphens",
    "hostname_digits",
    "is_ip_address",
    "is_punycode",
    "suspicious_tld",
    "suspicious_keyword_count",
    "percent_encoding_count",
    "percent_encoding_depth",
    "userinfo_deception",
    "is_https",
    "non_default_port",
    "suspicious_redirect_param",
    "char_diversity"
]


def calculate_entropy(text):
    """Calculate Shannon entropy for character variation."""
    if not text:
        return 0.0
    counter = {}
    for char in text:
        counter[char] = counter.get(char, 0) + 1
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counter.values())


def extract_features_v1(url):
    """Extract legacy 9-feature vector (Schema v1) for baseline model compatibility."""
    features_v2 = extract_features_v2_dict(url)
    return [
        features_v2["url_length"],
        features_v2["hostname_length"],
        features_v2["subdomain_count"],
        features_v2["path_depth"],
        features_v2["query_param_count"],
        features_v2["percent_encoding_count"],
        features_v2["hostname_hyphens"],
        features_v2["hostname_digits"],
        features_v2["hostname_entropy"]
    ]


def extract_features_v2_dict(url):
    """Extract full 28 structural and lexical features from a URL string."""
    if not isinstance(url, str):
        url = str(url) if url is not None else ""

    url_str = url.strip()
    if not re.match(r"^https?://", url_str, re.IGNORECASE):
        parsed = urlparse("http://" + url_str)
        is_https = 0
    else:
        parsed = urlparse(url_str)
        is_https = 1 if parsed.scheme.lower() == "https" else 0

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    query = parsed.query or ""

    url_len = len(url_str)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    # Subdomains
    host_parts = hostname.split(".")
    is_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    if is_ip:
        subdomain_count = 0
    elif len(host_parts) > 2:
        subdomain_count = len(host_parts) - 2
    else:
        subdomain_count = 0

    # Path depth
    path_depth = len([p for p in path.split("/") if p])

    # Query params
    try:
        q_params = parse_qs(query)
        q_param_count = len(q_params)
        has_redir_param = 1 if any(k.lower() in REDIRECT_PARAM_NAMES for k in q_params.keys()) else 0
    except Exception:
        q_param_count = 0
        has_redir_param = 0

    # Digits and letters
    digits = sum(1 for c in url_str if c.isdigit())
    letters = sum(1 for c in url_str if c.isalpha())
    digit_ratio = round(digits / max(url_len, 1), 4)
    letter_ratio = round(letters / max(url_len, 1), 4)

    # Special chars
    special_chars = sum(1 for c in url_str if not c.isalnum())
    special_char_ratio = round(special_chars / max(url_len, 1), 4)

    # Entropies
    url_entropy = round(calculate_entropy(url_str), 4)
    hostname_entropy = round(calculate_entropy(hostname), 4)

    # Hostname attributes
    host_hyphens = hostname.count("-")
    host_digits = sum(1 for c in hostname if c.isdigit())
    is_punycode = 1 if "xn--" in hostname else 0
    suspicious_tld = 1 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

    # Keyword density in entire URL
    url_lower = url_str.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Percent encoding & multi-layer depth
    pct_count = url_str.count("%")
    depth = 0
    curr = url_str
    for _ in range(3):
        unq = unquote(curr)
        if unq != curr:
            depth += 1
            curr = unq
        else:
            break

    try:
        userinfo_deception = 1 if ("@" in url_str and parsed.username) else 0
    except (ValueError, TypeError):
        userinfo_deception = 1 if "@" in url_str else 0

    try:
        non_default_port = 1 if parsed.port and parsed.port not in (80, 443) else 0
    except (ValueError, TypeError):
        non_default_port = 0

    char_diversity = round(len(set(url_str)) / max(url_len, 1), 4)

    return {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "subdomain_count": subdomain_count,
        "path_depth": path_depth,
        "query_param_count": q_param_count,
        "digit_count": digits,
        "digit_ratio": digit_ratio,
        "letter_count": letters,
        "letter_ratio": letter_ratio,
        "special_char_count": special_chars,
        "special_char_ratio": special_char_ratio,
        "url_entropy": url_entropy,
        "hostname_entropy": hostname_entropy,
        "hostname_hyphens": host_hyphens,
        "hostname_digits": host_digits,
        "is_ip_address": is_ip,
        "is_punycode": is_punycode,
        "suspicious_tld": suspicious_tld,
        "suspicious_keyword_count": keyword_count,
        "percent_encoding_count": pct_count,
        "percent_encoding_depth": depth,
        "userinfo_deception": userinfo_deception,
        "is_https": is_https,
        "non_default_port": non_default_port,
        "suspicious_redirect_param": has_redir_param,
        "char_diversity": char_diversity
    }


def extract_features_v2_df(urls):
    """Extract Schema v2 feature vectors for an iterable of URLs into a DataFrame."""
    records = [extract_features_v2_dict(u) for u in urls]
    return pd.DataFrame(records, columns=SCHEMA_V2_COLUMNS)
