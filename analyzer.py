"""
QRShield Canonical Security Analysis Engine Facade

This module re-exports the modular QRShield security engine from `qrshield/`
for full backward compatibility with existing tests, development scripts,
and web endpoints.
"""

# Standard library and transport imports for testing mock targets
import socket
import ssl
import urllib.parse
import urllib.request
import urllib.error
import datetime
import os
import json
import ipaddress
import math
import re
import joblib
import pandas as pd
from cryptography import x509
from google import genai

# Re-export constants
from qrshield.constants import (
    ML_MODEL_PATH,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    REDIRECT_STATUS_CODES
)

# Re-export lexical analysis
from qrshield.lexical import (
    calculate_entropy,
    decode_url_layers,
    is_ip_address,
    analyze_hostname_structure,
    analyze_punycode,
    analyze_port,
    analyze_path_query_deception,
    analyze_obfuscation_combination
)

# Re-export content types analysis
from qrshield.content_types import (
    detect_qr_content_type,
    analyze_wifi_qr,
    analyze_vcard_qr,
    extract_embedded_urls,
    analyze_message_qr
)

# Re-export network, SSRF and TLS intelligence
from qrshield.network import (
    is_unsafe_network_target,
    resolve_hostname,
    analyze_dns,
    build_dns_features,
    evaluate_dns_risk,
    get_tls_connection,
    get_tls_certificate,
    extract_certificate_metadata,
    analyze_certificate_validity,
    analyze_certificate_identity,
    build_tls_features,
    evaluate_tls_risk
)

# Re-export redirect handling
from qrshield.redirects import (
    NoRedirectHandler,
    make_http_request,
    analyze_redirect_response,
    validate_redirect_target,
    follow_redirect_chain,
    evaluate_redirect_risk,
    analyze_redirect_chain,
    classify_redirect_chain
)

# Re-export reputation intelligence
from qrshield.reputation import (
    query_urlhaus,
    query_google_safe_browsing,
    evaluate_reputation_consensus,
    analyze_reputation,
    evaluate_reputation_risk
)

# Re-export ML analysis
from qrshield.ml import (
    load_ml_model,
    extract_ml_features,
    analyze_ml_prediction,
    evaluate_ml_consensus
)

# Re-export explainability, AI context, guidance, and reports
from qrshield.explainability import (
    evaluate_risk_engine,
    build_finding_explanation,
    build_overall_explanation,
    build_risk_evidence_explanation,
    validate_explainability,
    build_ai_context,
    generate_ai_explanation,
    generate_user_guidance,
    validate_ai_output,
    build_security_report,
    export_security_report
)

# Re-export orchestrator pipeline
from qrshield.orchestrator import analyze_url

__all__ = [
    "ML_MODEL_PATH",
    "SUSPICIOUS_KEYWORDS",
    "SUSPICIOUS_TLDS",
    "REDIRECT_STATUS_CODES",
    "calculate_entropy",
    "decode_url_layers",
    "is_ip_address",
    "analyze_hostname_structure",
    "analyze_punycode",
    "analyze_port",
    "analyze_path_query_deception",
    "analyze_obfuscation_combination",
    "detect_qr_content_type",
    "analyze_wifi_qr",
    "analyze_vcard_qr",
    "extract_embedded_urls",
    "analyze_message_qr",
    "is_unsafe_network_target",
    "resolve_hostname",
    "analyze_dns",
    "build_dns_features",
    "evaluate_dns_risk",
    "get_tls_connection",
    "get_tls_certificate",
    "extract_certificate_metadata",
    "analyze_certificate_validity",
    "analyze_certificate_identity",
    "build_tls_features",
    "evaluate_tls_risk",
    "NoRedirectHandler",
    "make_http_request",
    "analyze_redirect_response",
    "validate_redirect_target",
    "follow_redirect_chain",
    "evaluate_redirect_risk",
    "analyze_redirect_chain",
    "classify_redirect_chain",
    "query_urlhaus",
    "query_google_safe_browsing",
    "evaluate_reputation_consensus",
    "analyze_reputation",
    "evaluate_reputation_risk",
    "load_ml_model",
    "extract_ml_features",
    "analyze_ml_prediction",
    "evaluate_ml_consensus",
    "evaluate_risk_engine",
    "build_finding_explanation",
    "build_overall_explanation",
    "build_risk_evidence_explanation",
    "validate_explainability",
    "build_ai_context",
    "generate_ai_explanation",
    "generate_user_guidance",
    "validate_ai_output",
    "build_security_report",
    "export_security_report",
    "analyze_url"
]
