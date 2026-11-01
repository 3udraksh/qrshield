"""
QRShield Analysis Orchestrator Pipeline
"""

import re
from urllib.parse import urlparse, parse_qs
from qrshield.compat import dispatch
from qrshield.constants import SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS
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
from qrshield.content_types import (
    detect_qr_content_type,
    analyze_wifi_qr,
    analyze_vcard_qr,
    extract_embedded_urls,
    analyze_message_qr
)
from qrshield.network import (
    analyze_dns,
    build_dns_features,
    evaluate_dns_risk,
    get_tls_certificate,
    extract_certificate_metadata,
    analyze_certificate_validity,
    analyze_certificate_identity,
    build_tls_features,
    evaluate_tls_risk
)
from qrshield.redirects import (
    follow_redirect_chain,
    analyze_redirect_chain,
    classify_redirect_chain,
    evaluate_redirect_risk
)
from qrshield.reputation import (
    analyze_reputation,
    evaluate_reputation_risk
)
from qrshield.ml import (
    analyze_ml_prediction,
    evaluate_ml_consensus
)
from qrshield.explainability import (
    evaluate_risk_engine,
    build_finding_explanation,
    build_overall_explanation,
    build_risk_evidence_explanation,
    build_ai_context,
    generate_ai_explanation,
    validate_ai_output,
    generate_user_guidance,
    build_security_report,
    export_security_report
)


def analyze_url(url):
    """
    Analyze a URL or non-URL QR payload using explainable heuristic indicators,
    network security verification, machine-learning consensus, and AI explanations.
    """
    score = 0
    findings = []
    features = []

    original_url = url.strip() if isinstance(url, str) else ""
    content_type = detect_qr_content_type(url)
    embedded_urls = extract_embedded_urls(url)

    wifi_analysis = None
    vcard_analysis = None
    message_analysis = None

    if content_type == "WIFI":
        wifi_analysis = analyze_wifi_qr(url)
    if content_type == "VCARD":
        vcard_analysis = analyze_vcard_qr(url)
    if content_type in ("EMAIL", "SMS"):
        message_analysis = analyze_message_qr(url, content_type)

    if content_type != "URL":
        return {
            "url": url,
            "content_type": content_type,
            "wifi_analysis": wifi_analysis,
            "vcard_analysis": vcard_analysis,
            "message_analysis": message_analysis,
            "embedded_urls": embedded_urls,
            "score": 0,
            "risk": "LOW RISK",
            "risk_analysis": {
                "score": 0,
                "risk": "LOW RISK",
                "risk_basis": "Non-URL QR content",
                "confidence": "LOW",
                "evidence": {
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "reputation_confirmed": False,
                "signals": {},
                "correlation": {
                    "level": "NONE",
                    "count": 0,
                    "signals": []
                }
            },
            "findings": [],
            "explanations": [],
            "overall_explanation": (
                f"QRShield detected {content_type} content. "
                "URL security analysis was not applied."
            ),
            "risk_evidence_explanation": (
                "No URL security indicators were evaluated because "
                "the QR content is not a URL."
            ),
            "features": {}
        }

    if not original_url:
        return {
            "url": "",
            "score": 0,
            "risk": "INVALID",
            "findings": ["No URL was provided."],
            "features": []
        }

    # Normalize URL scheme
    if not re.match(r"^https?://", original_url, re.IGNORECASE):
        normalized_url = "http://" + original_url
    else:
        normalized_url = original_url

    # Multi-layer URL decoding
    decode_layers = decode_url_layers(normalized_url)
    decoding_count = len(decode_layers) - 1

    features.append({
        "name": "Decoding Layers",
        "value": decoding_count
    })

    features.append({
        "name": "Decoded URL",
        "value": decode_layers[-1]
    })

    if decoding_count >= 1:
        score += 5
        findings.append({
            "severity": "medium",
            "indicator": "URL encoding detected",
            "detail": (
                f"The URL changed after percent-decoding "
                f"({decoding_count} decoding layer(s))."
            )
        })

    if decoding_count >= 2:
        score += 15
        findings.append({
            "severity": "high",
            "indicator": "Multiple URL-decoding layers detected",
            "detail": (
                "The URL required multiple percent-decoding "
                "operations to reach its final representation."
            )
        })

    parsed = urlparse(normalized_url)
    hostname = parsed.hostname

    # Port analysis
    port_analysis = analyze_port(parsed)
    if not port_analysis["valid"]:
        score += 15
        features.append({
            "name": "Port",
            "value": "Invalid"
        })
        findings.append({
            "severity": "medium",
            "message": "URL contains an invalid port specification"
        })
    elif port_analysis["explicit"]:
        features.append({
            "name": "Explicit Port",
            "value": port_analysis["port"]
        })
        if not port_analysis["default"]:
            score += 5
            findings.append({
                "severity": "low",
                "message": (
                    f"URL uses non-default port "
                    f"{port_analysis['port']} for {parsed.scheme.upper()}"
                )
            })

    # Punycode / IDN analysis
    punycode_analysis = analyze_punycode(hostname)
    if punycode_analysis["detected"]:
        score += 10
        features.append({
            "name": "Punycode / IDN",
            "value": punycode_analysis["punycode_labels"]
        })
        findings.append({
            "severity": "medium",
            "message": (
                "Hostname contains Punycode / Internationalized "
                "Domain Name (IDN) labels"
            )
        })

    # Hostname structure analysis
    hostname_analysis = analyze_hostname_structure(hostname)
    features.append({
        "name": "Hostname Labels",
        "value": hostname_analysis["labels"]
    })

    if hostname_analysis["suspicious_subdomain"]:
        score += 10
        findings.append({
            "severity": "medium",
            "message": (
                "Security-sensitive keywords appear in the hostname's "
                "subdomain structure"
            )
        })

    if not hostname:
        return {
            "url": normalized_url,
            "score": 100,
            "risk": "INVALID",
            "findings": [
                "The URL could not be parsed correctly."
            ],
            "features": []
        }

    # Path and query deception analysis
    path_query_analysis = analyze_path_query_deception(parsed)
    if path_query_analysis["suspicious_path_keywords"]:
        features.append({
            "name": "Suspicious Path Keywords",
            "value": path_query_analysis["suspicious_path_keywords"]
        })
        findings.append({
            "severity": "low",
            "message": (
                "URL path contains security-sensitive keywords: "
                + ", ".join(path_query_analysis["suspicious_path_keywords"])
            )
        })

    if path_query_analysis["redirect_parameters"]:
        score += 10
        features.append({
            "name": "Redirect Parameters",
            "value": path_query_analysis["redirect_parameters"]
        })
        findings.append({
            "severity": "medium",
            "message": (
                "URL query contains redirect-style parameters: "
                + ", ".join(path_query_analysis["redirect_parameters"])
            )
        })

    hostname = hostname.lower()

    # DNS Intelligence
    dns_analysis = analyze_dns(hostname)
    dns_features = build_dns_features(dns_analysis)
    dns_risk = evaluate_dns_risk(dns_features)
    score += dns_risk["score"]
    for finding in dns_risk["findings"]:
        findings.append(finding)

    # TLS Intelligence
    tls_features = None
    if parsed.scheme == "https":
        tls_port = port_analysis["port"] or 443
        tls_result = dispatch("get_tls_certificate", get_tls_certificate)(hostname, tls_port)

        if tls_result["retrieved"]:
            certificate_metadata = dispatch("extract_certificate_metadata", extract_certificate_metadata)(tls_result["certificate"])
            validity_analysis = dispatch("analyze_certificate_validity", analyze_certificate_validity)(
                certificate_metadata["valid_from"],
                certificate_metadata["valid_until"]
            )
            identity_analysis = dispatch("analyze_certificate_identity", analyze_certificate_identity)(
                hostname,
                certificate_metadata
            )
        else:
            certificate_metadata = dispatch("extract_certificate_metadata", extract_certificate_metadata)(None)
            validity_analysis = dispatch("analyze_certificate_validity", analyze_certificate_validity)(None, None)
            identity_analysis = dispatch("analyze_certificate_identity", analyze_certificate_identity)(hostname, certificate_metadata)

        tls_features = build_tls_features(
            certificate_metadata,
            validity_analysis,
            identity_analysis
        )
        tls_risk = evaluate_tls_risk(tls_features)
        score += tls_risk["score"]
        for finding in tls_risk["findings"]:
            findings.append(finding)

        if tls_features is not None:
            features.append({
                "name": "TLS Intelligence",
                "value": tls_features
            })

    # Redirect Intelligence
    redirect_chain = dispatch("follow_redirect_chain", follow_redirect_chain)(
        normalized_url,
        max_redirects=5,
        timeout=5
    )
    redirect_analysis = analyze_redirect_chain(redirect_chain)
    redirect_classification = classify_redirect_chain(redirect_analysis)
    redirect_risk = evaluate_redirect_risk(redirect_analysis)

    score += redirect_risk["score"]
    findings.extend(redirect_risk["findings"])

    features.append({
        "name": "Redirect Intelligence",
        "redirect_count": redirect_analysis["redirect_count"],
        "classification": redirect_classification,
        "domains": redirect_analysis["domains"],
        "cross_domain_redirect": redirect_analysis["cross_domain_redirect"],
        "https_downgrade": redirect_analysis["https_downgrade"],
        "final_domain": redirect_analysis["final_domain"],
        "completed": redirect_chain.get("completed", False),
        "loop_detected": redirect_chain.get("loop_detected", False),
        "max_redirects_reached": redirect_chain.get("max_redirects_reached", False),
        "error": redirect_chain.get("error")
    })

    # Reputation Intelligence
    reputation_analysis = analyze_reputation(normalized_url, hostname)
    reputation_risk = evaluate_reputation_risk(reputation_analysis)
    score += reputation_risk["score"]
    findings.extend(reputation_risk["findings"])

    features.append({
        "name": "Reputation Intelligence",
        "status": reputation_analysis["status"],
        "reputation": reputation_analysis["reputation"],
        "consensus": reputation_analysis["consensus"],
        "sources": reputation_analysis["sources"],
        "findings": reputation_analysis["findings"]
    })

    # Basic URL Features
    if port_analysis["explicit"] and port_analysis["valid"]:
        port_value = port_analysis["port"]
    elif not port_analysis["valid"]:
        port_value = "Invalid"
    else:
        port_value = "Default"

    features.append({
        "name": "Port",
        "value": port_value
    })
    features.append({
        "name": "Scheme",
        "value": parsed.scheme.upper()
    })
    features.append({
        "name": "Hostname",
        "value": hostname
    })
    features.append({
        "name": "DNS Intelligence",
        "value": dns_features
    })

    # HTTPS check
    if parsed.scheme.lower() != "https":
        score += 15
        findings.append({
            "severity": "medium",
            "indicator": "HTTPS not detected",
            "detail": "The destination does not use HTTPS."
        })
    else:
        features.append({
            "name": "HTTPS",
            "value": "Enabled"
        })

    # IP Address check
    if is_ip_address(hostname):
        score += 25
        findings.append({
            "severity": "high",
            "indicator": "IP address used as destination",
            "detail": "The URL uses an IP address instead of a domain name."
        })
        features.append({
            "name": "IP Address",
            "value": "Yes"
        })
    else:
        features.append({
            "name": "IP Address",
            "value": "No"
        })

    # URL Length
    url_length = len(normalized_url)
    features.append({
        "name": "URL Length",
        "value": url_length
    })
    if url_length > 100:
        score += 10
        findings.append({
            "severity": "low",
            "indicator": "Unusually long URL",
            "detail": f"The URL contains {url_length} characters."
        })

    # Hostname Length
    hostname_length = len(hostname)
    features.append({
        "name": "Hostname Length",
        "value": hostname_length
    })
    if hostname_length > 50:
        score += 10
        findings.append({
            "severity": "medium",
            "indicator": "Long hostname",
            "detail": "The hostname is unusually long."
        })

    # Subdomains count
    hostname_parts = hostname.split(".")
    subdomain_count = max(0, len(hostname_parts) - 2)
    features.append({
        "name": "Subdomain Count",
        "value": subdomain_count
    })
    if subdomain_count >= 3:
        score += 10
        findings.append({
            "severity": "medium",
            "indicator": "Multiple subdomains",
            "detail": f"The hostname contains approximately {subdomain_count} subdomain levels."
        })

    # Path Depth
    path_parts = [part for part in parsed.path.split("/") if part]
    path_depth = len(path_parts)
    features.append({
        "name": "Path Depth",
        "value": path_depth
    })
    if path_depth >= 5:
        score += 5
        findings.append({
            "severity": "low",
            "indicator": "Deep URL path",
            "detail": "The destination contains many path levels."
        })

    # Query Parameters
    query_parameters = parse_qs(parsed.query)
    parameter_count = len(query_parameters)
    features.append({
        "name": "Query Parameters",
        "value": parameter_count
    })
    if parameter_count >= 5:
        score += 5
        findings.append({
            "severity": "low",
            "indicator": "Many query parameters",
            "detail": f"The URL contains {parameter_count} query parameters."
        })

    # Fragment
    if parsed.fragment:
        features.append({
            "name": "Fragment",
            "value": "Present"
        })
    else:
        features.append({
            "name": "Fragment",
            "value": "None"
        })

    # Userinfo / @ symbol
    if "@" in normalized_url:
        try:
            parsed = urlparse(normalized_url)
            username = parsed.username
            hostname = parsed.hostname

            if username:
                score += 20
                features.append({
                    "name": "URL Userinfo",
                    "value": username
                })
                features.append({
                    "name": "Actual Hostname",
                    "value": hostname
                })
                findings.append({
                    "severity": "high",
                    "message": (
                        f"URL contains userinfo before @. "
                        f"Actual destination hostname is {hostname}"
                    )
                })
            else:
                score += 10
                features.append({
                    "name": "At Symbol",
                    "value": True
                })
                findings.append({
                    "severity": "medium",
                    "message": "URL contains @ symbol"
                })
        except ValueError:
            score += 20
            findings.append({
                "severity": "high",
                "message": "Malformed URL contains @ symbol"
            })

    # Percent encoding count
    encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", normalized_url)
    encoded_count = len(encoded_matches)
    features.append({
        "name": "Percent Encoded Characters",
        "value": encoded_count
    })
    if encoded_count >= 5:
        score += 10
        findings.append({
            "severity": "medium",
            "indicator": "Heavy URL encoding",
            "detail": f"The URL contains {encoded_count} percent-encoded sequences."
        })

    # Encoded Content
    if decoding_count > 0:
        features.append({
            "name": "Encoded Content",
            "value": "Present"
        })
    else:
        features.append({
            "name": "Encoded Content",
            "value": "None detected"
        })

    # Suspicious keywords
    lower_url = normalized_url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]
    if found_keywords:
        keyword_score = min(25, len(found_keywords) * 5)
        score += keyword_score
        findings.append({
            "severity": "medium",
            "indicator": "Security-sensitive keywords",
            "detail": ", ".join(found_keywords)
        })

    features.append({
        "name": "Suspicious Keywords",
        "value": ", ".join(found_keywords) if found_keywords else "None"
    })

    # Hyphens
    hyphen_count = hostname.count("-")
    features.append({
        "name": "Hostname Hyphens",
        "value": hyphen_count
    })
    if hyphen_count >= 3:
        score += 10
        findings.append({
            "severity": "low",
            "indicator": "Hyphen-heavy hostname",
            "detail": f"The hostname contains {hyphen_count} hyphens."
        })

    # Digits
    digit_count = sum(char.isdigit() for char in hostname)
    features.append({
        "name": "Hostname Digits",
        "value": digit_count
    })
    if digit_count >= 5 and not is_ip_address(hostname):
        score += 5
        findings.append({
            "severity": "low",
            "indicator": "High digit count in hostname",
            "detail": f"The hostname contains {digit_count} digits."
        })

    # Suspicious TLD
    matched_tld = None
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            matched_tld = tld
            break

    if matched_tld:
        score += 15
        findings.append({
            "severity": "medium",
            "indicator": "Suspicious-looking TLD",
            "detail": f"The hostname ends with {matched_tld}."
        })

    features.append({
        "name": "TLD Indicator",
        "value": matched_tld if matched_tld else "No match"
    })

    # Hostname entropy
    entropy = calculate_entropy(hostname)
    features.append({
        "name": "Hostname Entropy",
        "value": round(entropy, 2)
    })
    if entropy > 4.2 and hostname_length > 20:
        score += 5
        findings.append({
            "severity": "low",
            "indicator": "High hostname complexity",
            "detail": "The hostname contains a relatively high degree of character variation."
        })

    # Obfuscation Combination
    obfuscation_analysis = analyze_obfuscation_combination(
        decoding_count=decoding_count,
        userinfo_detected=("@" in normalized_url and bool(parsed.username)),
        suspicious_subdomain=hostname_analysis["suspicious_subdomain"],
        punycode_detected=punycode_analysis["detected"],
        non_default_port=(
            port_analysis["explicit"]
            and port_analysis["valid"]
            and not port_analysis["default"]
        ),
        suspicious_path=bool(path_query_analysis["suspicious_path_keywords"]),
        redirect_parameters=bool(path_query_analysis["redirect_parameters"])
    )
    features.append({
        "name": "Obfuscation Combination",
        "value": {
            "count": obfuscation_analysis["count"],
            "indicators": obfuscation_analysis["indicators"],
            "level": obfuscation_analysis["level"]
        }
    })

    # Machine Learning Analysis & Consensus
    ml_analysis = analyze_ml_prediction({"features": features})
    ml_consensus = evaluate_ml_consensus(score, ml_analysis)

    if obfuscation_analysis["count"] >= 4:
        score += 10
        findings.append({
            "severity": "high",
            "message": "Multiple URL obfuscation and deception techniques occur together"
        })
    elif obfuscation_analysis["count"] >= 2:
        score += 5
        findings.append({
            "severity": "medium",
            "message": "Multiple URL obfuscation and deception indicators occur together"
        })

    # Risk Engine Evaluation
    risk_analysis = evaluate_risk_engine(
        score=score,
        findings=findings,
        reputation_analysis=reputation_analysis,
        dns_analysis=dns_analysis,
        tls_features=tls_features,
        redirect_analysis=redirect_analysis
    )

    overall_explanation = build_overall_explanation(risk_analysis)
    risk_evidence_explanation = build_risk_evidence_explanation(risk_analysis)
    explanations = [build_finding_explanation(f) for f in findings]

    score = min(risk_analysis["score"], 100)
    risk = risk_analysis["risk"]

    if score <= 20:
        risk = "LOW RISK"
    elif score <= 50:
        risk = "CAUTION"
    else:
        risk = "HIGH RISK"

    if not findings:
        findings.append({
            "severity": "info",
            "indicator": "No obvious indicators detected",
            "detail": "The current heuristic engine did not identify suspicious characteristics."
        })

    result = {
        "url": normalized_url,
        "content_type": content_type,
        "wifi_analysis": wifi_analysis,
        "vcard_analysis": vcard_analysis,
        "message_analysis": message_analysis,
        "embedded_urls": embedded_urls,
        "score": score,
        "risk": risk,
        "risk_analysis": risk_analysis,
        "explanations": explanations,
        "overall_explanation": overall_explanation,
        "risk_evidence_explanation": risk_evidence_explanation,
        "findings": findings,
        "features": features,
        "ml_analysis": ml_analysis,
        "ml_consensus": ml_consensus,
        "security_report": build_security_report({
            "url": url,
            "content_type": content_type,
            "score": score,
            "risk": risk,
            "risk_analysis": risk_analysis,
            "findings": findings,
            "explanations": explanations,
            "overall_explanation": overall_explanation,
            "risk_evidence_explanation": risk_evidence_explanation,
            "features": features
        })
    }

    result["ai_context"] = build_ai_context(result)
    result["ai_explanation"] = dispatch("generate_ai_explanation", generate_ai_explanation)(result["ai_context"])
    result["ai_validation"] = validate_ai_output(result["ai_explanation"], result)
    result["user_guidance"] = generate_user_guidance(result)

    return result
