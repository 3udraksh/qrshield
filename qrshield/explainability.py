"""
QRShield Explainability Engine, Risk Correlation, AI Explanations & Reporting
"""

import os
import json
from google import genai


def evaluate_risk_engine(
    score,
    findings,
    reputation_analysis=None,
    dns_analysis=None,
    tls_features=None,
    redirect_analysis=None
):
    """
    Build a centralized risk profile from QRShield security evidence.
    """
    score = min(max(score, 0), 100)

    high_findings = sum(
        1 for finding in findings
        if isinstance(finding, dict) and finding.get("severity") == "high"
    )
    medium_findings = sum(
        1 for finding in findings
        if isinstance(finding, dict) and finding.get("severity") == "medium"
    )
    low_findings = sum(
        1 for finding in findings
        if isinstance(finding, dict) and finding.get("severity") == "low"
    )

    reputation_confirmed = False
    if reputation_analysis:
        reputation_confirmed = (
            reputation_analysis.get("reputation") == "MALICIOUS"
        )

    available_evidence = 0
    unavailable_evidence = 0

    if reputation_analysis:
        reputation_consensus = reputation_analysis.get("consensus", {})
        if reputation_consensus.get("consensus") in (
            "CONFIRMED_THREAT",
            "NO_THREAT_MATCH"
        ):
            available_evidence += 1
        else:
            unavailable_evidence += 1
    else:
        unavailable_evidence += 1

    if dns_analysis:
        if dns_analysis.get("status") in ("RESOLVED", "IP_LITERAL"):
            available_evidence += 1
        else:
            unavailable_evidence += 1
    else:
        unavailable_evidence += 1

    if tls_features:
        if tls_features.get("certificate_present"):
            available_evidence += 1
        else:
            unavailable_evidence += 1
    else:
        unavailable_evidence += 1

    if redirect_analysis:
        if redirect_analysis.get("completed"):
            available_evidence += 1
        else:
            unavailable_evidence += 1
    else:
        unavailable_evidence += 1

    total_evidence_sources = available_evidence + unavailable_evidence

    if total_evidence_sources == 0:
        confidence = "LOW"
    elif available_evidence == total_evidence_sources:
        confidence = "HIGH"
    elif available_evidence >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    dns_status = dns_analysis.get("status") if dns_analysis else None
    tls_status = tls_features.get("validity_status") if tls_features else None
    tls_identity_match = tls_features.get("identity_matches") if tls_features else None

    redirect_count = 0
    redirect_cross_domain = False
    redirect_https_downgrade = False

    if redirect_analysis:
        redirect_count = redirect_analysis.get("redirect_count", 0)
        redirect_cross_domain = redirect_analysis.get("cross_domain_redirect", False)
        redirect_https_downgrade = redirect_analysis.get("https_downgrade", False)

    correlated_signals = []
    if dns_status == "DNS_FAILURE":
        correlated_signals.append("DNS failure")
    if tls_identity_match is False:
        correlated_signals.append("TLS identity mismatch")
    if tls_status in ("EXPIRED", "NOT_YET_VALID"):
        correlated_signals.append("Invalid TLS validity")
    if redirect_cross_domain:
        correlated_signals.append("Cross-domain redirect")
    if redirect_https_downgrade:
        correlated_signals.append("HTTPS downgrade")
    if redirect_count >= 3:
        correlated_signals.append("Multiple redirects")
    if reputation_confirmed:
        correlated_signals.append("Threat intelligence match")
    if medium_findings >= 2:
        correlated_signals.append("Multiple medium-severity findings")
    if high_findings >= 1:
        correlated_signals.append("High-severity finding")

    correlation_count = len(correlated_signals)
    if correlation_count >= 3:
        correlation_level = "HIGH"
    elif correlation_count == 2:
        correlation_level = "MEDIUM"
    elif correlation_count == 1:
        correlation_level = "LOW"
    else:
        correlation_level = "NONE"

    if score <= 20:
        risk = "LOW RISK"
    elif score <= 50:
        risk = "CAUTION"
    else:
        risk = "HIGH RISK"

    if reputation_confirmed:
        risk_basis = "External threat intelligence"
    elif redirect_https_downgrade:
        risk_basis = "HTTPS downgrade detected"
    elif tls_identity_match is False:
        risk_basis = "TLS certificate identity mismatch"
    elif tls_status in ("EXPIRED", "NOT_YET_VALID"):
        risk_basis = "Invalid TLS certificate validity"
    elif redirect_cross_domain:
        risk_basis = "Cross-domain redirect behavior"
    elif redirect_count >= 3:
        risk_basis = "Multiple redirects"
    elif dns_status == "DNS_FAILURE":
        risk_basis = "DNS resolution failure"
    elif high_findings >= 2:
        risk_basis = "Multiple high-severity indicators"
    elif high_findings == 1:
        risk_basis = "High-severity indicator"
    elif medium_findings >= 2:
        risk_basis = "Multiple medium-severity indicators"
    elif score > 0:
        risk_basis = "Heuristic indicators"
    else:
        risk_basis = "No significant indicators"

    return {
        "score": score,
        "risk": risk,
        "risk_basis": risk_basis,
        "confidence": confidence,
        "evidence": {
            "high": high_findings,
            "medium": medium_findings,
            "low": low_findings
        },
        "reputation_confirmed": reputation_confirmed,
        "signals": {
            "dns_status": dns_status,
            "tls_status": tls_status,
            "tls_identity_match": tls_identity_match,
            "redirect_count": redirect_count,
            "redirect_cross_domain": redirect_cross_domain,
            "redirect_https_downgrade": redirect_https_downgrade
        },
        "correlation": {
            "level": correlation_level,
            "count": correlation_count,
            "signals": correlated_signals
        }
    }


def build_finding_explanation(finding):
    """
    Convert a QRShield finding into a structured explanation.
    """
    if not isinstance(finding, dict):
        return {
            "title": "Security finding",
            "severity": "info",
            "what": str(finding),
            "why_it_matters": "QRShield detected an item that requires attention.",
            "user_action": "Review the destination before interacting with it."
        }

    severity = finding.get("severity", "info")
    message = finding.get("message")
    indicator = finding.get("indicator")
    detail = finding.get("detail")

    title = indicator or "Security finding"
    what = detail or message or "QRShield detected a security-related indicator."

    if severity == "high":
        why_it_matters = (
            "This indicator can represent a significant security risk "
            "and should be investigated before interacting with the destination."
        )
        user_action = (
            "Do not interact with the destination until its legitimacy "
            "has been verified."
        )
    elif severity == "medium":
        why_it_matters = (
            "This indicator does not prove that the destination is malicious, "
            "but it increases the need for caution."
        )
        user_action = "Review the destination carefully before continuing."
    elif severity == "low":
        why_it_matters = (
            "This is a weaker indicator that provides additional context "
            "about the destination."
        )
        user_action = "Consider this indicator together with the other findings."
    else:
        why_it_matters = "QRShield detected an informational security indicator."
        user_action = "Review the finding together with the overall risk assessment."

    return {
        "title": title,
        "severity": severity,
        "what": what,
        "why_it_matters": why_it_matters,
        "user_action": user_action
    }


def build_overall_explanation(risk_analysis):
    """
    Build a human-readable explanation of the overall risk assessment.
    """
    if not isinstance(risk_analysis, dict):
        return "QRShield could not generate an overall risk explanation."

    risk = risk_analysis.get("risk", "UNKNOWN")
    risk_basis = risk_analysis.get("risk_basis", "Unknown")
    correlation = risk_analysis.get("correlation", {})
    correlation_count = correlation.get("count", 0)

    if risk == "LOW RISK" and risk_basis == "No significant indicators":
        return (
            "QRShield did not detect significant security "
            "indicators for this destination."
        )

    basis_text = {
        "External threat intelligence": "external threat intelligence identified the destination",
        "HTTPS downgrade detected": "an HTTPS downgrade was detected",
        "TLS certificate identity mismatch": "a TLS certificate identity mismatch was detected",
        "Invalid TLS certificate validity": "the TLS certificate has an invalid validity state",
        "Cross-domain redirect behavior": "cross-domain redirect behavior was detected",
        "Multiple redirects": "multiple redirects were detected",
        "DNS resolution failure": "DNS resolution failed for the hostname",
        "Multiple high-severity indicators": "multiple high-severity indicators were detected",
        "High-severity indicator": "a high-severity indicator was detected",
        "Multiple medium-severity indicators": "multiple medium-severity indicators were detected",
        "Heuristic indicators": "heuristic security indicators were detected"
    }

    explanation_basis = basis_text.get(risk_basis, "security indicators were detected")
    explanation = f"QRShield classified this destination as {risk} because {explanation_basis}."

    if correlation_count >= 2:
        explanation += " Multiple security indicators reinforce this assessment."

    return explanation


def build_risk_evidence_explanation(risk_analysis):
    """
    Explain the evidence supporting the QRShield risk assessment.
    """
    if not isinstance(risk_analysis, dict):
        return "Risk evidence is unavailable."

    risk = risk_analysis.get("risk", "UNKNOWN")
    risk_basis = risk_analysis.get("risk_basis", "Unknown")
    evidence = risk_analysis.get("evidence", {})

    high_count = evidence.get("high", 0)
    medium_count = evidence.get("medium", 0)
    low_count = evidence.get("low", 0)

    correlation = risk_analysis.get("correlation", {})
    correlation_count = correlation.get("count", 0)
    correlation_level = correlation.get("level", "NONE")

    finding_parts = []
    if high_count:
        finding_parts.append(f"{high_count} high-severity finding" + ("s" if high_count != 1 else ""))
    if medium_count:
        finding_parts.append(f"{medium_count} medium-severity finding" + ("s" if medium_count != 1 else ""))
    if low_count:
        finding_parts.append(f"{low_count} low-severity finding" + ("s" if low_count != 1 else ""))

    evidence_text = ", ".join(finding_parts) if finding_parts else "no individual security findings"

    if correlation_count > 0:
        correlation_text = (
            f"{correlation_count} correlated security signal"
            + ("s" if correlation_count != 1 else "")
            + f" classified at {correlation_level} correlation"
        )
    else:
        correlation_text = "no correlated security signals"

    return (
        f"Risk level: {risk}. "
        f"Primary basis: {risk_basis}. "
        f"Evidence: {evidence_text}. "
        f"Correlation: {correlation_text}."
    )


def validate_explainability(result):
    """
    Validate that QRShield produced a complete explainability result.
    """
    if not isinstance(result, dict):
        return {
            "valid": False,
            "missing": ["result"]
        }

    required_fields = [
        "score",
        "risk",
        "findings",
        "explanations",
        "overall_explanation",
        "risk_evidence_explanation",
        "risk_analysis"
    ]

    missing = [field for field in required_fields if field not in result]
    if missing:
        return {
            "valid": False,
            "missing": missing
        }

    risk_analysis = result.get("risk_analysis")
    if not isinstance(risk_analysis, dict):
        return {
            "valid": False,
            "missing": ["risk_analysis"]
        }

    required_risk_fields = [
        "score",
        "risk",
        "risk_basis",
        "confidence",
        "evidence",
        "correlation"
    ]

    missing_risk_fields = [field for field in required_risk_fields if field not in risk_analysis]
    if missing_risk_fields:
        return {
            "valid": False,
            "missing": missing_risk_fields
        }

    if result["score"] != risk_analysis["score"]:
        return {
            "valid": False,
            "missing": ["score_consistency"]
        }

    if result["risk"] != risk_analysis["risk"]:
        return {
            "valid": False,
            "missing": ["risk_consistency"]
        }

    return {
        "valid": True,
        "missing": []
    }


def build_ai_context(result):
    """
    Build structured context for AI-assisted explanation.
    """
    if not isinstance(result, dict):
        return {
            "status": "INVALID",
            "context": {}
        }

    risk_analysis = result.get("risk_analysis", {})
    features = result.get("features", [])
    ml_analysis = result.get("ml_analysis", {})
    ml_consensus = result.get("ml_consensus", {})

    return {
        "status": "READY",
        "content": {
            "decoded_content": result.get("url"),
            "content_type": result.get("content_type"),
            "embedded_urls": result.get("embedded_urls", [])
        },
        "assessment": {
            "score": result.get("score"),
            "risk": result.get("risk"),
            "risk_basis": risk_analysis.get("risk_basis"),
            "confidence": risk_analysis.get("confidence")
        },
        "security_evidence": {
            "findings": result.get("findings", []),
            "explanations": result.get("explanations", []),
            "risk_evidence": result.get("risk_evidence_explanation"),
            "correlation": risk_analysis.get("correlation", {})
        },
        "technical_analysis": features,
        "machine_learning": {
            "prediction": ml_analysis.get("prediction"),
            "label": ml_analysis.get("label"),
            "confidence": ml_analysis.get("confidence"),
            "consensus": ml_consensus.get("agreement"),
            "message": ml_consensus.get("message")
        }
    }


def generate_ai_explanation(ai_context):
    """
    Generate an AI explanation using Gemini API when configured.
    """
    if not isinstance(ai_context, dict):
        return {
            "status": "INVALID",
            "explanation": "AI context is unavailable."
        }

    if ai_context.get("status") != "READY":
        return {
            "status": "UNAVAILABLE",
            "explanation": "AI explanation cannot be generated."
        }

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {
            "status": "UNAVAILABLE",
            "explanation": "AI explanation is currently unavailable."
        }

    try:
        client = genai.Client(api_key=api_key)
        prompt = (
            "You are the security explanation layer for QRShield, "
            "a defensive QR security analysis tool.\n\n"
            "Explain the QRShield analysis using ONLY the evidence "
            "provided below.\n"
            "Do not invent facts.\n"
            "Do not change or override the QRShield risk score.\n"
            "Clearly distinguish detected evidence from inference.\n"
            "Give a concise explanation understandable to a user.\n\n"
            "QRShield evidence:\n"
            + json.dumps(
                ai_context,
                indent=2,
                ensure_ascii=False
            )
        )

        response = client.models.generate_content(
            model="gemini-3.1-flash-lite",
            contents=prompt
        )

        return {
            "status": "AVAILABLE",
            "explanation": response.text
        }

    except Exception:
        return {
            "status": "UNAVAILABLE",
            "explanation": "AI explanation generation failed."
        }


def generate_user_guidance(result):
    """
    Generate actionable user guidance based on risk level.
    """
    if not isinstance(result, dict):
        return {
            "status": "INVALID",
            "guidance": "Unable to generate security guidance."
        }

    risk = result.get("risk", "UNKNOWN")
    score = result.get("score", 0)
    findings = result.get("findings", [])

    if risk == "HIGH RISK":
        guidance = (
            "Do not open or interact with this QR destination. "
            "Review the detected security findings and verify the "
            "destination through a trusted source before proceeding."
        )
    elif risk == "CAUTION":
        guidance = (
            "Proceed carefully. Review the detected security findings "
            "and verify the destination independently before entering "
            "credentials or sensitive information."
        )
    else:
        guidance = (
            "No significant security indicators were detected by "
            "QRShield. Continue to verify that the QR code comes from "
            "a trusted source before interacting with it."
        )

    return {
        "status": "AVAILABLE",
        "risk": risk,
        "score": score,
        "finding_count": len(findings),
        "guidance": guidance
    }


def validate_ai_output(ai_explanation, result):
    """
    Validate that the AI explanation is non-empty and structurally sound.
    """
    if not isinstance(ai_explanation, dict):
        return {
            "status": "INVALID",
            "safe": False,
            "reason": "AI explanation has an invalid structure."
        }

    if not isinstance(result, dict):
        return {
            "status": "INVALID",
            "safe": False,
            "reason": "QRShield analysis result is invalid."
        }

    if ai_explanation.get("status") != "AVAILABLE":
        return {
            "status": "NOT_AVAILABLE",
            "safe": True,
            "reason": "AI explanation is unavailable."
        }

    explanation = ai_explanation.get("explanation")
    if not isinstance(explanation, str) or not explanation.strip():
        return {
            "status": "INVALID",
            "safe": False,
            "reason": "AI returned an empty explanation."
        }

    return {
        "status": "VALID",
        "safe": True,
        "reason": "AI explanation passed structural validation."
    }


def build_security_report(result):
    """
    Build a structured security report from a QRShield analysis result.
    """
    if not isinstance(result, dict):
        return {
            "report_type": "QRShield Security Report",
            "status": "INVALID"
        }

    risk_analysis = result.get("risk_analysis", {})
    features = result.get("features", {})

    return {
        "report_type": "QRShield Security Report",
        "content": {
            "decoded_content": result.get("url"),
            "content_type": result.get("content_type")
        },
        "assessment": {
            "score": result.get("score"),
            "risk": result.get("risk"),
            "risk_basis": risk_analysis.get("risk_basis"),
            "confidence": risk_analysis.get("confidence")
        },
        "evidence": {
            "findings": result.get("findings", []),
            "explanations": result.get("explanations", []),
            "risk_evidence": result.get("risk_evidence_explanation"),
            "correlation": risk_analysis.get("correlation", {})
        },
        "machine_learning": result.get("ml_analysis"),
        "machine_learning_consensus": result.get("ml_consensus"),
        "technical_analysis": features,
        "summary": result.get("overall_explanation")
    }


def export_security_report(result, filepath):
    """
    Export a QRShield security report as JSON.
    """
    if not isinstance(result, dict):
        raise ValueError("Invalid QRShield analysis result.")

    report = result.get("security_report")
    if not isinstance(report, dict):
        raise ValueError("Security report is unavailable.")

    with open(filepath, "w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    return filepath
