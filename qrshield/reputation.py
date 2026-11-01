"""
QRShield Reputation Intelligence & Threat Provider Integrations
"""

import os
import json
import socket
import urllib.parse
import urllib.request
import urllib.error


def query_urlhaus(url, timeout=5):
    """
    Query URLhaus for intelligence about a URL.
    """
    auth_key = os.getenv("URLHAUS_AUTH_KEY")
    if not auth_key:
        return {
            "source": "URLhaus",
            "status": "NOT_CONFIGURED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "URLhaus API key not configured"
        }

    if not url:
        return {
            "source": "URLhaus",
            "status": "INVALID_INPUT",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "No URL provided"
        }

    try:
        data = urllib.parse.urlencode({"url": url}).encode()
        request = urllib.request.Request(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data=data,
            headers={
                "Auth-Key": auth_key,
                "User-Agent": "QRShield/1.0"
            },
            method="POST"
        )

        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_data = json.loads(response.read().decode("utf-8"))

        query_status = response_data.get("query_status")

        if query_status == "ok":
            return {
                "source": "URLhaus",
                "status": "FOUND",
                "malicious": True,
                "url": response_data.get("url", url),
                "threat": response_data.get("threat"),
                "error": None
            }

        if query_status == "no_results":
            return {
                "source": "URLhaus",
                "status": "NOT_FOUND",
                "malicious": False,
                "url": url,
                "threat": None,
                "error": None
            }

        return {
            "source": "URLhaus",
            "status": "UNKNOWN",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": query_status
        }

    except urllib.error.HTTPError as error:
        return {
            "source": "URLhaus",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": f"HTTP {error.code}"
        }

    except urllib.error.URLError as error:
        return {
            "source": "URLhaus",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": str(error.reason)
        }

    except (socket.timeout, TimeoutError):
        return {
            "source": "URLhaus",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "Request timed out"
        }

    except (OSError, json.JSONDecodeError) as error:
        return {
            "source": "URLhaus",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": str(error)
        }


def query_google_safe_browsing(url, timeout=5):
    """
    Query Google Safe Browsing for URL reputation.
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not api_key:
        return {
            "source": "Google Safe Browsing",
            "status": "NOT_CONFIGURED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "Google Safe Browsing API key not configured"
        }

    if not url:
        return {
            "source": "Google Safe Browsing",
            "status": "INVALID_INPUT",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "No URL provided"
        }

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/"
        f"threatMatches:find?key={api_key}"
    )

    payload = {
        "client": {
            "clientId": "qrshield",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "QRShield/1.0"
            },
            method="POST"
        )

        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_data = json.loads(response.read().decode("utf-8"))

        matches = response_data.get("matches", [])
        if matches:
            threats = [
                match.get("threatType")
                for match in matches
                if match.get("threatType")
            ]
            return {
                "source": "Google Safe Browsing",
                "status": "FOUND",
                "malicious": True,
                "url": url,
                "threat": threats,
                "error": None
            }

        return {
            "source": "Google Safe Browsing",
            "status": "NOT_FOUND",
            "malicious": False,
            "url": url,
            "threat": None,
            "error": None
        }

    except urllib.error.HTTPError as error:
        return {
            "source": "Google Safe Browsing",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": f"HTTP {error.code}"
        }

    except urllib.error.URLError as error:
        return {
            "source": "Google Safe Browsing",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": str(error.reason)
        }

    except (socket.timeout, TimeoutError):
        return {
            "source": "Google Safe Browsing",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": "Request timed out"
        }

    except (OSError, json.JSONDecodeError) as error:
        return {
            "source": "Google Safe Browsing",
            "status": "REQUEST_FAILED",
            "malicious": None,
            "url": url,
            "threat": None,
            "error": str(error)
        }


def evaluate_reputation_consensus(sources):
    """
    Evaluate agreement between reputation providers.
    """
    if not sources:
        return {
            "consensus": "NO_DATA",
            "confidence": "LOW",
            "threat_sources": 0,
            "checked_sources": 0
        }

    checked_sources = len(sources)
    threat_sources = sum(1 for source in sources if source.get("status") == "FOUND")
    available_sources = sum(1 for source in sources if source.get("status") in ("FOUND", "NOT_FOUND"))

    if threat_sources == checked_sources:
        return {
            "consensus": "CONFIRMED_THREAT",
            "confidence": "HIGH",
            "threat_sources": threat_sources,
            "checked_sources": checked_sources
        }

    if threat_sources > 0 and available_sources > threat_sources:
        return {
            "consensus": "PARTIAL_THREAT",
            "confidence": "MEDIUM",
            "threat_sources": threat_sources,
            "checked_sources": checked_sources
        }

    if available_sources == checked_sources:
        return {
            "consensus": "NO_THREAT_MATCH",
            "confidence": "LOW",
            "threat_sources": 0,
            "checked_sources": checked_sources
        }

    return {
        "consensus": "INSUFFICIENT_DATA",
        "confidence": "LOW",
        "threat_sources": threat_sources,
        "checked_sources": checked_sources
    }


def analyze_reputation(url, hostname=None):
    """
    Analyze URL reputation using multiple threat-intelligence providers.
    """
    if not url:
        return {
            "status": "NO_URL",
            "reputation": "UNKNOWN",
            "sources": [],
            "findings": []
        }

    urlhaus_result = query_urlhaus(url)
    google_result = query_google_safe_browsing(url)
    sources = [urlhaus_result, google_result]

    consensus = evaluate_reputation_consensus(sources)
    findings = []
    threat_found = any(source.get("status") == "FOUND" for source in sources)

    if threat_found:
        reputation = "MALICIOUS"
        status = "THREAT_FOUND"
        for source in sources:
            if source.get("status") == "FOUND":
                findings.append({
                    "severity": "high",
                    "source": source["source"],
                    "message": "URL was found in this threat-intelligence database."
                })
    elif all(source.get("status") == "NOT_FOUND" for source in sources):
        reputation = "UNKNOWN"
        status = "NO_MATCH"
    else:
        reputation = "UNKNOWN"
        status = "INTELLIGENCE_UNAVAILABLE"

    return {
        "status": status,
        "reputation": reputation,
        "sources": sources,
        "findings": findings,
        "consensus": consensus
    }


def evaluate_reputation_risk(reputation_analysis):
    """
    Evaluate risk contribution from reputation intelligence.
    """
    if not reputation_analysis:
        return {
            "score": 0,
            "findings": []
        }

    score = 0
    findings = []

    if reputation_analysis.get("reputation") == "MALICIOUS":
        score += 30
        findings.append({
            "severity": "high",
            "source": "URLhaus",
            "message": "URL was identified as malicious by external threat intelligence."
        })

    return {
        "score": score,
        "findings": findings
    }
