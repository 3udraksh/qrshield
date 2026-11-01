"""
QRShield Redirect Handling, Loop Detection, and Risk Classification
"""

import socket
import urllib.parse
import urllib.request
import urllib.error
from qrshield.constants import REDIRECT_STATUS_CODES
from qrshield.network import is_unsafe_network_target
from qrshield.compat import dispatch


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    HTTP handler preventing automatic redirect following to allow hop-by-hop inspection.
    """
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_http_request(url, timeout=5):
    """
    Make an HTTP request to a URL without automatically following redirects.
    """
    if not url:
        return {
            "success": False,
            "url": url,
            "status_code": None,
            "location": None,
            "headers": {},
            "error": "No URL provided"
        }

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname

    network_check = is_unsafe_network_target(hostname)
    if network_check["unsafe"]:
        return {
            "success": False,
            "url": url,
            "status_code": None,
            "location": None,
            "headers": {},
            "error": "Blocked network target: " + network_check["reason"]
        }

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "QRShield/1.0"
        }
    )

    opener = urllib.request.build_opener(
        NoRedirectHandler()
    )

    try:
        response = opener.open(
            request,
            timeout=timeout
        )

        return {
            "success": True,
            "url": response.geturl(),
            "status_code": response.status,
            "location": response.headers.get("Location"),
            "headers": dict(response.headers),
            "error": None
        }

    except urllib.error.HTTPError as error:
        return {
            "success": True,
            "url": error.geturl(),
            "status_code": error.code,
            "location": error.headers.get("Location"),
            "headers": dict(error.headers),
            "error": None
        }

    except (urllib.error.URLError, socket.timeout, TimeoutError) as error:
        return {
            "success": False,
            "url": url,
            "status_code": None,
            "location": None,
            "headers": {},
            "error": str(error)
        }

    except OSError as error:
        return {
            "success": False,
            "url": url,
            "status_code": None,
            "location": None,
            "headers": {},
            "error": str(error)
        }


def analyze_redirect_response(response):
    """
    Analyze a single HTTP response for redirect behavior.
    """
    if not response:
        return {
            "is_redirect": False,
            "status_code": None,
            "location": None,
            "has_location": False
        }

    status_code = response.get("status_code")
    location = response.get("location")

    is_redirect = (
        status_code in REDIRECT_STATUS_CODES
        and bool(location)
    )

    return {
        "is_redirect": is_redirect,
        "status_code": status_code,
        "location": location,
        "has_location": bool(location)
    }


def validate_redirect_target(url):
    """
    Validate a redirect target before following it.
    """
    if not url:
        return {
            "valid": False,
            "reason": "Empty redirect target"
        }

    try:
        parsed = urllib.parse.urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return {
                "valid": False,
                "reason": "Unsupported redirect scheme"
            }

        if not parsed.hostname:
            return {
                "valid": False,
                "reason": "Redirect target has no hostname"
            }

        return {
            "valid": True,
            "reason": None
        }

    except ValueError:
        return {
            "valid": False,
            "reason": "Malformed redirect target"
        }


def follow_redirect_chain(url, max_redirects=5, timeout=5):
    """
    Follow HTTP redirects manually.
    """
    if not url:
        return {
            "original_url": url,
            "final_url": None,
            "redirect_count": 0,
            "loop_detected": False,
            "max_redirects_reached": False,
            "completed": False,
            "hops": [],
            "error": "No URL provided"
        }

    current_url = url
    visited_urls = set()
    hops = []

    for _ in range(max_redirects + 1):
        if current_url in visited_urls:
            return {
                "original_url": url,
                "final_url": current_url,
                "redirect_count": len(hops),
                "loop_detected": True,
                "max_redirects_reached": False,
                "completed": False,
                "hops": hops,
                "error": "Redirect loop detected"
            }

        visited_urls.add(current_url)

        response = dispatch("make_http_request", make_http_request)(
            current_url,
            timeout=timeout
        )

        if not response.get("success"):
            return {
                "original_url": url,
                "final_url": current_url,
                "redirect_count": len(hops),
                "loop_detected": False,
                "max_redirects_reached": False,
                "completed": False,
                "hops": hops,
                "error": response.get("error")
            }

        redirect = analyze_redirect_response(response)

        hops.append({
            "url": current_url,
            "status_code": redirect["status_code"],
            "location": redirect["location"],
            "is_redirect": redirect["is_redirect"]
        })

        if not redirect["is_redirect"]:
            return {
                "original_url": url,
                "final_url": current_url,
                "redirect_count": len(hops) - 1,
                "loop_detected": False,
                "max_redirects_reached": False,
                "completed": True,
                "hops": hops,
                "error": None
            }

        next_url = urllib.parse.urljoin(
            current_url,
            redirect["location"]
        )

        target_validation = validate_redirect_target(next_url)
        if not target_validation["valid"]:
            return {
                "original_url": url,
                "final_url": current_url,
                "redirect_count": len(hops),
                "loop_detected": False,
                "max_redirects_reached": False,
                "completed": False,
                "hops": hops,
                "error": target_validation["reason"]
            }

        current_url = next_url

    return {
        "original_url": url,
        "final_url": current_url,
        "redirect_count": len(hops),
        "loop_detected": False,
        "max_redirects_reached": True,
        "completed": False,
        "hops": hops,
        "error": "Maximum redirect limit reached"
    }


def evaluate_redirect_risk(redirect_analysis):
    """
    Evaluate security risk from redirect behavior.
    """
    score = 0
    findings = []

    if not redirect_analysis:
        return {
            "score": 0,
            "findings": []
        }

    redirect_count = redirect_analysis.get("redirect_count", 0)
    cross_domain = redirect_analysis.get("cross_domain_redirect", False)
    https_downgrade = redirect_analysis.get("https_downgrade", False)

    if redirect_count >= 3:
        score += 10
        findings.append("URL uses multiple redirects")

    if cross_domain:
        score += 10
        findings.append("Redirect chain crosses between different domains")

    if https_downgrade:
        score += 20
        findings.append("Redirect chain downgrades from HTTPS to HTTP")

    return {
        "score": score,
        "findings": findings
    }


def analyze_redirect_chain(chain):
    """
    Analyze a completed redirect chain for security-relevant behavior.
    """
    if not chain:
        return {
            "redirect_count": 0,
            "domains": [],
            "cross_domain_redirect": False,
            "https_downgrade": False,
            "final_domain": None,
            "findings": []
        }

    hops = chain.get("hops", [])
    domains = []
    cross_domain_redirect = False
    https_downgrade = False
    findings = []

    previous_url = None

    for hop in hops:
        current_url = hop.get("url")
        if not current_url:
            continue

        parsed_current = urllib.parse.urlparse(current_url)
        current_domain = parsed_current.hostname

        if current_domain and current_domain not in domains:
            domains.append(current_domain)

        if previous_url:
            parsed_previous = urllib.parse.urlparse(previous_url)
            previous_domain = parsed_previous.hostname

            if (
                previous_domain
                and current_domain
                and previous_domain.lower() != current_domain.lower()
            ):
                cross_domain_redirect = True

            if (
                parsed_previous.scheme.lower() == "https"
                and parsed_current.scheme.lower() == "http"
            ):
                https_downgrade = True

        previous_url = current_url

    final_url = chain.get("final_url")
    final_domain = None

    if final_url:
        final_domain = urllib.parse.urlparse(final_url).hostname

    if cross_domain_redirect:
        findings.append("Redirect chain crosses between different domains")

    if https_downgrade:
        findings.append("Redirect chain downgrades from HTTPS to HTTP")

    return {
        "redirect_count": chain.get("redirect_count", 0),
        "domains": domains,
        "cross_domain_redirect": cross_domain_redirect,
        "https_downgrade": https_downgrade,
        "final_domain": final_domain,
        "findings": findings
    }


def classify_redirect_chain(redirect_analysis):
    """
    Classify the overall redirect behavior.
    """
    if not redirect_analysis:
        return "NO_REDIRECT_DATA"

    if redirect_analysis.get("https_downgrade"):
        return "HTTPS_DOWNGRADE"

    if redirect_analysis.get("cross_domain_redirect"):
        return "CROSS_DOMAIN"

    redirect_count = redirect_analysis.get("redirect_count", 0)

    if redirect_count >= 3:
        return "MULTIPLE_REDIRECTS"

    if redirect_count > 0:
        return "SINGLE_REDIRECT"

    return "NO_REDIRECT"
