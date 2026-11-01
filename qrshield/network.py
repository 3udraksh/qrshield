"""
QRShield Network Security, SSRF Prevention, DNS & TLS Intelligence
"""

import socket
import ssl
import datetime
import ipaddress
from cryptography import x509
from qrshield.lexical import is_ip_address


def is_unsafe_network_target(hostname):
    """
    Determine whether a hostname resolves to a local,
    private, loopback, link-local, or otherwise non-public
    IP address.
    """
    if not hostname:
        return {
            "unsafe": True,
            "addresses": [],
            "reason": "No hostname provided"
        }

    # Direct IP address
    try:
        ip = ipaddress.ip_address(hostname)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return {
                "unsafe": True,
                "addresses": [str(ip)],
                "reason": "Non-public IP address"
            }

        return {
            "unsafe": False,
            "addresses": [str(ip)],
            "reason": None
        }

    except ValueError:
        pass

    # Hostname -> IP resolution
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        addresses = []
        for result in results:
            address = result[4][0]
            if address not in addresses:
                addresses.append(address)

        for address in addresses:
            ip = ipaddress.ip_address(address)

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                return {
                    "unsafe": True,
                    "addresses": addresses,
                    "reason": "Hostname resolves to a non-public IP address"
                }

        return {
            "unsafe": False,
            "addresses": addresses,
            "reason": None
        }

    except socket.gaierror:
        return {
            "unsafe": True,
            "addresses": [],
            "reason": "Hostname could not be resolved"
        }

    except (socket.timeout, TimeoutError):
        return {
            "unsafe": True,
            "addresses": [],
            "reason": "Hostname resolution timed out"
        }

    except OSError as exc:
        return {
            "unsafe": True,
            "addresses": [],
            "reason": f"Network resolution error: {exc}"
        }


def resolve_hostname(hostname):
    """
    Resolve a hostname using the system DNS resolver.
    """
    if not hostname:
        return {
            "resolved": False,
            "addresses": [],
            "ipv4": [],
            "ipv6": [],
            "error": "No hostname provided"
        }

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        addresses = set()
        for result in results:
            address = result[4][0]
            addresses.add(address)

        ipv4_addresses = []
        ipv6_addresses = []

        for address in sorted(addresses):
            try:
                ip = ipaddress.ip_address(address)
                if ip.version == 4:
                    ipv4_addresses.append(address)
                elif ip.version == 6:
                    ipv6_addresses.append(address)
            except ValueError:
                continue

        all_addresses = ipv4_addresses + ipv6_addresses

        return {
            "resolved": bool(all_addresses),
            "addresses": all_addresses,
            "ipv4": ipv4_addresses,
            "ipv6": ipv6_addresses,
            "error": None
        }

    except socket.gaierror as error:
        return {
            "resolved": False,
            "addresses": [],
            "ipv4": [],
            "ipv6": [],
            "error": str(error)
        }

    except socket.timeout:
        return {
            "resolved": False,
            "addresses": [],
            "ipv4": [],
            "ipv6": [],
            "error": "DNS resolution timed out"
        }

    except OSError as error:
        return {
            "resolved": False,
            "addresses": [],
            "ipv4": [],
            "ipv6": [],
            "error": str(error)
        }


def analyze_dns(hostname):
    """
    Analyze DNS information for a hostname.
    """
    if not hostname:
        return {
            "hostname": hostname,
            "status": "NO_HOSTNAME",
            "is_ip": False,
            "resolved": False,
            "addresses": [],
            "ipv4": [],
            "ipv6": [],
            "address_count": 0,
            "ipv4_count": 0,
            "ipv6_count": 0,
            "error": "No hostname provided"
        }

    if is_ip_address(hostname):
        return {
            "hostname": hostname,
            "status": "IP_LITERAL",
            "is_ip": True,
            "resolved": False,
            "addresses": [hostname],
            "ipv4": [hostname] if "." in hostname else [],
            "ipv6": [hostname] if ":" in hostname else [],
            "address_count": 1,
            "ipv4_count": 1 if "." in hostname else 0,
            "ipv6_count": 1 if ":" in hostname else 0,
            "error": None
        }

    dns_result = resolve_hostname(hostname)

    if dns_result["resolved"]:
        status = "RESOLVED"
    else:
        status = "DNS_FAILURE"

    return {
        "hostname": hostname,
        "status": status,
        "is_ip": False,
        "resolved": dns_result["resolved"],
        "addresses": dns_result["addresses"],
        "ipv4": dns_result["ipv4"],
        "ipv6": dns_result["ipv6"],
        "address_count": len(dns_result["addresses"]),
        "ipv4_count": len(dns_result["ipv4"]),
        "ipv6_count": len(dns_result["ipv6"]),
        "error": dns_result["error"]
    }


def build_dns_features(dns_analysis):
    """
    Convert detailed DNS analysis into a compact feature set.
    """
    return {
        "status": dns_analysis["status"],
        "address_count": dns_analysis["address_count"],
        "ipv4_count": dns_analysis["ipv4_count"],
        "ipv6_count": dns_analysis["ipv6_count"],
        "has_ipv4": dns_analysis["ipv4_count"] > 0,
        "has_ipv6": dns_analysis["ipv6_count"] > 0,
        "resolution_failed": dns_analysis["status"] == "DNS_FAILURE"
    }


def evaluate_dns_risk(dns_features):
    """
    Evaluate DNS-related risk indicators.
    """
    score = 0
    findings = []

    if dns_features["status"] == "DNS_FAILURE":
        score += 10
        findings.append({
            "severity": "low",
            "message": "Hostname could not be resolved through DNS"
        })

    return {
        "score": score,
        "findings": findings
    }


def get_tls_connection(hostname, port=443, timeout=5):
    """
    Establish a TLS connection to a hostname with SSRF validation.
    """
    if not hostname:
        return {
            "connected": False,
            "hostname": hostname,
            "port": port,
            "error": "No hostname provided"
        }

    target_check = is_unsafe_network_target(hostname)
    if target_check["unsafe"]:
        return {
            "connected": False,
            "hostname": hostname,
            "port": port,
            "error": f"Blocked unsafe network target: {target_check['reason']}"
        }

    try:
        context = ssl.create_default_context()
        target_ip = target_check["addresses"][0] if target_check.get("addresses") else hostname
        sni_hostname = None if is_ip_address(hostname) else hostname

        with socket.create_connection(
            (target_ip, port),
            timeout=timeout
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=sni_hostname
            ):

                return {
                    "connected": True,
                    "hostname": hostname,
                    "port": port,
                    "error": None
                }

    except (socket.timeout, TimeoutError):
        return {
            "connected": False,
            "hostname": hostname,
            "port": port,
            "error": "TLS connection timed out"
        }

    except ssl.SSLError as error:
        return {
            "connected": False,
            "hostname": hostname,
            "port": port,
            "error": str(error)
        }

    except OSError as error:
        return {
            "connected": False,
            "hostname": hostname,
            "port": port,
            "error": str(error)
        }


def get_tls_certificate(hostname, port=443, timeout=5):
    """
    Retrieve the TLS certificate presented by a hostname in binary DER form.
    Protects against SSRF and DNS rebinding via IP pinning.
    """
    if not hostname:
        return {
            "retrieved": False,
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "error": "No hostname provided"
        }

    target_check = is_unsafe_network_target(hostname)
    if target_check["unsafe"]:
        return {
            "retrieved": False,
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "error": f"Blocked unsafe network target: {target_check['reason']}"
        }

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        target_ip = target_check["addresses"][0] if target_check.get("addresses") else hostname
        sni_hostname = None if is_ip_address(hostname) else hostname

        with socket.create_connection(
            (target_ip, port),
            timeout=timeout
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=sni_hostname
            ) as tls_socket:

                certificate = tls_socket.getpeercert(
                    binary_form=True
                )

                return {
                    "retrieved": bool(certificate),
                    "hostname": hostname,
                    "port": port,
                    "certificate": certificate,
                    "error": None if certificate else "Empty TLS certificate"
                }

    except (socket.timeout, TimeoutError):
        return {
            "retrieved": False,
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "error": "TLS connection timed out"
        }

    except ssl.SSLError as error:
        return {
            "retrieved": False,
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "error": str(error)
        }

    except OSError as error:
        return {
            "retrieved": False,
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "error": str(error)
        }


def extract_certificate_metadata(certificate):
    """
    Extract useful metadata from a TLS certificate.
    """
    if not certificate:
        return {
            "common_name": None,
            "issuer": None,
            "valid_from": None,
            "valid_until": None,
            "dns_names": [],
            "ip_addresses": [],
            "dns_name_count": 0,
            "ip_address_count": 0
        }

    try:
        cert = x509.load_der_x509_certificate(certificate)

        common_name = None
        try:
            common_name = cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )[0].value
        except IndexError:
            pass

        issuer_parts = cert.issuer.get_attributes_for_oid(
            x509.NameOID.ORGANIZATION_NAME
        )

        issuer = ", ".join(
            attribute.value
            for attribute in issuer_parts
        ) if issuer_parts else None

        dns_names = []
        ip_addresses = []

        try:
            san_extension = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )

            for name in san_extension.value:
                if isinstance(name, x509.DNSName):
                    dns_names.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    ip_addresses.append(str(name.value))

        except x509.ExtensionNotFound:
            pass

        valid_from = cert.not_valid_before_utc.strftime(
            "%b %d %H:%M:%S %Y GMT"
        )
        valid_until = cert.not_valid_after_utc.strftime(
            "%b %d %H:%M:%S %Y GMT"
        )

        return {
            "common_name": common_name,
            "issuer": issuer,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "dns_names": dns_names,
            "ip_addresses": ip_addresses,
            "dns_name_count": len(dns_names),
            "ip_address_count": len(ip_addresses)
        }

    except Exception:
        return {
            "common_name": None,
            "issuer": None,
            "valid_from": None,
            "valid_until": None,
            "dns_names": [],
            "ip_addresses": [],
            "dns_name_count": 0,
            "ip_address_count": 0
        }


def analyze_certificate_validity(valid_from, valid_until):
    """
    Analyze the validity period of a TLS certificate.
    """
    if not valid_from or not valid_until:
        return {
            "status": "INVALID",
            "valid_from": valid_from,
            "valid_until": valid_until,
            "days_remaining": None,
            "error": "Certificate validity dates are missing"
        }

    try:
        date_format = "%b %d %H:%M:%S %Y GMT"
        start_date = datetime.datetime.strptime(
            valid_from,
            date_format
        )
        end_date = datetime.datetime.strptime(
            valid_until,
            date_format
        )

        current_date = datetime.datetime.utcnow()

        if current_date < start_date:
            status = "NOT_YET_VALID"
        elif current_date > end_date:
            status = "EXPIRED"
        else:
            status = "VALID"

        days_remaining = (end_date - current_date).days

        return {
            "status": status,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "days_remaining": days_remaining,
            "error": None
        }

    except ValueError as error:
        return {
            "status": "INVALID",
            "valid_from": valid_from,
            "valid_until": valid_until,
            "days_remaining": None,
            "error": str(error)
        }


def analyze_certificate_identity(hostname, certificate_metadata):
    """
    Determine whether a TLS certificate identifies the requested hostname.
    """
    if not hostname:
        return {
            "hostname": hostname,
            "matches": False,
            "matched_name": None,
            "match_type": "NONE",
            "error": "No hostname provided"
        }

    dns_names = certificate_metadata.get("dns_names", [])
    ip_addresses = certificate_metadata.get("ip_addresses", [])

    if is_ip_address(hostname):
        try:
            requested_ip = ipaddress.ip_address(hostname)

            for certificate_ip in ip_addresses:
                try:
                    certificate_ip_object = ipaddress.ip_address(
                        certificate_ip
                    )
                    if requested_ip == certificate_ip_object:
                        return {
                            "hostname": hostname,
                            "matches": True,
                            "matched_name": certificate_ip,
                            "match_type": "IP",
                            "error": None
                        }
                except ValueError:
                    continue

        except ValueError:
            pass

        return {
            "hostname": hostname,
            "matches": False,
            "matched_name": None,
            "match_type": "NONE",
            "error": "IP address not present in certificate SANs"
        }

    # Exact DNS match
    if hostname in dns_names:
        return {
            "hostname": hostname,
            "matches": True,
            "matched_name": hostname,
            "match_type": "DNS",
            "error": None
        }

    # Wildcard matching
    for name in dns_names:
        if name.startswith("*."):
            suffix = name[2:]
            if hostname.endswith("." + suffix):
                hostname_labels = hostname.split(".")
                suffix_labels = suffix.split(".")
                if len(hostname_labels) == len(suffix_labels) + 1:
                    return {
                        "hostname": hostname,
                        "matches": True,
                        "matched_name": name,
                        "match_type": "DNS",
                        "error": None
                    }

    return {
        "hostname": hostname,
        "matches": False,
        "matched_name": None,
        "match_type": "NONE",
        "error": "Hostname not present in certificate SANs"
    }


def build_tls_features(
    certificate_metadata,
    validity_analysis,
    identity_analysis
):
    """
    Convert detailed TLS analysis into a compact feature set.
    """
    return {
        "certificate_present": (
            certificate_metadata.get("common_name") is not None
            or certificate_metadata.get("issuer") is not None
            or certificate_metadata.get("valid_from") is not None
            or certificate_metadata.get("valid_until") is not None
            or certificate_metadata.get("dns_name_count", 0) > 0
            or certificate_metadata.get("ip_address_count", 0) > 0
        ),
        "common_name": certificate_metadata.get("common_name"),
        "issuer": certificate_metadata.get("issuer"),
        "validity_status": validity_analysis["status"],
        "days_remaining": validity_analysis["days_remaining"],
        "identity_matches": identity_analysis["matches"],
        "identity_match_type": identity_analysis["match_type"],
        "matched_name": identity_analysis["matched_name"],
        "dns_name_count": certificate_metadata["dns_name_count"],
        "ip_address_count": certificate_metadata["ip_address_count"]
    }


def evaluate_tls_risk(tls_features):
    """
    Evaluate TLS-related risk indicators.
    """
    score = 0
    findings = []

    if not tls_features["certificate_present"]:
        score += 15
        findings.append({
            "severity": "medium",
            "message": "No TLS certificate was retrieved"
        })
        return {
            "score": score,
            "findings": findings
        }

    if tls_features["validity_status"] == "EXPIRED":
        score += 20
        findings.append({
            "severity": "high",
            "message": "TLS certificate has expired"
        })
    elif tls_features["validity_status"] == "NOT_YET_VALID":
        score += 20
        findings.append({
            "severity": "high",
            "message": "TLS certificate is not yet valid"
        })
    elif tls_features["validity_status"] == "INVALID":
        score += 15
        findings.append({
            "severity": "medium",
            "message": "TLS certificate validity could not be verified"
        })

    if not tls_features["identity_matches"]:
        score += 25
        findings.append({
            "severity": "high",
            "message": "TLS certificate does not match the requested hostname"
        })

    return {
        "score": score,
        "findings": findings
    }
