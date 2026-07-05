import requests
import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from models.schemas import HTTPHeadersInfo, SSLInfo, SeverityLevel

logger = logging.getLogger(__name__)

# Security headers that should be present
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": SeverityLevel.HIGH,
        "description": "HSTS not set — site is vulnerable to protocol downgrade attacks",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cve": None,
    },
    "Content-Security-Policy": {
        "severity": SeverityLevel.HIGH,
        "description": "No Content-Security-Policy header — site may be vulnerable to XSS attacks",
        "recommendation": "Implement a strict CSP to prevent injection attacks",
        "cve": None,
    },
    "X-Frame-Options": {
        "severity": SeverityLevel.MEDIUM,
        "description": "Missing X-Frame-Options — site may be vulnerable to clickjacking",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        "cve": None,
    },
    "X-Content-Type-Options": {
        "severity": SeverityLevel.MEDIUM,
        "description": "Missing X-Content-Type-Options — MIME sniffing attacks possible",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "cve": None,
    },
    "Referrer-Policy": {
        "severity": SeverityLevel.LOW,
        "description": "Missing Referrer-Policy — referrer information may leak",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cve": None,
    },
    "Permissions-Policy": {
        "severity": SeverityLevel.LOW,
        "description": "Missing Permissions-Policy — browser features not restricted",
        "recommendation": "Add Permissions-Policy to restrict access to sensitive browser features",
        "cve": None,
    },
    "X-XSS-Protection": {
        "severity": SeverityLevel.MEDIUM,
        "description": "Missing X-XSS-Protection — legacy XSS filter not enabled",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
        "cve": None,
    },
}

# Headers that leak server information
INFORMATION_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-WordPress-Cache",
    "Via",
]


async def scan_http_headers(target: str) -> Dict[str, Any]:
    """Analyze HTTP security headers."""
    results = {
        "headers_info": None,
        "vulnerabilities": [],
        "server_info": {},
        "redirects": [],
        "uses_https": False,
    }

    # Normalize URL
    if not target.startswith(("http://", "https://")):
        urls_to_try = [f"https://{target}", f"http://{target}"]
    else:
        urls_to_try = [target]
        if target.startswith("https://"):
            results["uses_https"] = True

    response = None
    final_url = None

    for url in urls_to_try:
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "VulnScanner/1.0 Security Assessment Tool"},
                verify=False,
            )
            final_url = url
            if url.startswith("https://"):
                results["uses_https"] = True
            break
        except requests.exceptions.SSLError:
            results["vulnerabilities"].append({
                "title": "SSL Certificate Error",
                "severity": SeverityLevel.HIGH,
                "description": "SSL certificate validation failed",
                "recommendation": "Ensure SSL certificate is valid and properly configured",
                "category": "SSL/TLS",
                "affected": target,
            })
            try:
                response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
                final_url = url
                results["uses_https"] = True
                break
            except Exception:
                continue
        except Exception as e:
            logger.warning(f"Failed to connect to {url}: {e}")
            continue

    if not response:
        results["vulnerabilities"].append({
            "title": "Target Unreachable",
            "severity": SeverityLevel.INFO,
            "description": f"Could not establish HTTP connection to {target}",
            "recommendation": "Verify target is accessible and accepting connections",
            "category": "Connectivity",
            "affected": target,
        })
        return results

    headers = dict(response.headers)
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check if site is HTTP-only (no HTTPS)
    if not results["uses_https"]:
        results["vulnerabilities"].append({
            "title": "No HTTPS Support",
            "severity": SeverityLevel.HIGH,
            "description": "Site does not support HTTPS — all traffic is transmitted in plaintext",
            "recommendation": "Obtain an SSL/TLS certificate and enable HTTPS",
            "category": "Encryption",
            "affected": target,
            "cvss_score": 7.5,
        })

    # Check missing security headers
    present_headers = []
    missing_headers = []

    for header, config in REQUIRED_SECURITY_HEADERS.items():
        if header.lower() in headers_lower:
            present_headers.append(header)
            # Validate header values
            value = headers_lower[header.lower()]
            if header == "Strict-Transport-Security":
                if "max-age" not in value.lower():
                    results["vulnerabilities"].append({
                        "title": "Weak HSTS Configuration",
                        "severity": SeverityLevel.MEDIUM,
                        "description": f"HSTS header present but misconfigured: {value}",
                        "recommendation": "Set max-age to at least 31536000 (1 year)",
                        "category": "HTTP Headers",
                        "affected": header,
                    })
        else:
            missing_headers.append(header)
            results["vulnerabilities"].append({
                "title": f"Missing Security Header: {header}",
                "severity": config["severity"],
                "description": config["description"],
                "recommendation": config["recommendation"],
                "category": "HTTP Headers",
                "affected": header,
                "cve_id": config.get("cve"),
            })

    # Check information disclosure headers
    for header in INFORMATION_DISCLOSURE_HEADERS:
        if header.lower() in headers_lower:
            value = headers_lower[header.lower()]
            results["vulnerabilities"].append({
                "title": f"Information Disclosure via {header} Header",
                "severity": SeverityLevel.LOW,
                "description": f"Server reveals: {header}: {value}",
                "recommendation": f"Remove or obscure the {header} header to prevent fingerprinting",
                "category": "Information Disclosure",
                "affected": header,
                "evidence": value,
            })

    # Check for cookie security
    if "set-cookie" in headers_lower:
        cookie_value = headers_lower["set-cookie"]
        cookie_issues = []
        if "httponly" not in cookie_value.lower():
            cookie_issues.append("HttpOnly flag missing")
        if "secure" not in cookie_value.lower():
            cookie_issues.append("Secure flag missing")
        if "samesite" not in cookie_value.lower():
            cookie_issues.append("SameSite attribute missing")

        if cookie_issues:
            results["vulnerabilities"].append({
                "title": "Insecure Cookie Configuration",
                "severity": SeverityLevel.MEDIUM,
                "description": f"Cookie security issues: {', '.join(cookie_issues)}",
                "recommendation": "Set HttpOnly, Secure, and SameSite=Strict on all cookies",
                "category": "Session Security",
                "affected": "Set-Cookie",
                "evidence": cookie_value[:100],
            })

    # Check CORS misconfiguration
    if "access-control-allow-origin" in headers_lower:
        cors_value = headers_lower["access-control-allow-origin"]
        if cors_value == "*":
            results["vulnerabilities"].append({
                "title": "CORS Wildcard Configuration",
                "severity": SeverityLevel.HIGH,
                "description": "Access-Control-Allow-Origin: * allows any origin to make cross-origin requests",
                "recommendation": "Restrict CORS to specific trusted origins",
                "category": "CORS",
                "affected": "Access-Control-Allow-Origin",
                "evidence": cors_value,
                "cvss_score": 6.5,
            })

    # Track redirect chain
    if response.history:
        for r in response.history:
            results["redirects"].append({
                "url": r.url,
                "status_code": r.status_code,
            })

    # Build headers info
    results["headers_info"] = HTTPHeadersInfo(
        present=present_headers,
        missing=missing_headers,
        raw_headers={k: v[:200] for k, v in headers.items() if k.lower() in
                     [h.lower() for h in REQUIRED_SECURITY_HEADERS]},
    )

    return results


async def check_ssl_certificate(hostname: str) -> Optional[SSLInfo]:
    """Check SSL/TLS certificate details."""
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                # Parse expiry
                expiry_str = cert.get("notAfter", "")
                days_remaining = None
                expiry_formatted = None

                if expiry_str:
                    try:
                        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_remaining = (expiry_date - now).days
                        expiry_formatted = expiry_date.strftime("%Y-%m-%d")
                    except Exception:
                        pass

                # Extract subject
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))

                # Grade based on protocol
                grade = "A"
                if protocol in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    grade = "F"
                elif protocol == "TLSv1.2":
                    grade = "B"
                elif protocol == "TLSv1.3":
                    grade = "A+"

                return SSLInfo(
                    valid=True,
                    issuer=issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                    subject=subject.get("commonName", hostname),
                    expiry_date=expiry_formatted,
                    days_remaining=days_remaining,
                    protocol=protocol,
                    grade=grade,
                )
    except ssl.SSLCertVerificationError as e:
        return SSLInfo(valid=False, grade="F")
    except ssl.SSLError as e:
        return SSLInfo(valid=False, grade="F")
    except ConnectionRefusedError:
        return None  # Port 443 not open
    except Exception as e:
        logger.warning(f"SSL check error for {hostname}: {e}")
        return None


def get_ssl_vulnerabilities(ssl_info: SSLInfo, target: str) -> list:
    """Generate vulnerability findings from SSL info."""
    vulns = []

    if not ssl_info.valid:
        vulns.append({
            "title": "Invalid SSL Certificate",
            "severity": SeverityLevel.CRITICAL,
            "description": "SSL certificate is invalid or could not be verified",
            "recommendation": "Obtain a valid SSL certificate from a trusted CA",
            "category": "SSL/TLS",
            "affected": target,
            "cvss_score": 9.0,
        })
        return vulns

    if ssl_info.days_remaining is not None:
        if ssl_info.days_remaining < 0:
            vulns.append({
                "title": "Expired SSL Certificate",
                "severity": SeverityLevel.CRITICAL,
                "description": f"SSL certificate expired {abs(ssl_info.days_remaining)} days ago",
                "recommendation": "Renew the SSL certificate immediately",
                "category": "SSL/TLS",
                "affected": target,
                "cvss_score": 9.5,
            })
        elif ssl_info.days_remaining < 14:
            vulns.append({
                "title": "SSL Certificate Expiring Soon (Critical)",
                "severity": SeverityLevel.CRITICAL,
                "description": f"SSL certificate expires in {ssl_info.days_remaining} days",
                "recommendation": "Renew the SSL certificate immediately",
                "category": "SSL/TLS",
                "affected": target,
                "cvss_score": 7.0,
            })
        elif ssl_info.days_remaining < 30:
            vulns.append({
                "title": "SSL Certificate Expiring Soon",
                "severity": SeverityLevel.HIGH,
                "description": f"SSL certificate expires in {ssl_info.days_remaining} days",
                "recommendation": "Plan SSL certificate renewal soon",
                "category": "SSL/TLS",
                "affected": target,
            })

    if ssl_info.protocol in ["TLSv1", "TLSv1.1"]:
        vulns.append({
            "title": "Weak TLS Protocol Version",
            "severity": SeverityLevel.HIGH,
            "description": f"Server uses deprecated {ssl_info.protocol} which has known vulnerabilities (POODLE, BEAST)",
            "recommendation": "Upgrade to TLS 1.2 or TLS 1.3",
            "category": "SSL/TLS",
            "affected": target,
            "cvss_score": 7.5,
            "cve_id": "CVE-2014-3566",
        })

    return vulns
