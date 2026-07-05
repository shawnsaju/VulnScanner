import uuid
import logging
from typing import List, Dict, Any
from models.schemas import (
    Vulnerability, SeverityLevel, PortInfo, SSLInfo,
    HTTPHeadersInfo, DNSInfo, ScanType
)

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 0,
    SeverityLevel.HIGH: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 3,
    SeverityLevel.INFO: 4,
}

# Severity string → enum mapping
SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
}


def severity_from_str(s: str) -> SeverityLevel:
    return SEVERITY_MAP.get(s.lower(), SeverityLevel.INFO)


def analyze_port_vulnerabilities(open_ports: List[PortInfo], target: str) -> List[Dict]:
    """Generate vulnerability findings from open ports."""
    from scanner.port_scanner import HIGH_RISK_PORTS

    vulns = []

    # Check for dangerous port combinations
    port_numbers = {p.port for p in open_ports}

    if 23 in port_numbers:
        vulns.append({
            "title": "Telnet Service Exposed",
            "severity": SeverityLevel.CRITICAL,
            "description": "Telnet (port 23) transmits all data including credentials in plaintext",
            "recommendation": "Disable Telnet immediately and use SSH instead",
            "category": "Network Security",
            "affected": f"{target}:23",
            "cvss_score": 9.8,
            "cve_id": "CWE-319",
        })

    if 445 in port_numbers:
        vulns.append({
            "title": "SMB Port Exposed to Internet",
            "severity": SeverityLevel.CRITICAL,
            "description": "SMB (port 445) exposed — vulnerable to EternalBlue (MS17-010), WannaCry ransomware",
            "recommendation": "Block SMB ports (445, 139) at the firewall perimeter",
            "category": "Network Security",
            "affected": f"{target}:445",
            "cvss_score": 9.8,
            "cve_id": "CVE-2017-0144",
        })

    if 3389 in port_numbers:
        vulns.append({
            "title": "RDP Exposed to Internet",
            "severity": SeverityLevel.CRITICAL,
            "description": "RDP (port 3389) is exposed — vulnerable to BlueKeep (CVE-2019-0708), credential brute-force",
            "recommendation": "Place RDP behind VPN, enable NLA, and restrict by IP",
            "category": "Remote Access",
            "affected": f"{target}:3389",
            "cvss_score": 9.8,
            "cve_id": "CVE-2019-0708",
        })

    database_ports = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
                      27017: "MongoDB", 6379: "Redis", 1521: "Oracle"}
    for port, db_name in database_ports.items():
        if port in port_numbers:
            vulns.append({
                "title": f"{db_name} Database Port Exposed",
                "severity": SeverityLevel.CRITICAL,
                "description": f"{db_name} (port {port}) is directly accessible from the internet",
                "recommendation": f"Immediately restrict {db_name} access to application servers only via firewall rules",
                "category": "Database Security",
                "affected": f"{target}:{port}",
                "cvss_score": 9.8,
            })

    if 21 in port_numbers:
        vulns.append({
            "title": "FTP Service Exposed",
            "severity": SeverityLevel.HIGH,
            "description": "FTP (port 21) transmits credentials in plaintext and is prone to bounce attacks",
            "recommendation": "Replace FTP with SFTP or FTPS",
            "category": "Network Security",
            "affected": f"{target}:21",
            "cvss_score": 7.5,
        })

    if 4444 in port_numbers:
        vulns.append({
            "title": "Potential Backdoor Port Detected",
            "severity": SeverityLevel.CRITICAL,
            "description": "Port 4444 is open — commonly used by Metasploit reverse shells and malware",
            "recommendation": "Immediately investigate this port for malicious activity",
            "category": "Malware/Backdoor",
            "affected": f"{target}:4444",
            "cvss_score": 10.0,
        })

    return vulns


def build_vulnerabilities(
    raw_vulns: List[Dict],
    port_vulns: List[Dict],
    ssl_vulns: List[Dict],
) -> List[Vulnerability]:
    """Convert raw vulnerability dicts into typed Vulnerability models."""
    all_raw = raw_vulns + port_vulns + ssl_vulns
    vulnerabilities = []

    for raw in all_raw:
        severity = raw.get("severity", SeverityLevel.INFO)
        if isinstance(severity, str):
            severity = severity_from_str(severity)

        vuln = Vulnerability(
            id=str(uuid.uuid4()),
            title=raw.get("title", "Unknown Vulnerability"),
            description=raw.get("description", ""),
            severity=severity,
            category=raw.get("category", "General"),
            affected_component=raw.get("affected", "Unknown"),
            recommendation=raw.get("recommendation", "Review and remediate"),
            cvss_score=raw.get("cvss_score"),
            cve_id=raw.get("cve_id"),
            evidence=raw.get("evidence"),
        )
        vulnerabilities.append(vuln)

    # Sort by severity
    vulnerabilities.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 4))
    return vulnerabilities


def calculate_summary(vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
    """Calculate severity counts."""
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": len(vulnerabilities),
    }
    for v in vulnerabilities:
        level = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
        if level in summary:
            summary[level] += 1
    return summary


def calculate_risk_score(vulnerabilities: List[Vulnerability]) -> float:
    """Calculate overall risk score 0-10."""
    if not vulnerabilities:
        return 0.0

    weights = {
        SeverityLevel.CRITICAL: 10.0,
        SeverityLevel.HIGH: 7.5,
        SeverityLevel.MEDIUM: 4.0,
        SeverityLevel.LOW: 1.5,
        SeverityLevel.INFO: 0.0,
    }

    total_weight = sum(weights.get(v.severity, 0) for v in vulnerabilities)
    max_possible = len(vulnerabilities) * 10.0
    score = min(10.0, (total_weight / max_possible) * 10) if max_possible > 0 else 0.0
    return round(score, 1)
