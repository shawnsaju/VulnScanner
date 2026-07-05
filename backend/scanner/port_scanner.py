import socket
import asyncio
import logging
from typing import List, Tuple
from models.schemas import PortInfo, SeverityLevel

logger = logging.getLogger(__name__)

# High-risk ports and their associated risks
HIGH_RISK_PORTS = {
    21: ("FTP", SeverityLevel.HIGH, "FTP often transmits credentials in plaintext"),
    22: ("SSH", SeverityLevel.LOW, "SSH is generally secure but verify version"),
    23: ("Telnet", SeverityLevel.CRITICAL, "Telnet transmits all data in plaintext"),
    25: ("SMTP", SeverityLevel.MEDIUM, "Open SMTP relay may enable spam"),
    53: ("DNS", SeverityLevel.LOW, "DNS service exposed"),
    80: ("HTTP", SeverityLevel.MEDIUM, "Unencrypted HTTP traffic"),
    110: ("POP3", SeverityLevel.HIGH, "POP3 may transmit credentials in plaintext"),
    111: ("RPC", SeverityLevel.HIGH, "RPC portmapper can expose services"),
    135: ("MS-RPC", SeverityLevel.HIGH, "Windows RPC - common attack vector"),
    139: ("NetBIOS", SeverityLevel.HIGH, "NetBIOS session service exposed"),
    143: ("IMAP", SeverityLevel.MEDIUM, "IMAP service exposed"),
    443: ("HTTPS", SeverityLevel.INFO, "Standard HTTPS - verify SSL configuration"),
    445: ("SMB", SeverityLevel.CRITICAL, "SMB exposed - EternalBlue/ransomware risk"),
    1433: ("MSSQL", SeverityLevel.CRITICAL, "Database port exposed to internet"),
    1521: ("Oracle DB", SeverityLevel.CRITICAL, "Oracle database exposed"),
    2049: ("NFS", SeverityLevel.HIGH, "NFS can allow unauthorized file access"),
    3306: ("MySQL", SeverityLevel.CRITICAL, "MySQL database exposed to internet"),
    3389: ("RDP", SeverityLevel.CRITICAL, "RDP exposed - BlueKeep/credential stuffing risk"),
    4444: ("Metasploit", SeverityLevel.CRITICAL, "Known backdoor/Metasploit default port"),
    5432: ("PostgreSQL", SeverityLevel.CRITICAL, "PostgreSQL exposed to internet"),
    5900: ("VNC", SeverityLevel.HIGH, "VNC remote access exposed"),
    6379: ("Redis", SeverityLevel.CRITICAL, "Redis often misconfigured, no auth by default"),
    8080: ("HTTP-Alt", SeverityLevel.MEDIUM, "Alternative HTTP port"),
    8443: ("HTTPS-Alt", SeverityLevel.LOW, "Alternative HTTPS port"),
    27017: ("MongoDB", SeverityLevel.CRITICAL, "MongoDB exposed - often no auth"),
    27018: ("MongoDB", SeverityLevel.CRITICAL, "MongoDB shard exposed"),
}

# Common ports to scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
    4444, 5432, 5900, 6379, 8080, 8443, 8888, 9200,
    27017, 27018, 6443, 2375, 2376, 5000, 5001
]

QUICK_PORTS = [21, 22, 23, 80, 443, 3306, 3389, 5432, 6379, 27017, 8080, 8443]


async def check_port(host: str, port: int, timeout: float = 2.0) -> Tuple[int, bool]:
    """Asynchronously check if a port is open."""
    try:
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(
            None,
            lambda: _sync_check_port(host, port, timeout)
        )
        result = await asyncio.wait_for(future, timeout=timeout + 1)
        return port, result
    except Exception:
        return port, False


def _sync_check_port(host: str, port: int, timeout: float) -> bool:
    """Synchronous port check."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def get_service_banner(host: str, port: int, timeout: float = 3.0) -> str:
    """Try to grab a service banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                # Send HTTP request for web ports
                if port in [80, 8080, 8443, 443]:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
                return data.decode('utf-8', errors='ignore').strip()[:200]
            except Exception:
                return ""
    except Exception:
        return ""


async def scan_ports(host: str, scan_type: str = "full") -> List[PortInfo]:
    """Scan ports on the target host."""
    ports_to_scan = QUICK_PORTS if scan_type == "quick" else COMMON_PORTS
    open_ports: List[PortInfo] = []

    logger.info(f"Scanning {len(ports_to_scan)} ports on {host}")

    # Batch port checks for performance
    batch_size = 20
    for i in range(0, len(ports_to_scan), batch_size):
        batch = ports_to_scan[i:i + batch_size]
        tasks = [check_port(host, port) for port in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                continue
            port, is_open = result
            if is_open:
                service_name, risk, _ = HIGH_RISK_PORTS.get(
                    port, ("unknown", SeverityLevel.INFO, "")
                )
                banner = get_service_banner(host, port)
                version = None
                if banner:
                    # Try to extract version from banner
                    lines = banner.split('\n')
                    if lines:
                        version = lines[0][:80]

                open_ports.append(PortInfo(
                    port=port,
                    state="open",
                    service=service_name,
                    version=version,
                    risk=risk
                ))
                logger.info(f"  Open: {port}/{service_name}")

    return open_ports


def resolve_hostname(target: str) -> str:
    """Resolve hostname to IP, or return IP if already one."""
    # Strip protocol if present
    target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target
