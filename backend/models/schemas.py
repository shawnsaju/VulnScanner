from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any
from enum import Enum
import uuid
from datetime import datetime


class ScanType(str, Enum):
    FULL = "full"
    QUICK = "quick"
    HEADERS = "headers"
    PORTS = "ports"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRequest(BaseModel):
    target: str
    scan_type: ScanType = ScanType.FULL


class Vulnerability(BaseModel):
    id: str
    title: str
    description: str
    severity: SeverityLevel
    category: str
    affected_component: str
    recommendation: str
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    evidence: Optional[str] = None


class PortInfo(BaseModel):
    port: int
    state: str
    service: str
    version: Optional[str] = None
    risk: SeverityLevel = SeverityLevel.INFO


class SSLInfo(BaseModel):
    valid: bool
    issuer: Optional[str] = None
    subject: Optional[str] = None
    expiry_date: Optional[str] = None
    days_remaining: Optional[int] = None
    protocol: Optional[str] = None
    grade: Optional[str] = None


class HTTPHeadersInfo(BaseModel):
    present: List[str] = []
    missing: List[str] = []
    raw_headers: Dict[str, str] = {}


class DNSInfo(BaseModel):
    a_records: List[str] = []
    mx_records: List[str] = []
    txt_records: List[str] = []
    ns_records: List[str] = []
    cname_records: List[str] = []


class ScanStage(BaseModel):
    name: str
    status: str  # pending | running | completed | failed
    progress: int = 0
    message: Optional[str] = None


class ScanResult(BaseModel):
    scan_id: str
    target: str
    scan_type: ScanType
    status: ScanStatus
    started_at: str
    completed_at: Optional[str] = None
    progress: int = 0
    stages: List[ScanStage] = []
    vulnerabilities: List[Vulnerability] = []
    open_ports: List[PortInfo] = []
    ssl_info: Optional[SSLInfo] = None
    http_headers: Optional[HTTPHeadersInfo] = None
    dns_info: Optional[DNSInfo] = None
    whois_data: Optional[Dict[str, Any]] = None
    summary: Optional[Dict[str, int]] = None
    error: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    message: str
    status: ScanStatus


class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
