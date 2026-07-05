import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional
from contextlib import asynccontextmanager

import requests as req_lib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse

from models.schemas import (
    ScanRequest, ScanResponse, ScanResult, ScanStatus, ScanType,
    ScanStage, DNSInfo
)
from scanner.port_scanner import scan_ports, resolve_hostname
from scanner.http_scanner import scan_http_headers, check_ssl_certificate, get_ssl_vulnerabilities
from scanner.whois_scanner import scan_whois_dns
from scanner.vuln_analyzer import (
    analyze_port_vulnerabilities, build_vulnerabilities,
    calculate_summary, calculate_risk_score
)
from reports.generator import generate_pdf_report

# ─────────────────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# In-memory scan store (replace with Redis/DB in production)
scan_store: Dict[str, ScanResult] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("VulnScanner API starting up...")
    yield
    logger.info("VulnScanner API shutting down...")


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="VulnScanner API",
    description="Automated Vulnerability Scanner & Report Generator",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Background Scan Worker
# ─────────────────────────────────────────────────────────────────────────────
def update_stage(scan_id: str, stage_name: str, status: str, progress: int, message: str = ""):
    """Update a specific stage in the scan."""
    if scan_id not in scan_store:
        return
    result = scan_store[scan_id]
    for stage in result.stages:
        if stage.name == stage_name:
            stage.status = status
            stage.progress = progress
            stage.message = message
            break
    # Update overall progress
    completed = sum(1 for s in result.stages if s.status == "completed")
    total_stages = len(result.stages)
    result.progress = int((completed / total_stages) * 100) if total_stages > 0 else 0


async def run_scan(scan_id: str, target: str, scan_type: ScanType):
    """Execute the full vulnerability scan pipeline."""
    logger.info(f"Starting scan {scan_id} on {target} ({scan_type})")

    result = scan_store[scan_id]
    result.status = ScanStatus.RUNNING

    all_raw_vulns = []
    port_vulns = []
    ssl_vulns = []

    try:
        # ── Stage 1: DNS Resolution ──────────────────────────────────
        update_stage(scan_id, "DNS Resolution", "running", 10, f"Resolving {target}...")
        await asyncio.sleep(0.5)

        hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        resolved_ip = resolve_hostname(hostname)
        update_stage(scan_id, "DNS Resolution", "completed", 100, f"Resolved to {resolved_ip}")

        # ── Stage 2: WHOIS & DNS Recon ───────────────────────────────
        if scan_type in [ScanType.FULL, ScanType.QUICK]:
            update_stage(scan_id, "WHOIS & DNS", "running", 20, "Gathering DNS and WHOIS data...")
            try:
                whois_result = await asyncio.wait_for(scan_whois_dns(target), timeout=30)
                result.whois_data = whois_result.get("whois_data", {})
                dns_data = whois_result.get("dns_info", {})
                result.dns_info = DNSInfo(
                    a_records=dns_data.get("a_records", []),
                    mx_records=dns_data.get("mx_records", []),
                    txt_records=dns_data.get("txt_records", []),
                    ns_records=dns_data.get("ns_records", []),
                    cname_records=dns_data.get("cname_records", []),
                )
                all_raw_vulns.extend(whois_result.get("vulnerabilities", []))
                update_stage(scan_id, "WHOIS & DNS", "completed", 100, "DNS reconnaissance complete")
            except asyncio.TimeoutError:
                update_stage(scan_id, "WHOIS & DNS", "completed", 100, "DNS scan timed out (partial results)")
            except Exception as e:
                logger.warning(f"WHOIS/DNS scan failed: {e}")
                update_stage(scan_id, "WHOIS & DNS", "completed", 100, f"DNS scan error: {str(e)[:50]}")

        # ── Stage 3: HTTP Headers ────────────────────────────────────
        if scan_type in [ScanType.FULL, ScanType.QUICK, ScanType.HEADERS]:
            update_stage(scan_id, "HTTP Headers", "running", 30, "Analyzing security headers...")
            try:
                http_result = await asyncio.wait_for(scan_http_headers(target), timeout=20)
                result.http_headers = http_result.get("headers_info")
                all_raw_vulns.extend(http_result.get("vulnerabilities", []))
                update_stage(scan_id, "HTTP Headers", "completed", 100, "Header analysis complete")
            except asyncio.TimeoutError:
                update_stage(scan_id, "HTTP Headers", "completed", 100, "Header scan timed out")
            except Exception as e:
                logger.warning(f"HTTP header scan failed: {e}")
                update_stage(scan_id, "HTTP Headers", "completed", 100, f"Header scan error: {str(e)[:50]}")

        # ── Stage 4: SSL/TLS ─────────────────────────────────────────
        if scan_type in [ScanType.FULL, ScanType.QUICK, ScanType.HEADERS]:
            update_stage(scan_id, "SSL/TLS Analysis", "running", 40, "Checking SSL certificate...")
            try:
                ssl_info = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, lambda: asyncio.run(check_ssl_certificate(hostname))
                    ) if False else check_ssl_certificate(hostname),
                    timeout=15
                )
                if ssl_info:
                    result.ssl_info = ssl_info
                    ssl_vulns = get_ssl_vulnerabilities(ssl_info, target)
                update_stage(scan_id, "SSL/TLS Analysis", "completed", 100, "SSL analysis complete")
            except asyncio.TimeoutError:
                update_stage(scan_id, "SSL/TLS Analysis", "completed", 100, "SSL scan timed out")
            except Exception as e:
                logger.warning(f"SSL check failed: {e}")
                update_stage(scan_id, "SSL/TLS Analysis", "completed", 100, "SSL scan skipped")

        # ── Stage 5: Port Scan ───────────────────────────────────────
        if scan_type in [ScanType.FULL, ScanType.QUICK, ScanType.PORTS]:
            update_stage(scan_id, "Port Scanning", "running", 50, f"Scanning ports on {resolved_ip}...")
            try:
                st = "quick" if scan_type == ScanType.QUICK else "full"
                open_ports = await asyncio.wait_for(scan_ports(resolved_ip, st), timeout=60)
                result.open_ports = open_ports
                port_vulns = analyze_port_vulnerabilities(open_ports, target)
                update_stage(
                    scan_id, "Port Scanning", "completed", 100,
                    f"Found {len(open_ports)} open port(s)"
                )
            except asyncio.TimeoutError:
                update_stage(scan_id, "Port Scanning", "completed", 100, "Port scan timed out (partial)")
            except Exception as e:
                logger.warning(f"Port scan failed: {e}")
                update_stage(scan_id, "Port Scanning", "completed", 100, f"Port scan error: {str(e)[:50]}")

        # ── Stage 6: Analysis & Report ───────────────────────────────
        update_stage(scan_id, "Analysis", "running", 80, "Analyzing findings...")
        await asyncio.sleep(0.5)

        result.vulnerabilities = build_vulnerabilities(all_raw_vulns, port_vulns, ssl_vulns)
        result.summary = calculate_summary(result.vulnerabilities)
        result.progress = 100
        result.status = ScanStatus.COMPLETED
        result.completed_at = datetime.now(timezone.utc).isoformat()

        update_stage(scan_id, "Analysis", "completed", 100,
                     f"Found {result.summary.get('total', 0)} vulnerabilities")

        logger.info(
            f"Scan {scan_id} complete: "
            f"{result.summary.get('critical', 0)} critical, "
            f"{result.summary.get('high', 0)} high, "
            f"{result.summary.get('medium', 0)} medium, "
            f"{result.summary.get('low', 0)} low"
        )

    except Exception as e:
        logger.error(f"Scan {scan_id} failed with unexpected error: {e}", exc_info=True)
        result.status = ScanStatus.FAILED
        result.error = str(e)
        result.completed_at = datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    return {"message": "VulnScanner API v1.0", "status": "operational", "docs": "/docs"}


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "active_scans": len([s for s in scan_store.values()
                                                   if s.status == ScanStatus.RUNNING])}


@app.post("/scan", response_model=ScanResponse, tags=["Scanning"])
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new vulnerability scan."""
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Determine stages based on scan type
    stages_map = {
        ScanType.FULL: ["DNS Resolution", "WHOIS & DNS", "HTTP Headers", "SSL/TLS Analysis", "Port Scanning", "Analysis"],
        ScanType.QUICK: ["DNS Resolution", "WHOIS & DNS", "HTTP Headers", "SSL/TLS Analysis", "Port Scanning", "Analysis"],
        ScanType.HEADERS: ["DNS Resolution", "HTTP Headers", "SSL/TLS Analysis", "Analysis"],
        ScanType.PORTS: ["DNS Resolution", "Port Scanning", "Analysis"],
    }
    stages = [
        ScanStage(name=name, status="pending", progress=0)
        for name in stages_map.get(scan_request.scan_type, stages_map[ScanType.FULL])
    ]

    scan_result = ScanResult(
        scan_id=scan_id,
        target=scan_request.target,
        scan_type=scan_request.scan_type,
        status=ScanStatus.PENDING,
        started_at=now,
        stages=stages,
        progress=0,
    )
    scan_store[scan_id] = scan_result

    background_tasks.add_task(run_scan, scan_id, scan_request.target, scan_request.scan_type)

    return ScanResponse(
        scan_id=scan_id,
        message=f"Scan started for {scan_request.target}",
        status=ScanStatus.PENDING,
    )


@app.get("/scan/{scan_id}", response_model=ScanResult, tags=["Scanning"])
async def get_scan_status(scan_id: str):
    """Get the status and results of a scan."""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan_store[scan_id]


@app.get("/scan/{scan_id}/report", tags=["Reports"])
async def download_report(scan_id: str):
    """Download a PDF vulnerability report."""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    scan_result = scan_store[scan_id]
    if scan_result.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    try:
        pdf_bytes = generate_pdf_report(scan_result)
        filename = f"vuln_report_{scan_result.target.replace('.', '_')}_{scan_id[:8]}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


@app.get("/scans", tags=["Scanning"])
async def list_scans():
    """List all scans with basic info."""
    return [
        {
            "scan_id": r.scan_id,
            "target": r.target,
            "status": r.status,
            "progress": r.progress,
            "started_at": r.started_at,
            "completed_at": r.completed_at,
            "summary": r.summary,
        }
        for r in sorted(scan_store.values(), key=lambda x: x.started_at, reverse=True)
    ]


@app.delete("/scan/{scan_id}", tags=["Scanning"])
async def delete_scan(scan_id: str):
    """Delete a scan from memory."""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    del scan_store[scan_id]
    return {"message": f"Scan {scan_id} deleted"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
