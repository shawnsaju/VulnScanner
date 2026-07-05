# 🔒 VulnScanner — Automated Vulnerability Scanner & Dashboard

> **An end-to-end cybersecurity assessment platform** that scans URLs and IP addresses for security vulnerabilities, displays results in a real-time visual dashboard, and generates professional PDF reports.

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Technology Stack & Why We Chose It](#technology-stack)
3. [Architecture](#architecture)
4. [Scanning Capabilities](#scanning-capabilities)
5. [How It Works — Technical Walkthrough](#how-it-works)
6. [Clone & Setup Guide](#setup--run-guide)
7. [Project Structure](#project-structure)
8. [Legal Disclaimer](#legal-disclaimer)

---

## Project Overview

VulnScanner is a full-stack security tool that automates the reconnaissance and vulnerability assessment phase of security testing. It combines:

- **Backend** — A Python/FastAPI server that orchestrates asynchronous security scans
- **Frontend** — A React/Vite dashboard that shows live scan progress, charts, and findings
- **Report Engine** — ReportLab-powered PDF generation for professional security reports

### Key Features

| Feature                 | Description                                            |
| ----------------------- | ------------------------------------------------------ |
| Port Scanning           | Identifies open TCP ports using async Python sockets   |
| HTTP Header Analysis    | Checks for 7 critical security headers                 |
| SSL/TLS Inspection      | Certificate validity, expiry, protocol version grading |
| DNS Reconnaissance      | A, MX, NS, TXT, CNAME records + SPF/DMARC checks       |
| WHOIS Lookup            | Domain registration, registrar, expiry data            |
| Severity Classification | Critical / High / Medium / Low / Info                  |
| Real-time Progress      | Polling-based stage-by-stage progress tracking         |
| PDF Reports             | Downloadable professional security reports             |
| Scan History            | All scans stored in-memory with list/delete            |

---

## Technology Stack

### Backend

#### 🐍 Python 3.11+

**Why Python?** Python is the lingua franca of cybersecurity. Libraries like `requests`, `dnspython`, `python-whois`, `pyOpenSSL`, and `nmap` all have mature Python bindings. Python's `asyncio` makes concurrent scanning efficient without threading complexity.

**Compared to Node.js:** Node has fewer mature security libraries and less community tooling in the infosec space.

**Compared to Go:** Go has excellent performance but a smaller security library ecosystem.

---

#### ⚡ FastAPI (Web Framework)

**Why FastAPI?**

- **Async-native** — `async/await` throughout means scans run in background without blocking the API
- **Pydantic integration** — request/response validation is automatic
- **BackgroundTasks** — built-in mechanism to fire-and-forget long-running scans
- **Performance** — on par with Node.js/Go for I/O-bound workloads (Starlette under the hood)

**Compared to Flask:** Flask is synchronous by default; async requires extensions. BackgroundTasks requires Celery/Redis setup.

**Compared to Django:** Django is too heavyweight for a microservice API. Too much ORM/admin overhead.

```python
# FastAPI makes scan endpoints trivially clean:
@app.post("/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_scan, scan_id, req.target, req.scan_type)
    return ScanResponse(scan_id=scan_id, status=ScanStatus.PENDING)
```

---

#### 📐 Pydantic v2

**Why Pydantic?** Schema validation, serialization, and IDE autocomplete for all data models. Ensures `ScanRequest`, `Vulnerability`, `SSLInfo`, etc. are always well-typed.

---

#### 🔌 Python `socket` (Port Scanning)

**Why pure socket instead of Nmap?** Nmap requires installation and elevated privileges on some systems. Python's built-in `socket` module works everywhere without system dependencies. We implement async batching (20 ports at a time) for speed.

**If Nmap is available:** `python-nmap` can be added for OS fingerprinting and version detection. The requirements.txt includes it as an optional enhancement.

---

#### 🌐 `requests` (HTTP Analysis)

Industry-standard HTTP library for Python. Used for:

- Fetching headers (with `allow_redirects=True`)
- Handling SSL errors gracefully
- Detecting redirect chains

---

#### 🔒 `ssl` + `pyOpenSSL` (SSL Analysis)

Python's built-in `ssl` module connects to port 443, retrieves the certificate chain, and extracts: issuer, subject, expiry date, protocol version. We calculate a TLS grade (A+ for TLS 1.3, F for SSLv3/TLS 1.0).

---

#### 🌍 `dnspython` (DNS Reconnaissance)

**Why dnspython?** The definitive Python DNS library. Used to query:

- A, AAAA, MX, NS, TXT, CNAME records
- Attempt DNS zone transfer (AXFR) — a critical misconfiguration
- Check for missing SPF/DMARC records

---

#### 📄 ReportLab (PDF Generation)

**Why ReportLab?** The most mature Python PDF library. Supports:

- Tables with custom styling
- Color-coded severity rows
- Page breaks, headers, footers
- Embedded metadata

**Compared to WeasyPrint:** ReportLab produces smaller files and doesn't require external CSS/HTML rendering.  
**Compared to fpdf2:** ReportLab has richer table/flowable support needed for our complex reports.

---

### Frontend

#### ⚛️ React 19 + Vite

**Why React?**

- Component model maps perfectly to the dashboard's modular UI
- Large ecosystem (Recharts, React Router, Axios all battle-tested)
- Hooks (`useState`, `useEffect`) make polling logic clean

**Why Vite over Create React App (CRA)?**

- 10-100x faster cold starts (native ESM + esbuild)
- No Webpack config bloat
- Hot Module Replacement works instantly

**Compared to Next.js:** We don't need SSR/SSG. A pure SPA is simpler to deploy alongside the FastAPI backend.

**Compared to Vue:** React has deeper community support for security/data visualization tools.

---

#### 📊 Recharts

**Why Recharts?**

- React-native (not a jQuery wrapper)
- Composable: `<PieChart>`, `<BarChart>`, `<Cell>` are just React components
- Responsive out of the box via `<ResponsiveContainer>`
- Custom tooltips via render props

**Compared to Chart.js:** Chart.js requires canvas manipulation; Recharts uses SVG and integrates naturally with React state.  
**Compared to D3:** D3 requires much more code for the same charts.

---

#### 🔀 React Router v6

Client-side routing between:

- `/` — Home/Scanner page
- `/results/:scanId` — Results dashboard

---

#### 📡 Axios

**Why Axios over `fetch`?**

- Automatic JSON parsing
- Request/response interceptors
- Better error handling (non-2xx responses throw automatically)
- Timeout support built-in

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  USER BROWSER                    │
│                                                  │
│  React SPA (port 5173)                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ ScanForm │  │ Progress │  │ Dashboard    │  │
│  │          │  │ Stages   │  │ Charts Ports │  │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘  │
│       │             │  polling       │           │
└───────┼─────────────┼────────────────┼───────────┘
        │ POST /scan  │ GET /scan/:id  │ GET report
        ▼             ▼                ▼
┌─────────────────────────────────────────────────┐
│              FastAPI Backend (port 8000)          │
│                                                  │
│  ┌───────────┐   ┌──────────────────────────┐   │
│  │  /scan    │→  │  BackgroundTask: run_scan │   │
│  │  /scan/:id│   │                          │   │
│  │  /report  │   │  ┌──────────────────┐    │   │
│  └───────────┘   │  │ port_scanner.py  │    │   │
│                  │  │ http_scanner.py  │    │   │
│  In-Memory Store │  │ whois_scanner.py │    │   │
│  scan_store: {}  │  │ vuln_analyzer.py │    │   │
│                  │  └──────────────────┘    │   │
│                  └──────────────────────────┘   │
│                                                  │
│  PDF Generator (ReportLab)                       │
└─────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────┐
│                 INTERNET / TARGET                 │
│  - DNS servers (dnspython)                       │
│  - Target HTTP/HTTPS endpoint (requests)         │
│  - Target TCP ports (socket)                     │
│  - WHOIS servers (python-whois)                  │
└─────────────────────────────────────────────────┘
```

---

## Scanning Capabilities

### 1. Port Scanner (`scanner/port_scanner.py`)

- Uses `asyncio` + Python `socket` for concurrent scanning
- Batches 20 simultaneous port checks for performance
- Scans 35 common ports (Full) or 12 critical ports (Quick)
- Banner grabbing for service version detection
- Maps high-risk ports to pre-defined severity/CVE data:

| Port  | Service | Severity    | Why                    |
| ----- | ------- | ----------- | ---------------------- |
| 23    | Telnet  | 🔴 Critical | Plaintext protocol     |
| 445   | SMB     | 🔴 Critical | EternalBlue / WannaCry |
| 3389  | RDP     | 🔴 Critical | BlueKeep CVE-2019-0708 |
| 3306  | MySQL   | 🔴 Critical | DB exposed to internet |
| 6379  | Redis   | 🔴 Critical | No auth by default     |
| 27017 | MongoDB | 🔴 Critical | No auth by default     |
| 21    | FTP     | 🟠 High     | Plaintext credentials  |
| 80    | HTTP    | 🟡 Medium   | Unencrypted traffic    |

### 2. HTTP Header Scanner (`scanner/http_scanner.py`)

Checks for 7 required security headers:

| Header                    | Severity if Missing | Attack Prevented         |
| ------------------------- | ------------------- | ------------------------ |
| Strict-Transport-Security | 🟠 High             | Protocol downgrade, MITM |
| Content-Security-Policy   | 🟠 High             | XSS injection            |
| X-Frame-Options           | 🟡 Medium           | Clickjacking             |
| X-Content-Type-Options    | 🟡 Medium           | MIME sniffing            |
| X-XSS-Protection          | 🟡 Medium           | Reflected XSS            |
| Referrer-Policy           | 🔵 Low              | Data leakage             |
| Permissions-Policy        | 🔵 Low              | Feature abuse            |

Also checks:

- **CORS wildcard** (`Access-Control-Allow-Origin: *`)
- **Cookie flags** (HttpOnly, Secure, SameSite)
- **Information disclosure** (Server, X-Powered-By headers)
- **HTTPS enforcement**

### 3. SSL/TLS Analyzer (`scanner/http_scanner.py`)

- Connects to port 443 using Python's `ssl` module
- Extracts certificate: issuer, subject, expiry date
- Calculates days until expiry
- Grades TLS protocol: A+ (TLS 1.3), A (TLS 1.2), F (TLS 1.0/1.1/SSL)
- Detects expired certificates (Critical severity)

### 4. DNS & WHOIS Recon (`scanner/whois_scanner.py`)

- Queries A, MX, NS, TXT, CNAME records
- Checks for missing **SPF** record (email spoofing risk)
- Checks for missing **DMARC** policy
- Attempts **DNS Zone Transfer** (AXFR) — critical if successful
- Fetches WHOIS: registrar, creation/expiry dates, nameservers

### 5. Vulnerability Analyzer (`scanner/vuln_analyzer.py`)

- Aggregates findings from all scanners
- Maps port findings to CVEs (EternalBlue, BlueKeep, etc.)
- Calculates **CVSS-like risk score** (0-10)
- Sorts vulnerabilities by severity (Critical → Info)

---

## How It Works

### Scan Lifecycle

```
User submits target
       │
       ▼
POST /scan → Creates ScanResult (PENDING)
       │      Fires BackgroundTask
       │
       ▼
Background: run_scan()
  ├─ Stage 1: DNS Resolution (socket.gethostbyname)
  ├─ Stage 2: WHOIS & DNS (dnspython + python-whois)
  ├─ Stage 3: HTTP Headers (requests.get)
  ├─ Stage 4: SSL/TLS (ssl.create_default_context)
  ├─ Stage 5: Port Scan (async socket batching)
  └─ Stage 6: Analysis (aggregate + classify)
       │
       ▼
ScanResult updated to COMPLETED
       │
Frontend polls GET /scan/:id every 1.5s
       │
       ▼
Results page renders Dashboard + Charts + Cards
       │
       ▼
PDF download → GET /scan/:id/report (ReportLab generates on-demand)
```

### Frontend Polling Strategy

Rather than WebSockets (which require persistent connections and more complex state management), we use simple interval polling every 1.5 seconds. This is simpler, works behind proxies, and is sufficient for scans that take 15-60 seconds.

### Severity Classification Logic

```python
SEVERITY_ORDER = {
    CRITICAL: score 8-10 (immediate action required)
    HIGH:     score 6-8  (fix within days)
    MEDIUM:   score 4-6  (fix within weeks)
    LOW:      score 2-4  (fix in next release)
    INFO:     score 0-2  (informational only)
}
```

---

## Setup & Run Guide

### Prerequisites

- **Python 3.11+** — [python.org](https://python.org)
- **Node.js 18+** — [nodejs.org](https://nodejs.org)
- **pip** (comes with Python)

> **Optional:** Install [Nmap](https://nmap.org/download.html) for enhanced port scanning (python-nmap wrapper)

---

### Step 1: Clone the Repository

```powershell
# Clone from GitHub
git clone https://github.com/<your-username>/VulnScanner.git

# Enter the project folder
cd VulnScanner
```

---

### Step 1b: Configure Environment Variables

```powershell
# Copy the example env file and fill in your values
cd backend
copy .env.example .env
```

Open `backend/.env` in any text editor and set the required values (API keys, allowed origins, etc.).

Then come back to the project root:

```powershell
cd ..
```

---

### Step 2: Set Up Python Backend

```powershell
# Navigate to backend
cd backend

# Create a virtual environment (recommended)
python -m venv venv

# Activate the virtual environment
.\venv\Scripts\activate          # Windows PowerShell
# source venv/bin/activate       # macOS/Linux

# Install all dependencies
pip install -r requirements.txt
```

---

### Step 3: Start the Backend Server

```powershell
# From the backend/ directory (with venv activated)
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Expected output:**

```
INFO:     VulnScanner API starting up...
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

✅ Backend is live at: `http://localhost:8000`

---

### Step 4: Set Up Frontend

Open a **new terminal window**:

```powershell
# Navigate to frontend (relative path — works after cloning on any machine)
cd frontend

# Install npm dependencies (already done if you followed the build)
npm install

# Start the development server
npm run dev
```

**Expected output:**

```
  VITE v6.x.x  ready in 350 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

✅ Frontend is live at: `http://localhost:5173`

---

### Step 5: Run Your First Scan

1. Open `http://localhost:5173` in your browser
2. Enter a target: `scanme.nmap.org` (Nmap's official legal test target)
3. Select **Full Scan**
4. Click **🚀 Start Scan**
5. Watch the live stage-by-stage progress
6. View the results dashboard with charts
7. Click **⬇️ Download PDF Report**

---

### Quick Startup Script (Windows)

Create `start.ps1` in the project root:

```powershell
# start.ps1
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd backend; .\venv\Scripts\activate; uvicorn main:app --reload"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd frontend; npm run dev"
Start-Process "http://localhost:5173"
```

### 🎉 VulnScanner — Project Complete Guide

🚀 Start the Project

Option 1 — One click: (One-click launcher for both servers)
powershell

```bash
cd VulnScanner
.\start.ps1
```

Option 2 — Manual (two terminals):
powershell

```bash
# Terminal 1 (backend)
cd VulnScanner\backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
# Terminal 2 (frontend)
cd VulnScanner\frontend
npm run dev
Then open http://localhost:5173 and scan scanme.nmap.org as your first test!
```

---

### Troubleshooting

| Issue                                            | Solution                                                                     |
| ------------------------------------------------ | ---------------------------------------------------------------------------- |
| `ModuleNotFoundError: No module named 'fastapi'` | Run `pip install -r requirements.txt` in the backend dir with venv activated |
| `CORS error in browser`                          | Make sure backend is running on port 8000                                    |
| `Connection refused` on scan                     | Target may be firewalled; try `scanme.nmap.org`                              |
| `PDF download fails`                             | Ensure `reportlab` is installed: `pip install reportlab`                     |
| `dnspython not found`                            | Run `pip install dnspython`                                                  |
| Port scan very slow                              | Try **Quick Scan** mode instead of Full                                      |

---


## Project Structure

```
VulnScanner/
├── backend/
│   ├── main.py                  # FastAPI app, endpoints, scan orchestration
│   ├── requirements.txt         # Python dependencies
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py           # Pydantic models (ScanRequest, Vulnerability, etc.)
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── port_scanner.py      # Async socket port scanning
│   │   ├── http_scanner.py      # HTTP headers + SSL analysis
│   │   ├── whois_scanner.py     # DNS + WHOIS reconnaissance
│   │   └── vuln_analyzer.py     # Severity classification + risk scoring
│   └── reports/
│       ├── __init__.py
│       └── generator.py         # ReportLab PDF generation
│
├── frontend/
│   ├── index.html               # HTML entry point with SEO meta tags
│   ├── vite.config.js           # Vite configuration
│   ├── package.json             # npm dependencies
│   └── src/
│       ├── main.jsx             # React entry point
│       ├── App.jsx              # Router + Navbar + Layout
│       ├── index.css            # Full design system (dark theme, animations)
│       ├── api/
│       │   └── scanner.js       # Axios API client
│       ├── components/
│       │   ├── ScanForm.jsx     # Target input + scan type selector
│       │   ├── ScanProgress.jsx # Live stage progress tracking
│       │   ├── Dashboard.jsx    # Stats grid + risk score
│       │   ├── VulnerabilityCard.jsx  # Expandable finding card
│       │   ├── SeverityChart.jsx      # Recharts pie + bar charts
│       │   └── ReportDownload.jsx     # PDF download button
│       └── pages/
│           ├── Home.jsx         # Landing page + scan history
│           └── Results.jsx      # Full tabbed results dashboard
│
└── PROJECT_GUIDE.md             # This file
```

---

## Legal Disclaimer

> ⚠️ **IMPORTANT:** VulnScanner is intended exclusively for **authorized security assessments**.
>
> - Only scan systems you **own** or have **explicit written permission** to test
> - Unauthorized scanning may violate the **Computer Fraud and Abuse Act (CFAA)**, **GDPR**, and other laws
> - The authors assume **no liability** for misuse of this tool
> - For practice, use: `scanme.nmap.org`, `testphp.vulnweb.com`, or your own local VM

---

_Built for the Cybersecurity + Full-Stack Developer portfolio | FastAPI + React + Recharts + ReportLab_
