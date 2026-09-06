# SecureVision VAPT

> **Web-based Vulnerability Assessment and Penetration Testing (VAPT)
> platform for network and surveillance-device security assessment.**

SecureVision VAPT is a Flask-based cybersecurity assessment platform
that combines **Nmap-based network discovery, service/version
fingerprinting, vulnerability correlation, risk scoring, remediation
guidance, historical reporting, analytics, and a web dashboard** into a
single workflow.

The project is designed primarily for **authorized security assessments,
academic demonstration, defensive security research, and
vulnerability-management workflows**.

------------------------------------------------------------------------

## 📌 Overview

SecureVision VAPT follows a structured assessment pipeline:

``` text
Target Scope
     │
     ▼
Network Discovery
     │
     ▼
Nmap Service & Version Detection
     │
     ▼
Device Fingerprinting
     │
     ├── Vendor / Model
     ├── Services
     ├── Product / Version
     ├── CPE
     └── Device Type / OS Context
     │
     ▼
Vulnerability Analysis
     │
     ├── Service Exposure Checks
     ├── Credential Risk Checks
     ├── Firmware Analysis
     └── CPE / Product / Version → CVE Correlation
     │
     ▼
Risk Scoring
     │
     ▼
Remediation Recommendations
     │
     ▼
SQLite Persistence
     │
     ├── Reports
     ├── Devices
     ├── Findings
     └── Assets / Alerts
     │
     ▼
Dashboard / Analytics / Reports / API
```

The application supports both **live Nmap scanning** and a separate
simulated discovery mode for deterministic development/testing. Live
scanning does not silently fall back to simulated data.

------------------------------------------------------------------------

## 🎯 Objectives

-   Discover hosts and exposed network services within an authorized
    scope.
-   Identify service names, products, versions, and CPE information
    using Nmap.
-   Build a security-oriented fingerprint of discovered devices.
-   Detect potentially risky or exposed services such as Telnet, FTP,
    RTSP, ONVIF, and HTTP.
-   Analyze known firmware/version information against local security
    baselines.
-   Correlate sufficiently supported software evidence with CVE records.
-   Calculate a 0--100 risk score based on finding severity.
-   Generate remediation recommendations and security guidance.
-   Maintain historical scan reports and asset information.
-   Provide dashboard analytics for security review and prioritization.
-   Export assessment results in PDF, CSV, and JSON formats.
-   Provide REST API endpoints for integration with other security
    tooling.

------------------------------------------------------------------------

## 🧩 Core Features

### 1. Network Discovery

Targets can be supplied as:

-   Individual IPv4 addresses
-   Hostnames
-   CIDR network ranges
-   Comma-separated target lists

For CIDR ranges, Nmap host discovery is performed before individual
service/version scans.

For hostnames, the application resolves IPv4 addresses and attempts live
scanning against the resolved addresses.

------------------------------------------------------------------------

### 2. Nmap Integration

SecureVision uses Nmap for live network assessment.

The host service scan uses:

``` text
-Pn -sT -sV --reason
```

This provides:

-   TCP connect scanning
-   Service detection
-   Product identification
-   Version information
-   Port state
-   Nmap service name
-   Tunnel information
-   Detection reason
-   CPE information when reported by Nmap

Example evidence captured by the scanner:

``` text
Port:       3306/tcp
State:      open
Service:    mysql
Product:    MySQL
Version:    8.0.44
CPE:        cpe:/a:mysql:mysql:8.0.44
```

------------------------------------------------------------------------

### 3. Device Fingerprinting

The fingerprinting layer builds a structured device profile without
inventing unsupported information.

It can derive:

-   IP address
-   Vendor
-   Model
-   Firmware/version information
-   Device type
-   Platform/OS context
-   Architecture
-   Detection confidence
-   Observed products
-   Observed versions
-   Observed CPEs
-   Exposure profile
-   Nmap evidence

Vendor/device intelligence includes surveillance-oriented profiles such
as:

-   Hikvision
-   Dahua
-   Axis
-   Uniview

The system also provides conservative service-based device
classification when vendor-specific evidence is unavailable.

------------------------------------------------------------------------

### 4. Service Exposure Analysis

The service detection layer maintains profiles for network services and
evaluates their security exposure.

Examples include:

  Service   Example Risk
  --------- --------------------------------------------
  Telnet    High -- unencrypted remote access
  RTSP      Medium -- video stream exposure
  ONVIF     Medium -- device management exposure
  FTP       Medium -- file transfer exposure
  MySQL     Medium -- database exposure
  HTTP      Low -- unencrypted web management exposure

The application distinguishes **observed service exposure** from a
confirmed CVE.

------------------------------------------------------------------------

### 5. Vulnerability & CVE Correlation

SecureVision uses a conservative vulnerability-correlation approach.

A generic service being open does **not** automatically produce a CVE.

Instead, CVE correlation can use:

``` text
Observed Product
       +
Observed Version
       +
Service Context
       +
CPE Evidence
       ↓
CVE Match
```

CPE information reported by Nmap can be used to strengthen product
identification and version correlation.

The system records match evidence such as:

-   CVE ID
-   Title
-   Description
-   CVSS score
-   Severity
-   Exploitability
-   Match source
-   Observed CPE
-   References

This design helps avoid reporting a CVE when the scanner does not have
sufficient product/version evidence.

------------------------------------------------------------------------

### 6. Firmware Analysis

The firmware analysis component maintains vendor-specific baselines for
supported vendors.

It can identify:

-   Current version
-   Latest baseline version
-   Outdated status
-   End-of-life status
-   Firmware upgrade guidance

Supported vendor knowledge currently includes:

-   Hikvision
-   Dahua
-   Axis
-   Uniview

Firmware being old is not automatically treated as proof that every CVE
associated with that vendor applies. Confirmed vulnerability correlation
is handled separately.

------------------------------------------------------------------------

### 7. Security Plugins

The scanner includes a plugin architecture for service-specific checks.

Current plugin areas include:

-   Telnet
-   RTSP
-   ONVIF
-   HTTP/HTTPS
-   FTP

Plugins are discovered dynamically and use manifests to define metadata
such as:

-   Plugin name
-   Description
-   Severity
-   Associated service

This structure makes the scanner extensible without placing every
service-specific check inside one large function.

------------------------------------------------------------------------

### 8. Risk Scoring

Findings are assigned severity levels:

``` text
Critical
High
Medium
Low
Info
```

The current risk scoring model uses severity weights:

``` text
Critical = 40
High     = 25
Medium   = 12
Low      = 4
Info     = 1
```

The combined score is capped at:

``` text
100
```

This produces an easy-to-understand 0--100 risk score for
prioritization.

------------------------------------------------------------------------

### 9. Intelligence & Remediation

Findings can be enriched with security context such as:

-   Technical explanation
-   Business impact
-   Exploitability
-   Attack scenario
-   Risk justification

The remediation engine provides actionable recommendations.

Vendor-specific remediation guidance is available for supported
surveillance vendors and common exposed services.

Examples include:

-   Disable Telnet.
-   Restrict management services.
-   Enforce HTTPS.
-   Enable RTSP authentication.
-   Restrict ONVIF access.
-   Disable unnecessary FTP exposure.
-   Replace default credentials.
-   Upgrade firmware using the correct vendor/model package.

------------------------------------------------------------------------

### 10. Historical Database

SecureVision uses SQLite for local persistence.

The database stores assessment information including:

-   Reports
-   Devices
-   Findings
-   Assets
-   Intelligence
-   Risk scores
-   Scan history

This enables historical review rather than treating each scan as an
isolated operation.

> For a production-scale deployment, an external persistent database
> would be preferable to SQLite.

------------------------------------------------------------------------

### 11. Dashboard & Analytics

The Flask web interface provides views for:

-   Dashboard
-   Devices
-   Device details
-   Assets
-   Reports
-   Remediation
-   Alerts

Analytics are derived from persisted scan evidence.

Examples include:

-   Risk distribution
-   CVE counts
-   CVE trends
-   Device risk timeline
-   Service exposure
-   Asset statistics

The analytics layer intentionally avoids creating synthetic scan results
when historical data is unavailable.

------------------------------------------------------------------------

### 12. Alerts

The alerting engine supports security-event categories such as:

-   Risk threshold exceeded
-   Critical finding detected
-   New CVE detected
-   Firmware update available
-   Device offline
-   Default credential exposure
-   Dangerous service exposure

Alerts can be stored and acknowledged through the application.

------------------------------------------------------------------------

### 13. Report Generation

Assessment results can be exported in multiple formats:

``` text
PDF
CSV
JSON
```

The PDF report includes structured assessment information such as:

-   Executive summary
-   Target scope
-   Overall risk score
-   Device count
-   Finding count
-   Severity information
-   Vulnerability information
-   Recommendations

------------------------------------------------------------------------

### 14. REST API

SecureVision provides REST API endpoints under:

``` text
/api/v1
```

The API contains areas for:

-   Health/status
-   Statistics
-   Assets
-   Findings
-   Reports
-   Devices
-   Scan operations
-   Remediation
-   Dashboard/integration functionality

The current API documentation is available in:

``` text
API_DOCUMENTATION.md
```

> **Important:** The current API does not implement authentication. API
> authentication should be added before exposing it in an untrusted
> production environment.

------------------------------------------------------------------------

## 🏗️ Project Architecture

``` text
SecureVision VAPT
│
├── app.py
├── wsgi.py
├── requirements.txt
├── Dockerfile
├── render.yaml
│
├── api/
│   ├── scan.py
│   ├── dashboard.py
│   ├── devices.py
│   ├── reports.py
│   ├── assets.py
│   ├── export.py
│   ├── remediation.py
│   ├── alerts.py
│   └── integration.py
│
├── core/
│   ├── app_factory.py
│   └── config.py
│
├── scanner/
│   ├── nmap_scanner.py
│   ├── discovery.py
│   ├── fingerprint.py
│   ├── vulnerability.py
│   ├── cve_matcher.py
│   ├── firmware_database.py
│   ├── service_detector.py
│   ├── os_detection.py
│   ├── intelligence_enricher.py
│   ├── recommendation_engine.py
│   ├── remediation_guide.py
│   ├── risk_score.py
│   ├── analytics.py
│   ├── alerting.py
│   ├── report.py
│   ├── report_generator.py
│   ├── pipeline.py
│   └── plugins/
│
├── database/
│   ├── db.py
│   ├── models.py
│   └── assets.py
│
├── templates/
│   └── Flask/Jinja web interface
│
├── static/
│   └── CSS and frontend assets
│
├── data/
│   ├── vendors.json
│   └── default_credentials.json
│
└── tests/
    └── automated tests
```

------------------------------------------------------------------------

## 🔄 Assessment Workflow

A typical live assessment follows this sequence:

### Step 1 --- Define Scope

Example:

``` text
192.168.1.100
```

or:

``` text
192.168.1.0/24
```

or:

``` text
camera.example.local
```

### Step 2 --- Discover Hosts

Nmap identifies active hosts within the defined scope.

### Step 3 --- Detect Services

The scanner identifies exposed ports and attempts service/version
detection.

### Step 4 --- Build Fingerprint

The application processes Nmap evidence to determine available vendor,
model, version, CPE, service, and device-type information.

### Step 5 --- Analyze Security Exposure

Service-specific plugins and security rules evaluate potentially risky
configurations.

### Step 6 --- Correlate Vulnerabilities

Known vulnerability records are matched only when sufficient
product/version/service evidence exists.

### Step 7 --- Calculate Risk

Finding severities are converted into an overall 0--100 risk score.

### Step 8 --- Generate Recommendations

The remediation engine provides prioritized security guidance.

### Step 9 --- Persist Results

Reports, devices, findings, and intelligence are stored in SQLite.

### Step 10 --- Present Results

Results become available through the dashboard, analytics, reports, and
API.

------------------------------------------------------------------------

## 🛠️ Technology Stack

  Technology    Purpose
  ------------- ----------------------------------------------
  Python        Core application and scanner logic
  Flask         Web application and REST API
  Nmap          Network/service discovery and fingerprinting
  python-nmap   Python integration with Nmap
  SQLite        Local persistence
  SQLAlchemy    Database-related dependency
  Jinja2        Server-side HTML templates
  ReportLab     PDF report generation
  Pandas        Data processing/export support
  OpenPyXL      Spreadsheet-related export support
  Gunicorn      Production WSGI server
  Docker        Deployment/runtime environment
  Render        Cloud deployment

------------------------------------------------------------------------

## 🚀 Local Setup

### Prerequisites

Install:

-   Python 3.11+
-   Nmap
-   Git

Verify Nmap:

``` bash
nmap --version
```

### Clone the repository

``` bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd "SecureVision VAPT"
```

### Create a virtual environment

Windows PowerShell:

``` powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Install dependencies

``` bash
pip install -r requirements.txt
```

### Start the application

``` bash
python app.py
```

The application normally runs on:

``` text
http://127.0.0.1:5000
```

------------------------------------------------------------------------

## 🐳 Docker

The repository includes a Dockerfile that installs Nmap inside the
container and prepares the Flask application for deployment.

Build:

``` bash
docker build -t securevision-vapt .
```

Run:

``` bash
docker run -p 5000:5000 securevision-vapt
```

For cloud deployment, the included `render.yaml` configures a Render web
service using Gunicorn.

------------------------------------------------------------------------

## 🌐 Live Demo

The current deployed application:

**https://securevision-vapt.onrender.com**

The live deployment is intended for demonstration and authorized testing
only.

Because the current Render configuration uses an ephemeral filesystem
path for SQLite, persistent production data should not be assumed to
survive service restarts/redeployments.

------------------------------------------------------------------------

## 🧪 Testing & Validation

The project contains automated tests under:

``` text
tests/
```

and an Nmap integration flow under:

``` text
scanner/test_nmap_flow.py
```

Validation covers areas including:

-   Python compilation
-   Live discovery behavior
-   Prevention of silent simulated fallback
-   Nmap product/version evidence preservation
-   CPE-based vulnerability matching
-   Conservative CVE correlation
-   Plugin discovery and execution
-   Dashboard/report selection behavior

Example local scanner flow:

``` bash
python -m scanner.test_nmap_flow
```

------------------------------------------------------------------------

## 🔐 Security Design Principles

SecureVision follows several important defensive-security principles:

### No silent simulation in live mode

If Nmap fails during a live scan, the application exposes the failure
instead of silently generating simulated devices.

### Evidence-based vulnerability correlation

A generic service such as FTP or HTTP is not automatically treated as
proof of a CVE.

### Conservative fingerprinting

Vendor, model, and firmware information are not invented when Nmap
evidence is insufficient.

### Scope-aware scanning

The scanner should only be used against systems for which the operator
has explicit authorization.

### Separation of exposure findings and CVEs

An exposed service can be a security finding even when no specific CVE
can be confidently correlated.

------------------------------------------------------------------------

## 🤖 Machine Learning Component

SecureVision includes an **ML-based exposure anomaly detection layer** implemented with **Isolation Forest** from scikit-learn.

The model is intentionally separate from deterministic CVE matching and the existing severity-based risk score. It learns an exposure baseline and identifies device profiles that are unusual compared with that baseline.

### ML features

The model uses scanner-derived security evidence such as:

- Number of open services
- High-risk and medium-risk service counts
- Unencrypted service count
- Number of correlated CVEs
- Maximum CVSS score
- Potentially exploitable CVE evidence
- Default credential exposure
- Outdated firmware
- End-of-life firmware
- RTSP/ONVIF surveillance exposure

The existing deterministic `risk_score` is deliberately **not** used as a model input, preventing circular learning from the rule-based score.

### ML workflow

```text
Nmap / Security Evidence
          ↓
Feature Extraction
          ↓
Isolation Forest
          ↓
Anomaly Score (0–100)
          ↓
Low / Medium / High
          ↓
Risk Prioritization Support
```

The dashboard displays the ML anomaly score, risk level, and top contributing security signals. The ML result is a **prioritization signal**, not proof that a vulnerability or CVE exists.

For first-run deployments, the model uses a small deterministic bootstrap baseline. As the project evolves, the baseline can be replaced or supplemented with historical authorized scan data. No ML accuracy claim is made from the bootstrap baseline because it is not a labeled benchmark dataset.

## ⚠️ Limitations

-   CVE correlation depends on the local vulnerability knowledge base.
-   A CVE match is intentionally conservative and requires sufficient
    evidence.
-   Firmware analysis uses maintained local vendor baselines.
-   SQLite is suitable for development/demo workloads but is not ideal
    for large production deployments.
-   The current REST API does not provide authentication.
-   The project should not be treated as a replacement for a full
    enterprise VAPT platform or professional penetration test.
-   Some device/vendor identification is dependent on the information
    exposed by the target service.
-   Network visibility and firewall configuration can affect Nmap
    results.

------------------------------------------------------------------------

## 🔮 Future Enhancements

Potential future improvements include:

-   Machine-learning-based risk prediction
-   Larger and automatically updated CVE intelligence
-   NVD/CVE feed synchronization
-   User authentication
-   Role-based access control
-   Persistent PostgreSQL deployment
-   Background scan workers
-   Scheduled assessments
-   Email/SIEM notifications
-   More surveillance-device vendors
-   More service-specific plugins
-   Improved asset correlation
-   CI/CD security testing
-   Advanced vulnerability trend analysis
-   Authenticated device assessment
-   Enterprise-scale multi-user support

------------------------------------------------------------------------

## 👥 Project Structure for Academic Presentation

The project can be explained through the following major modules:

``` text
Member / Module Area
        │
        ├── Web Application
        │      └── Flask + Dashboard
        │
        ├── Network Security Scanner
        │      └── Nmap + Discovery
        │
        ├── Vulnerability Analysis
        │      └── Fingerprinting + CVE Correlation
        │
        ├── Risk & Intelligence
        │      └── Scoring + Recommendations
        │
        └── Data & Reporting
               └── SQLite + Analytics + PDF/API
```

------------------------------------------------------------------------

## 📄 Additional Documentation

  File                          Purpose
  ----------------------------- -----------------------------------
  `API_DOCUMENTATION.md`        REST API reference
  `VALIDATION.txt`              Pipeline and CVE validation notes
  `FIX_AUDIT.md`                Development/fix audit information
  `scanner/test_nmap_flow.py`   Nmap integration flow
  `Dockerfile`                  Container configuration
  `render.yaml`                 Render deployment configuration

------------------------------------------------------------------------

## ⚖️ Responsible Use

SecureVision VAPT is intended for **authorized security assessment and
defensive purposes**.

Only scan:

-   Systems you own
-   Systems you are explicitly authorized to assess
-   Controlled laboratory environments
-   Intentionally provided security-testing targets

Do not use the platform to scan or test systems without permission.

------------------------------------------------------------------------

## 📜 License

No explicit open-source license is currently defined in the project
repository.

If this project is published publicly, add an appropriate `LICENSE` file
describing how others may use, modify, and distribute the software.

------------------------------------------------------------------------

## ⭐ Project Summary

**SecureVision VAPT** brings together network discovery, security
fingerprinting, vulnerability correlation, risk scoring, remediation
guidance, historical asset tracking, analytics, and reporting into a
single web-based platform.

Its core design emphasizes **real scanner evidence, conservative
vulnerability matching, explainable risk analysis, and actionable
remediation** rather than treating every exposed service as a confirmed
vulnerability.
