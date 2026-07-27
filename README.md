# SecureVision VAPT

## Project Abstract

**SecureVision VAPT**

**AI-assisted Vulnerability Assessment Platform for Surveillance Infrastructure**

SecureVision VAPT is a practical cybersecurity assessment dashboard designed for evaluating CCTV cameras, DVRs, and similar surveillance devices in a safe and controlled way. The project allows users to enter an IP range or a list of devices, simulate discovery and fingerprinting, analyze common weak points such as exposed services, outdated firmware, and default credential risks, and then generate a structured risk report for review. It combines Flask-based web development, SQLite persistence, and an interactive dashboard to make security assessment easier to understand and manage.

This project is especially useful for learning, demonstration, and academic purposes because it focuses on defensive security practices rather than offensive exploitation. It offers a strong foundation for building a more advanced vulnerability management platform in the future.

## Security Product Architecture

The platform follows a structured security-assessment workflow designed to resemble a modern vulnerability management product:

Discovery
↓
Fingerprinting
↓
Service Detection
↓
Credential Audit
↓
Firmware Analysis
↓
CVE Correlation
↓
Risk Scoring
↓
Remediation Engine
↓
Historical Database
↓
Dashboard
↓
PDF Report

### Architecture Overview

- Discovery: identifies target devices and network assets within a given scope.
- Fingerprinting: collects device metadata, service banners, and vendor information.
- Service Detection: recognizes exposed services such as RTSP, Telnet, or ONVIF.
- Credential Audit: evaluates weak or default credential exposure patterns.
- Firmware Analysis: checks for version baselines and outdated firmware behavior.
- CVE Correlation: maps observed weaknesses to known vulnerability context.
- Risk Scoring: calculates severity and prioritizes findings.
- Remediation Engine: provides actionable mitigation guidance.
- Historical Database: stores findings and supports evidence-based review.
- Dashboard: presents insights through an interactive web interface.
- PDF Report: produces a formal report for assessment delivery.

## What this project does well

- Discovers devices from CIDR ranges or comma-separated IP lists
- Performs service and firmware fingerprinting
- Simulates common surveillance-device risks in a safe manner
- Stores report history and device inventory locally
- Presents findings through an easy-to-use dashboard

## Suggested next improvements

To make the project more professional and production-ready, the following improvements are recommended:

- Add user authentication and role-based access control
- Add report export options such as PDF and CSV
- Add analytics for risk trends and recurring issues
- Add scheduled scanning and alerting features
- Move from SQLite to a stronger database for larger deployments
- Add API support for integration with SIEM or SOC tools
- Add automated tests and CI/CD workflows

## Run

```bash
pip install -r requirements.txt
python app.py
```

Then open the local Flask URL shown in the terminal.

## Live deploy on Render

Render can host this project as a free web service. Use the included `render.yaml` blueprint or create a new Web Service with these settings:

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn -b 0.0.0.0:$PORT wsgi:app`
- Environment variables: `SECRET_KEY` and `SECUREVISION_DB_PATH=/tmp/securevision/database.db`

Note: the free Render filesystem is ephemeral, so SQLite data is best treated as demo data unless you add an external database later.

## Repository hygiene

The project ignores generated and local-only artifacts such as Python bytecode, virtual environments, backups, and the local SQLite database. Those files should stay untracked so a fresh clone remains clean and portable.
