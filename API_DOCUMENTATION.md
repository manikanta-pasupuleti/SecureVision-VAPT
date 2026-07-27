# SecureVision VAPT REST API v1.0

## Overview

The SecureVision VAPT REST API provides programmatic access to vulnerability assessment data for integration with SIEM, SOC, and other security tools.

**Base URL:** `http://localhost:5000/api/v1`

## Authentication

Currently, the API is accessible without authentication. For production deployments, implement API key or OAuth2 authentication.

---

## Endpoints

### Health & Status

#### Health Check
```
GET /health
```
Returns system health status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-07-21T13:16:28Z",
  "version": "1.0"
}
```

#### System Statistics
```
GET /stats
```
Returns overall system statistics.

**Response:**
```json
{
  "reports": 8,
  "devices": 15,
  "findings": 120,
  "assets": 12,
  "alerts": 45,
  "timestamp": "2026-07-21T13:16:28Z"
}
```

---

### Assets

#### List Assets
```
GET /assets?status=active&risk_min=50&risk_max=100&limit=100&offset=0
```

**Query Parameters:**
- `status` (optional): Filter by status (active, inactive, archived)
- `risk_min` (optional): Minimum risk score (0-100)
- `risk_max` (optional): Maximum risk score (0-100)
- `limit` (optional): Results per page (default: 100)
- `offset` (optional): Pagination offset (default: 0)

**Response:**
```json
{
  "total": 12,
  "limit": 100,
  "offset": 0,
  "assets": [
    {
      "id": 1,
      "ip_address": "192.168.1.100",
      "vendor": "Hikvision",
      "model": "DS-2CD2143G0-I",
      "first_seen": "2026-07-04T10:00:00Z",
      "last_seen": "2026-07-21T13:16:28Z",
      "current_firmware": "V5.4.41",
      "current_risk_score": 85,
      "status": "active",
      "owner": "Security Team",
      "location": "Building A - Floor 3",
      "notes": "Main entrance camera"
    }
  ]
}
```

#### Get Asset Detail
```
GET /assets/<asset_id>
```

#### Search Assets
```
POST /assets/search
Content-Type: application/json

{
  "vendor": "Hikvision",
  "ip_pattern": "192.168.1",
  "risk_range": {"min": 70, "max": 100},
  "status": "active"
}
```

#### Asset Statistics
```
GET /assets/stats
```

---

### Findings

#### List Findings
```
GET /findings?severity=critical&device_ip=192.168.1.100&report_id=8&limit=100&offset=0
```

**Query Parameters:**
- `severity` (optional): Filter by severity (critical, high, medium, low, info)
- `device_ip` (optional): Filter by device IP
- `report_id` (optional): Filter by report ID
- `limit` (optional): Results per page (default: 100)
- `offset` (optional): Pagination offset (default: 0)

**Response:**
```json
{
  "total": 45,
  "limit": 100,
  "offset": 0,
  "findings": [
    {
      "id": 1,
      "report_id": 8,
      "device_ip": "192.168.1.100",
      "severity": "critical",
      "title": "Default Credentials Detected",
      "description": "Device has default admin/admin credentials",
      "remediation": "Change default credentials immediately",
      "evidence": "Successful login with admin/admin",
      "technical_explanation": "Device uses hardcoded default credentials...",
      "business_impact": "Unauthorized access to camera feeds...",
      "exploitability": "Easy - no authentication required",
      "attack_scenario": "Attacker gains access to camera feeds...",
      "risk_justification": "Critical risk due to ease of exploitation...",
      "cve_references": [
        {"id": "CVE-2018-10088", "cvss_score": 9.8}
      ],
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-10088"]
    }
  ]
}
```

#### Get Finding Detail
```
GET /findings/<finding_id>
```

#### Search Findings
```
POST /findings/search
Content-Type: application/json

{
  "keyword": "default credentials",
  "severity": "critical",
  "cve_id": "CVE-2018-10088",
  "device_ip": "192.168.1.100",
  "date_range": {
    "start": "2026-07-01T00:00:00Z",
    "end": "2026-07-31T23:59:59Z"
  }
}
```

#### Get Findings by CVE
```
GET /findings/by-cve/CVE-2018-10088
```

#### Findings Statistics
```
GET /findings/stats
```

**Response:**
```json
{
  "total": 120,
  "by_severity": {
    "critical": 15,
    "high": 35,
    "medium": 50,
    "low": 20
  },
  "top_cves": [
    {"cve_id": "CVE-2018-10088", "count": 8},
    {"cve_id": "CVE-2019-5959", "count": 6}
  ]
}
```

---

### Reports

#### List Reports
```
GET /reports?limit=50&offset=0
```

**Query Parameters:**
- `limit` (optional): Results per page (default: 50)
- `offset` (optional): Pagination offset (default: 0)

**Response:**
```json
{
  "total": 8,
  "limit": 50,
  "offset": 0,
  "reports": [
    {
      "id": 8,
      "created_at": "2026-07-21T13:16:28Z",
      "target_spec": "192.168.1.0/24",
      "device_count": 5,
      "finding_count": 45,
      "risk_score": 78,
      "summary": {
        "severity_breakdown": {
          "critical": 5,
          "high": 15,
          "medium": 20,
          "low": 5
        }
      }
    }
  ]
}
```

#### Get Report Detail
```
GET /reports/<report_id>
```

#### Get Report Summary
```
GET /reports/<report_id>/summary
```

#### Get Report Devices
```
GET /reports/<report_id>/devices
```

#### Get Report Findings
```
GET /reports/<report_id>/findings?severity=critical
```

#### Search Reports
```
POST /reports/search
Content-Type: application/json

{
  "target": "192.168.1",
  "risk_range": {"min": 70, "max": 100},
  "date_range": {
    "start": "2026-07-01T00:00:00Z",
    "end": "2026-07-31T23:59:59Z"
  }
}
```

---

### Devices

#### List Devices
```
GET /devices?vendor=Hikvision&limit=100&offset=0
```

**Query Parameters:**
- `vendor` (optional): Filter by vendor
- `limit` (optional): Results per page (default: 100)
- `offset` (optional): Pagination offset (default: 0)

**Response:**
```json
{
  "total": 15,
  "limit": 100,
  "offset": 0,
  "devices": [
    {
      "ip_address": "192.168.1.100",
      "vendor": "Hikvision",
      "model": "DS-2CD2143G0-I",
      "firmware_version": "V5.4.41",
      "services": ["http", "https", "rtsp"],
      "risk_score": 85,
      "intelligence": {
        "device_type": "IP Camera",
        "platform": "Linux",
        "firmware_eol": false
      }
    }
  ]
}
```

#### Get Device by IP
```
GET /devices/192.168.1.100
```

#### Get Device Findings
```
GET /devices/192.168.1.100/findings
```

---

## Integration Examples

### Python - Fetch Critical Findings
```python
import requests

api_url = "http://localhost:5000/api/v1"

# Get critical findings
response = requests.get(
    f"{api_url}/findings",
    params={"severity": "critical", "limit": 50}
)

findings = response.json()["findings"]
for finding in findings:
    print(f"{finding['device_ip']}: {finding['title']}")
```

### Python - Search Assets by Risk
```python
import requests

api_url = "http://localhost:5000/api/v1"

# Search high-risk assets
response = requests.post(
    f"{api_url}/assets/search",
    json={
        "risk_range": {"min": 80, "max": 100},
        "status": "active"
    }
)

assets = response.json()["assets"]
print(f"Found {len(assets)} high-risk assets")
```

### cURL - Get System Stats
```bash
curl -X GET http://localhost:5000/api/v1/stats
```

### cURL - Search Findings by CVE
```bash
curl -X GET "http://localhost:5000/api/v1/findings/by-cve/CVE-2018-10088"
```

### cURL - Export Report Data
```bash
curl -X GET "http://localhost:5000/api/v1/reports/8" | jq .
```

---

## Error Responses

### 404 Not Found
```json
{
  "error": "Report not found"
}
```

### 400 Bad Request
```json
{
  "error": "Invalid query parameters"
}
```

---

## Rate Limiting

Currently no rate limiting is implemented. For production, implement rate limiting (e.g., 100 requests/minute per IP).

---

## Pagination

All list endpoints support pagination via `limit` and `offset` parameters:

```
GET /findings?limit=50&offset=100
```

Returns findings 100-150.

---

## Filtering

Most endpoints support filtering via query parameters or POST body:

**Query Parameters:**
```
GET /findings?severity=critical&device_ip=192.168.1.100
```

**POST Body:**
```json
POST /findings/search
{
  "keyword": "default",
  "severity": "critical",
  "cve_id": "CVE-2018-10088"
}
```

---

## SIEM Integration

### Splunk
```
[securevision]
url = http://localhost:5000/api/v1/findings
interval = 3600
sourcetype = securevision:findings
```

### ELK Stack
```
input {
  http_poller {
    urls => {
      securevision => "http://localhost:5000/api/v1/findings"
    }
    request_timeout => 60
    interval => 3600
  }
}
```

### Generic Webhook
Configure your SIEM to POST to:
```
POST /api/v1/reports/<report_id>/findings
```

---

## Changelog

### v1.0 (2026-07-21)
- Initial release
- Assets, Findings, Reports, Devices endpoints
- Search and filtering capabilities
- Health check and statistics endpoints
