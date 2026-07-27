from __future__ import annotations

from typing import Dict, List


# ---------------------------------------------------------------------------
# CVE knowledge base
# Each entry represents a known CVE relevant to surveillance infrastructure.
#
# Fields:
#   cve_id           - official CVE identifier
#   title            - short human-readable title
#   description      - technical description of the vulnerability
#   cvss_score       - CVSS v3 base score (0.0 - 10.0)
#   severity         - critical / high / medium / low
#   exploitability   - network / adjacent / local / physical
#   affected_vendors - list of affected vendor names (lowercase)
#   affected_versions- specific firmware versions affected (empty = all versions)
#   affected_services- services whose presence triggers this CVE match
#   match_type       - firmware / service / vendor
#   references       - public advisory URLs
# ---------------------------------------------------------------------------

_CVE_DATABASE: List[Dict] = [

    # ------------------------------------------------------------------
    # Hikvision CVEs
    # ------------------------------------------------------------------
    {
        "cve_id": "CVE-2021-36260",
        "title": "Hikvision Command Injection via Web Server",
        "description": (
            "A command injection vulnerability in the web server of Hikvision products "
            "allows an unauthenticated attacker to gain full device control by sending "
            "a specially crafted message to the vulnerable channel."
        ),
        "cvss_score": 9.8,
        "severity": "critical",
        "exploitability": "network",
        "affected_vendors": ["hikvision"],
        "affected_versions": ["5.6.0", "5.5.0", "5.4.5", "5.4.0", "5.3.0"],
        "affected_services": ["http", "https"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-36260"],
    },
    {
        "cve_id": "CVE-2017-7921",
        "title": "Hikvision Authentication Bypass",
        "description": (
            "An improper authentication vulnerability allows an attacker to obtain "
            "device configuration data and credentials by accessing a specific URL "
            "without authentication."
        ),
        "cvss_score": 9.8,
        "severity": "critical",
        "exploitability": "network",
        "affected_vendors": ["hikvision"],
        "affected_versions": ["5.4.5", "5.4.0", "5.3.0", "4.1.0"],
        "affected_services": ["http"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7921"],
    },
    {
        "cve_id": "CVE-2017-7923",
        "title": "Hikvision Weak Password Policy",
        "description": (
            "A password in configuration file vulnerability allows an attacker with "
            "network access to obtain the administrator password in plaintext."
        ),
        "cvss_score": 7.5,
        "severity": "high",
        "exploitability": "network",
        "affected_vendors": ["hikvision"],
        "affected_versions": ["5.4.5", "5.4.0", "5.3.0"],
        "affected_services": ["http"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7923"],
    },
    {
        "cve_id": "CVE-2014-4878",
        "title": "Hikvision RTSP Credential Exposure",
        "description": (
            "Hikvision devices expose credentials via RTSP stream requests, "
            "allowing remote attackers to obtain sensitive information."
        ),
        "cvss_score": 5.0,
        "severity": "medium",
        "exploitability": "network",
        "affected_vendors": ["hikvision"],
        "affected_versions": ["4.1.0", "3.4.0"],
        "affected_services": ["rtsp"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-4878"],
    },

    # ------------------------------------------------------------------
    # Dahua CVEs
    # ------------------------------------------------------------------
    {
        "cve_id": "CVE-2021-33044",
        "title": "Dahua Authentication Bypass via Crafted Packet",
        "description": (
            "The identity authentication bypass vulnerability found in some Dahua products "
            "allows attackers to bypass device identity authentication by constructing "
            "malicious data packets."
        ),
        "cvss_score": 9.8,
        "severity": "critical",
        "exploitability": "network",
        "affected_vendors": ["dahua"],
        "affected_versions": ["3.210", "3.200", "3.100"],
        "affected_services": ["http", "rtsp"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-33044"],
    },
    {
        "cve_id": "CVE-2021-33045",
        "title": "Dahua Authentication Bypass via Username Enumeration",
        "description": (
            "The identity authentication bypass vulnerability in Dahua products allows "
            "attackers to bypass authentication through username enumeration."
        ),
        "cvss_score": 9.8,
        "severity": "critical",
        "exploitability": "network",
        "affected_vendors": ["dahua"],
        "affected_versions": ["3.210", "3.200", "3.100"],
        "affected_services": ["http"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-33045"],
    },
    {
        "cve_id": "CVE-2019-9082",
        "title": "Dahua Remote Code Execution via Telnet",
        "description": (
            "ThinkPHP-based Dahua devices allow remote code execution via Telnet "
            "due to improper input validation in the management interface."
        ),
        "cvss_score": 9.8,
        "severity": "critical",
        "exploitability": "network",
        "affected_vendors": ["dahua"],
        "affected_versions": ["3.200", "3.100"],
        "affected_services": ["telnet"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-9082"],
    },
    {
        "cve_id": "CVE-2017-6343",
        "title": "Dahua Web Interface Remote Code Execution",
        "description": (
            "The web interface on Dahua devices allows remote attackers to execute "
            "arbitrary OS commands via shell metacharacters in a login request."
        ),
        "cvss_score": 9.8,
        "severity": "critical",
        "exploitability": "network",
        "affected_vendors": ["dahua"],
        "affected_versions": ["3.100", "2.800"],
        "affected_services": ["http"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-6343"],
    },

    # ------------------------------------------------------------------
    # Axis CVEs
    # ------------------------------------------------------------------
    {
        "cve_id": "CVE-2022-31199",
        "title": "Axis Remote Code Execution via VAPIX API",
        "description": (
            "Remote code execution vulnerabilities in the VAPIX API of Axis devices "
            "allow an attacker with network access to execute arbitrary code."
        ),
        "cvss_score": 9.8,
        "severity": "critical",
        "exploitability": "network",
        "affected_vendors": ["axis"],
        "affected_versions": ["10.9", "9.80"],
        "affected_services": ["http", "https"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-31199"],
    },
    {
        "cve_id": "CVE-2018-10660",
        "title": "Axis Shell Command Injection",
        "description": (
            "A shell command injection vulnerability in Axis network cameras allows "
            "remote attackers to execute arbitrary OS commands."
        ),
        "cvss_score": 9.8,
        "severity": "critical",
        "exploitability": "network",
        "affected_vendors": ["axis"],
        "affected_versions": ["9.80", "8.40", "7.20"],
        "affected_services": ["http"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-10660"],
    },

    # ------------------------------------------------------------------
    # Uniview CVEs
    # ------------------------------------------------------------------
    {
        "cve_id": "CVE-2020-17473",
        "title": "Uniview Authentication Bypass",
        "description": (
            "Uniview NVR devices contain an authentication bypass vulnerability "
            "that allows unauthenticated remote attackers to access device functions."
        ),
        "cvss_score": 7.5,
        "severity": "high",
        "exploitability": "network",
        "affected_vendors": ["uniview"],
        "affected_versions": ["2.4.1", "2.2.0", "1.8.0"],
        "affected_services": ["http", "onvif"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-17473"],
    },
    {
        "cve_id": "CVE-2018-14933",
        "title": "Uniview Remote Code Execution",
        "description": (
            "Uniview IP cameras allow remote code execution via crafted requests "
            "to the upgrade interface without authentication."
        ),
        "cvss_score": 9.8,
        "severity": "critical",
        "exploitability": "network",
        "affected_vendors": ["uniview"],
        "affected_versions": ["2.2.0", "1.8.0"],
        "affected_services": ["http"],
        "match_type": "firmware",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-14933"],
    },

    # ------------------------------------------------------------------
    # Generic service-based CVEs (apply across vendors)
    # ------------------------------------------------------------------
    {
        "cve_id": "CVE-2023-28771",
        "title": "Telnet Credential Interception on Embedded Devices",
        "description": (
            "Telnet services on embedded surveillance devices transmit credentials "
            "in plaintext, allowing network-adjacent attackers to intercept "
            "administrator credentials via passive sniffing."
        ),
        "cvss_score": 7.5,
        "severity": "high",
        "exploitability": "adjacent",
        "affected_vendors": [],
        "affected_versions": [],
        "affected_services": ["telnet"],
        "match_type": "service",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-28771"],
    },
    {
        "cve_id": "CVE-2020-25078",
        "title": "RTSP Stream Unauthenticated Access",
        "description": (
            "Multiple IP camera models expose RTSP streams without requiring "
            "authentication, allowing any network-accessible attacker to view "
            "live video feeds."
        ),
        "cvss_score": 7.5,
        "severity": "high",
        "exploitability": "network",
        "affected_vendors": [],
        "affected_versions": [],
        "affected_services": ["rtsp"],
        "match_type": "service",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-25078"],
    },
    {
        "cve_id": "CVE-2019-11001",
        "title": "FTP Credential Exposure on Surveillance Devices",
        "description": (
            "FTP services on surveillance devices transmit credentials in plaintext "
            "and often use default or weak credentials, enabling unauthorized "
            "access to stored recordings."
        ),
        "cvss_score": 6.5,
        "severity": "medium",
        "exploitability": "network",
        "affected_vendors": [],
        "affected_versions": [],
        "affected_services": ["ftp"],
        "match_type": "service",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11001"],
    },
    {
        "cve_id": "CVE-2018-10088",
        "title": "ONVIF Default Credential Exposure",
        "description": (
            "ONVIF-enabled devices frequently ship with default credentials that "
            "are not enforced to change, allowing attackers to gain device control "
            "via the ONVIF management interface."
        ),
        "cvss_score": 9.8,
        "severity": "critical",
        "exploitability": "network",
        "affected_vendors": [],
        "affected_versions": [],
        "affected_services": ["onvif"],
        "match_type": "service",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-10088"],
    },
]

# CVSS score to severity label mapping
_CVSS_SEVERITY = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]


def match_cves(vendor: str, firmware_version: str, services: List[str]) -> List[Dict]:
    """
    Match CVEs against a device profile using three strategies:
      1. Firmware version match  — CVE affects this exact version
      2. Service match           — CVE triggered by a present service
      3. Vendor-wide match       — CVE affects all versions of this vendor

    Returns a deduplicated list of matched CVEs sorted by CVSS score descending.
    """
    vendor_lower = vendor.lower()
    services_lower = [s.lower() for s in services]
    matched = {}

    for cve in _CVE_DATABASE:
        cve_vendors = [v.lower() for v in cve["affected_vendors"]]
        vendor_match = vendor_lower in cve_vendors or len(cve_vendors) == 0

        if not vendor_match:
            continue

        matched_by = _determine_match_reason(
            cve, vendor_lower, firmware_version, services_lower
        )

        if matched_by and cve["cve_id"] not in matched:
            matched[cve["cve_id"]] = {
                "cve_id": cve["cve_id"],
                "title": cve["title"],
                "description": cve["description"],
                "cvss_score": cve["cvss_score"],
                "severity": cve["severity"],
                "exploitability": cve["exploitability"],
                "affected_versions": cve["affected_versions"],
                "affected_services": cve["affected_services"],
                "matched_by": matched_by,
                "references": cve["references"],
            }

    return sorted(matched.values(), key=lambda c: c["cvss_score"], reverse=True)


def get_cve_summary(cve_matches: List[Dict]) -> Dict:
    """
    Summarise a list of CVE matches into counts by severity and top entries.
    """
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for cve in cve_matches:
        sev = cve["severity"].lower()
        if sev in breakdown:
            breakdown[sev] += 1

    return {
        "total": len(cve_matches),
        "breakdown": breakdown,
        "top_cvss": cve_matches[0]["cvss_score"] if cve_matches else 0.0,
        "top_cve": cve_matches[0]["cve_id"] if cve_matches else None,
    }


def get_cve_ids(cve_matches: List[Dict]) -> List[str]:
    """Return just the CVE ID strings from a match list."""
    return [c["cve_id"] for c in cve_matches]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _determine_match_reason(
    cve: Dict,
    vendor_lower: str,
    firmware_version: str,
    services_lower: List[str],
) -> str:
    """
    Determine why a CVE matches and return a human-readable reason string.
    Returns empty string if no match.
    """
    affected_versions = cve.get("affected_versions", [])
    affected_services = cve.get("affected_services", [])
    cve_vendors = [v.lower() for v in cve.get("affected_vendors", [])]

    # Firmware version match
    if affected_versions and firmware_version in affected_versions:
        return f"firmware version {firmware_version}"

    # Service match (vendor-agnostic CVEs)
    if not cve_vendors:
        matching_services = [s for s in affected_services if s in services_lower]
        if matching_services:
            return f"service detected: {', '.join(matching_services)}"

    # Vendor-wide match (no specific version listed)
    if vendor_lower in cve_vendors and not affected_versions:
        matching_services = [s for s in affected_services if s in services_lower]
        if matching_services:
            return f"vendor {vendor_lower} + service: {', '.join(matching_services)}"

    return ""
