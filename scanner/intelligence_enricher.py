from __future__ import annotations

from typing import Dict, List


# ---------------------------------------------------------------------------
# Finding enrichment knowledge base
# Maps finding types to detailed intelligence context
# ---------------------------------------------------------------------------

_FINDING_INTELLIGENCE: Dict[str, Dict] = {
    "telnet_exposed": {
        "technical_explanation": (
            "Telnet is an unencrypted remote access protocol that transmits all data, "
            "including credentials, in plaintext over the network. Any attacker with "
            "network access can intercept and read this traffic."
        ),
        "business_impact": (
            "Compromise of this device allows unauthorized remote access, credential theft, "
            "and potential lateral movement to other network segments."
        ),
        "exploitability": "network",
        "attack_scenario": (
            "An attacker on the same network segment uses a packet sniffer to capture "
            "Telnet traffic, extracting administrator credentials. They then use these "
            "credentials to gain full device control."
        ),
        "risk_justification": (
            "CVSS 7.5 — Network-adjacent attacker can passively intercept credentials "
            "without authentication. Credentials provide full device access."
        ),
        "cve_tags": ["CVE-2023-28771"],
    },
    "rtsp_unauthenticated": {
        "technical_explanation": (
            "RTSP (Real Time Streaming Protocol) may be configured to allow stream access "
            "without authentication. This exposes live video feeds to any network-accessible attacker."
        ),
        "business_impact": (
            "Unauthorized access to live video feeds compromises physical security monitoring "
            "and may expose sensitive areas or activities."
        ),
        "exploitability": "network",
        "attack_scenario": (
            "An attacker discovers the RTSP stream URL and connects directly to view live video "
            "without providing credentials. They can monitor facility operations in real-time."
        ),
        "risk_justification": (
            "CVSS 7.5 — Network attacker can access video streams without authentication. "
            "Exposes sensitive surveillance data."
        ),
        "cve_tags": ["CVE-2020-25078"],
    },
    "onvif_exposed": {
        "technical_explanation": (
            "ONVIF (Open Network Video Interface Forum) is a device management protocol that "
            "allows discovery and control of surveillance devices. Weak or default credentials "
            "on ONVIF interfaces enable unauthorized device management."
        ),
        "business_impact": (
            "Unauthorized ONVIF access allows attackers to modify device settings, disable "
            "recording, redirect streams, or use the device as a pivot point for network attacks."
        ),
        "exploitability": "network",
        "attack_scenario": (
            "An attacker uses default ONVIF credentials to connect to the device management "
            "interface. They disable recording, modify stream settings, or add a backdoor account."
        ),
        "risk_justification": (
            "CVSS 9.8 — Network attacker can gain full device control via default credentials. "
            "ONVIF provides complete management access."
        ),
        "cve_tags": ["CVE-2018-10088"],
    },
    "http_unencrypted": {
        "technical_explanation": (
            "HTTP web interfaces transmit session tokens and credentials without encryption. "
            "An attacker can intercept these tokens and hijack authenticated sessions."
        ),
        "business_impact": (
            "Session hijacking allows unauthorized access to device configuration and control "
            "without needing to know the actual password."
        ),
        "exploitability": "network",
        "attack_scenario": (
            "An attacker on the network intercepts HTTP traffic and extracts the session cookie. "
            "They replay this cookie to gain authenticated access to the web interface."
        ),
        "risk_justification": (
            "CVSS 5.0 — Network attacker can intercept session tokens. Requires active "
            "interception but provides authenticated access."
        ),
        "cve_tags": [],
    },
    "ftp_exposed": {
        "technical_explanation": (
            "FTP (File Transfer Protocol) transmits credentials and file contents in plaintext. "
            "Attackers can intercept credentials and access stored files including recordings."
        ),
        "business_impact": (
            "Unauthorized FTP access exposes stored video recordings, configuration files, "
            "and may allow deletion or modification of evidence."
        ),
        "exploitability": "network",
        "attack_scenario": (
            "An attacker captures FTP credentials via packet sniffing. They connect to the FTP "
            "server and download all stored video recordings for analysis or deletion."
        ),
        "risk_justification": (
            "CVSS 6.5 — Network attacker can intercept credentials and access file storage. "
            "Exposes recorded video and configuration data."
        ),
        "cve_tags": ["CVE-2019-11001"],
    },
    "default_credentials": {
        "technical_explanation": (
            "Devices shipped with default credentials that are publicly known and documented. "
            "If not changed, any attacker can gain immediate access without password guessing."
        ),
        "business_impact": (
            "Default credentials provide immediate full device access to any attacker with "
            "network connectivity. No exploitation required."
        ),
        "exploitability": "network",
        "attack_scenario": (
            "An attacker discovers the device model and looks up default credentials online. "
            "They connect and gain full administrative access immediately."
        ),
        "risk_justification": (
            "CVSS 9.8 — Network attacker gains full device control with zero effort. "
            "Default credentials are trivial to discover and use."
        ),
        "cve_tags": [],
    },
    "outdated_firmware": {
        "technical_explanation": (
            "Outdated firmware versions contain known security vulnerabilities that have been "
            "publicly disclosed and may have working exploits available."
        ),
        "business_impact": (
            "Known vulnerabilities in outdated firmware can be exploited to gain device access, "
            "disable security features, or use the device as an attack platform."
        ),
        "exploitability": "network",
        "attack_scenario": (
            "An attacker identifies the firmware version and searches for known CVEs. They find "
            "a public exploit and use it to gain remote code execution on the device."
        ),
        "risk_justification": (
            "CVSS varies by CVE — Outdated firmware is known to contain exploitable vulnerabilities. "
            "Upgrade path is available and should be prioritized."
        ),
        "cve_tags": [],
    },
}


def enrich_finding(finding: Dict, device_context: Dict = None) -> Dict:
    """
    Enrich a finding with intelligence context.
    
    Adds technical explanation, business impact, exploitability, attack scenario,
    risk justification, and CVE references.
    """
    finding_type = _infer_finding_type(finding)
    intelligence = _FINDING_INTELLIGENCE.get(finding_type, {})

    enriched = {**finding}
    enriched.update({
        "technical_explanation": intelligence.get(
            "technical_explanation",
            "See description for technical details.",
        ),
        "business_impact": intelligence.get(
            "business_impact",
            "This finding may impact device security and operational integrity.",
        ),
        "exploitability": intelligence.get("exploitability", "unknown"),
        "attack_scenario": intelligence.get(
            "attack_scenario",
            "An attacker could exploit this vulnerability to gain unauthorized access.",
        ),
        "risk_justification": intelligence.get(
            "risk_justification",
            f"Severity: {finding.get('severity', 'unknown')}",
        ),
        "cve_references": intelligence.get("cve_tags", []),
        "references": intelligence.get("references", []),
    })

    return enriched


def enrich_findings(findings: List[Dict], device_context: Dict = None) -> List[Dict]:
    """Enrich a list of findings with intelligence context."""
    return [enrich_finding(f, device_context) for f in findings]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _infer_finding_type(finding: Dict) -> str:
    """Infer finding type from title and description."""
    title = finding.get("title", "").lower()
    description = finding.get("description", "").lower()
    combined = f"{title} {description}"

    if "telnet" in combined:
        return "telnet_exposed"
    if "rtsp" in combined and "unauthenticated" in combined:
        return "rtsp_unauthenticated"
    if "rtsp" in combined:
        return "rtsp_unauthenticated"
    if "onvif" in combined:
        return "onvif_exposed"
    if "http" in combined and "https" not in combined:
        return "http_unencrypted"
    if "ftp" in combined:
        return "ftp_exposed"
    if "default" in combined and "credential" in combined:
        return "default_credentials"
    if "firmware" in combined and ("outdated" in combined or "old" in combined):
        return "outdated_firmware"

    return "unknown"
