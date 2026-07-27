from __future__ import annotations

from typing import Dict, List


# ---------------------------------------------------------------------------
# Vendor-specific remediation steps
# ---------------------------------------------------------------------------

_VENDOR_STEPS: Dict[str, Dict[str, str]] = {
    "hikvision": {
        "telnet":   "Navigate to Configuration > Network > Advanced Settings > Other and disable Telnet.",
        "ftp":      "Navigate to Configuration > Network > Advanced Settings > FTP and disable the service.",
        "http":     "Navigate to Configuration > Network > Advanced Settings and enable HTTPS-only access.",
        "onvif":    "Navigate to Configuration > Network > Advanced Settings > Integration Protocol and restrict ONVIF access.",
        "rtsp":     "Navigate to Configuration > Network > Advanced Settings > RTSP and enable RTSP authentication.",
        "firmware": "Download latest firmware from hikvision.com/en/support/download/firmware/ and apply via Configuration > Maintenance > Upgrade.",
        "password": "Navigate to Configuration > System > User Management and change all default passwords.",
    },
    "dahua": {
        "telnet":   "Navigate to Setting > Network > TCP/IP > Telnet and disable the service.",
        "ftp":      "Navigate to Setting > Storage > FTP and disable FTP if not required.",
        "http":     "Navigate to Setting > Network > HTTPS and enforce HTTPS-only access.",
        "onvif":    "Navigate to Setting > System > ONVIF and restrict or disable ONVIF access.",
        "rtsp":     "Navigate to Setting > Network > RTSP and enable digest authentication for stream access.",
        "firmware": "Download latest firmware from dahuasecurity.com/support/downloadCenter/ and apply via Setting > System > Upgrade.",
        "password": "Navigate to Setting > System > Account and change all default credentials immediately.",
    },
    "axis": {
        "telnet":   "Access the AXIS web interface and navigate to System > Plain Config > Network to disable Telnet.",
        "ftp":      "Navigate to System > Plain Config > FTP and disable the FTP service.",
        "http":     "Navigate to System > Security > HTTPS and enforce HTTPS-only connections.",
        "onvif":    "Navigate to System > Plain Config > WebService and restrict ONVIF access to trusted hosts.",
        "rtsp":     "Navigate to System > Security > Certificates and enforce RTSP authentication.",
        "firmware": "Download latest firmware from axis.com/support/firmware and apply via System > Maintenance > Firmware upgrade.",
        "password": "Navigate to System > Users and change the root password and all default credentials.",
    },
    "uniview": {
        "telnet":   "Navigate to Configuration > Network > Port and disable Telnet.",
        "ftp":      "Navigate to Configuration > Network > FTP and disable the service.",
        "http":     "Navigate to Configuration > Network > HTTPS and enforce HTTPS-only access.",
        "onvif":    "Navigate to Configuration > Network > Integration Protocol and restrict ONVIF access.",
        "rtsp":     "Navigate to Configuration > Network > RTSP and enable authentication for stream access.",
        "firmware": "Download latest firmware from uniview.com/Support/ and apply via Configuration > System > Maintenance.",
        "password": "Navigate to Configuration > System > User Management and change all default credentials.",
    },
}

_GENERIC_STEPS: Dict[str, str] = {
    "telnet":   "Access the device management interface and disable Telnet. Enable SSH if remote access is required.",
    "ftp":      "Access the device management interface and disable FTP. Use SFTP as a secure alternative.",
    "http":     "Access the device management interface and enforce HTTPS-only access. Disable plain HTTP.",
    "onvif":    "Restrict ONVIF access to trusted management hosts only. Change default ONVIF credentials.",
    "rtsp":     "Enable RTSP authentication and restrict stream access to authorised clients via network ACLs.",
    "firmware": "Visit the vendor support portal and download the latest firmware. Apply via the device management interface.",
    "password": "Change all default credentials immediately. Use unique strong passwords per device.",
}

_PRIORITY_LABELS = [
    (9.0, "IMMEDIATE"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
]

_FIX_TIMES: Dict[str, str] = {
    "telnet":   "5-10 minutes",
    "ftp":      "5-10 minutes",
    "http":     "10-15 minutes",
    "onvif":    "10-15 minutes",
    "rtsp":     "10-15 minutes",
    "firmware": "20-45 minutes depending on device reboot time",
    "password": "5-10 minutes per device",
    "cve":      "Varies — follow CVE advisory for patch or workaround",
}

_SERVICE_CVSS: Dict[str, float] = {
    "telnet": 7.5, "ftp": 6.5, "onvif": 6.0,
    "http": 5.0, "rtsp": 5.0, "password": 9.0,
}

_SERVICE_TITLES: Dict[str, str] = {
    "telnet":   "Disable Telnet — unencrypted remote access is active",
    "ftp":      "Disable FTP — unencrypted file transfer is active",
    "http":     "Enforce HTTPS — web interface is served over plain HTTP",
    "onvif":    "Restrict ONVIF — device management interface is exposed",
    "rtsp":     "Secure RTSP — video stream may be accessible without authentication",
    "password": "Change default credentials — vendor defaults must be replaced",
}

_SERVICE_DESCRIPTIONS: Dict[str, str] = {
    "telnet":   "Telnet transmits all data including credentials in plaintext over the network.",
    "ftp":      "FTP transmits credentials and file contents in plaintext over the network.",
    "http":     "HTTP web interfaces expose session tokens and credentials without encryption.",
    "onvif":    "ONVIF interfaces allow device discovery and control — restrict to trusted hosts.",
    "rtsp":     "RTSP streams may be accessible without authentication on default configurations.",
    "password": "Default vendor credentials are publicly known and actively used in attacks.",
}

_DEVICE_IMPACTS: Dict[str, str] = {
    "DVR":          "Compromise of this DVR exposes all connected camera feeds and stored recordings.",
    "NVR":          "Compromise of this NVR exposes all connected camera feeds and stored recordings.",
    "DVR/NVR":      "Compromise of this device exposes all connected camera feeds and stored recordings.",
    "IP Camera":    "Compromise of this camera exposes the live video feed and device credentials.",
    "PTZ Camera":   "Compromise of this PTZ camera allows feed access and remote pan/tilt/zoom control.",
    "Network Device": "Compromise of this device may allow lateral movement across the network segment.",
}


def generate_recommendations(
    vendor: str,
    device_type: str,
    services: List[str],
    cve_matches: List[Dict],
    firmware_analysis: Dict,
) -> List[Dict]:
    """
    Generate a prioritised list of actionable recommendations for a device.
    Combines CVE-based, firmware-based, and service-based guidance.
    Returns deduplicated list sorted by priority.
    """
    recommendations = []
    seen = set()

    for cve in cve_matches:
        key = f"cve:{cve['cve_id']}"
        if key not in seen:
            seen.add(key)
            recommendations.append(_cve_rec(cve, vendor, device_type))

    if firmware_analysis.get("is_outdated") or firmware_analysis.get("is_eol"):
        key = "firmware:upgrade"
        if key not in seen:
            seen.add(key)
            recommendations.append(_firmware_rec(vendor, device_type, firmware_analysis))

    for service in services:
        s = service.lower()
        key = f"service:{s}"
        if key not in seen and s in _GENERIC_STEPS:
            seen.add(key)
            recommendations.append(_service_rec(s, vendor, device_type))

    if "service:password" not in seen:
        recommendations.append(_service_rec("password", vendor, device_type))

    return sorted(recommendations, key=lambda r: r["priority_order"])


def get_top_recommendations(recommendations: List[Dict], limit: int = 3) -> List[Dict]:
    """Return the top N recommendations by priority."""
    return recommendations[:limit]


def get_recommendation_summary(recommendations: List[Dict]) -> Dict:
    """Summarise recommendations by priority level."""
    breakdown = {"IMMEDIATE": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for rec in recommendations:
        label = rec.get("priority", "LOW")
        if label in breakdown:
            breakdown[label] += 1
    total = len(recommendations)
    if total == 0:
        time_est = "No remediation required"
    elif total <= 2:
        time_est = "30-60 minutes"
    elif total <= 5:
        time_est = "1-2 hours"
    else:
        time_est = "2-4 hours depending on device count"
    return {"total": total, "breakdown": breakdown, "estimated_total_time": time_est}


# ---------------------------------------------------------------------------
# Internal builders
# ---------------------------------------------------------------------------

def _cve_rec(cve: Dict, vendor: str, device_type: str) -> Dict:
    cvss = cve["cvss_score"]
    priority, order = _priority(cvss)
    services = cve.get("affected_services", [])
    primary = services[0] if services else "firmware"
    return {
        "type": "cve",
        "priority": priority,
        "priority_order": order,
        "cve_id": cve["cve_id"],
        "title": f"Patch or mitigate {cve['cve_id']} — {cve['title']}",
        "description": cve["description"],
        "action": _vendor_step(vendor, primary),
        "business_impact": _impact(device_type, cvss),
        "exploitability": cve["exploitability"],
        "cvss_score": cvss,
        "estimated_fix_time": _FIX_TIMES.get(primary, _FIX_TIMES["cve"]),
        "references": cve.get("references", []),
    }


def _firmware_rec(vendor: str, device_type: str, fw: Dict) -> Dict:
    is_eol = fw.get("is_eol", False)
    current = fw.get("current_version", "unknown")
    latest = fw.get("latest_version", "unknown")
    cves = fw.get("cves", [])
    cvss = 8.0 if is_eol else 6.0
    priority, order = _priority(cvss)
    cve_note = f" Associated CVEs: {', '.join(cves)}." if cves else ""
    title = (
        f"Firmware {current} is end-of-life — upgrade to {latest} immediately"
        if is_eol else
        f"Firmware {current} is outdated — upgrade to {latest}"
    )
    return {
        "type": "firmware",
        "priority": priority,
        "priority_order": order,
        "cve_id": None,
        "title": title,
        "description": f"Device is running firmware {current}. Latest available is {latest}.{cve_note}",
        "action": _vendor_step(vendor, "firmware"),
        "business_impact": _impact(device_type, cvss),
        "exploitability": "network",
        "cvss_score": cvss,
        "estimated_fix_time": _FIX_TIMES["firmware"],
        "references": [fw.get("upgrade_path", "")],
    }


def _service_rec(service: str, vendor: str, device_type: str) -> Dict:
    cvss = _SERVICE_CVSS.get(service, 4.0)
    priority, order = _priority(cvss)
    return {
        "type": "service",
        "priority": priority,
        "priority_order": order,
        "cve_id": None,
        "title": _SERVICE_TITLES.get(service, f"Review {service} service configuration"),
        "description": _SERVICE_DESCRIPTIONS.get(service, f"The {service} service requires review."),
        "action": _vendor_step(vendor, service),
        "business_impact": _impact(device_type, cvss),
        "exploitability": "network",
        "cvss_score": cvss,
        "estimated_fix_time": _FIX_TIMES.get(service, "10-20 minutes"),
        "references": [],
    }


def _vendor_step(vendor: str, action: str) -> str:
    profile = _VENDOR_STEPS.get(vendor.lower(), {})
    return profile.get(action, _GENERIC_STEPS.get(action, "Consult vendor documentation."))


def _priority(cvss: float) -> tuple:
    for threshold, label in _PRIORITY_LABELS:
        if cvss >= threshold:
            order = ["IMMEDIATE", "HIGH", "MEDIUM", "LOW"].index(label)
            return label, order
    return "LOW", 3


def _impact(device_type: str, cvss: float) -> str:
    base = _DEVICE_IMPACTS.get(device_type, "Compromise of this device may expose sensitive data and network access.")
    if cvss >= 9.0:
        return f"CRITICAL IMPACT — {base} Full unauthenticated remote access is likely."
    if cvss >= 7.0:
        return f"HIGH IMPACT — {base}"
    return f"MODERATE IMPACT — {base}"
