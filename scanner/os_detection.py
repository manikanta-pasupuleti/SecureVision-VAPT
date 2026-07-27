from __future__ import annotations

from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Vendor device profile knowledge base
# Maps vendor + service patterns to device type, platform, architecture
# ---------------------------------------------------------------------------

_VENDOR_PROFILES: Dict[str, Dict] = {
    "hikvision": {
        "device_types": {
            "default": "IP Camera",
            "service_hints": {
                "dvr":  ["rtsp", "http", "onvif"],
                "nvr":  ["rtsp", "http", "onvif", "https"],
                "ipc":  ["rtsp", "http"],
            },
        },
        "platform": "Embedded Linux",
        "architecture": "ARM",
        "os_indicators": ["hikvision", "ds-", "ivms"],
    },
    "dahua": {
        "device_types": {
            "default": "IP Camera",
            "service_hints": {
                "dvr":  ["rtsp", "http", "telnet"],
                "nvr":  ["rtsp", "http", "onvif"],
                "ipc":  ["rtsp", "http"],
            },
        },
        "platform": "Embedded Linux",
        "architecture": "MIPS",
        "os_indicators": ["dahua", "dh-", "ipc-hfw"],
    },
    "axis": {
        "device_types": {
            "default": "IP Camera",
            "service_hints": {
                "ptz":  ["http", "https", "onvif", "rtsp"],
                "ipc":  ["http", "https", "onvif"],
            },
        },
        "platform": "AXIS OS (Linux-based)",
        "architecture": "ARM",
        "os_indicators": ["axis", "m30", "vapix"],
    },
    "uniview": {
        "device_types": {
            "default": "IP Camera",
            "service_hints": {
                "nvr":  ["rtsp", "http", "onvif"],
                "ipc":  ["rtsp", "http", "telnet"],
            },
        },
        "platform": "Embedded Linux",
        "architecture": "ARM",
        "os_indicators": ["uniview", "ipc23"],
    },
}

# Service-based device type heuristics (vendor-agnostic fallback)
_SERVICE_DEVICE_HINTS: List[Dict] = [
    {
        "services":    ["rtsp", "http", "telnet", "onvif"],
        "device_type": "DVR/NVR",
        "confidence":  "medium",
    },
    {
        "services":    ["rtsp", "http", "onvif"],
        "device_type": "IP Camera",
        "confidence":  "medium",
    },
    {
        "services":    ["rtsp", "http"],
        "device_type": "IP Camera",
        "confidence":  "low",
    },
    {
        "services":    ["ftp", "http", "telnet"],
        "device_type": "DVR",
        "confidence":  "medium",
    },
    {
        "services":    ["http", "https"],
        "device_type": "Network Device",
        "confidence":  "low",
    },
]


def detect_os(vendor: str, services: List[str], firmware_version: str = "") -> Dict:
    """
    Detect device type, platform, and OS context from vendor + service profile.

    Returns a structured result with device_type, platform, architecture,
    confidence level, and the indicators that led to the conclusion.
    """
    vendor_key = _find_vendor(vendor)
    services_lower = [s.lower() for s in services]
    indicators = []

    if vendor_key:
        profile = _VENDOR_PROFILES[vendor_key]
        device_type = _infer_device_type(profile, services_lower)
        platform = profile["platform"]
        architecture = profile["architecture"]
        confidence = "high"

        indicators.append(f"{vendor} vendor profile matched")
        indicators.extend(_collect_service_indicators(services_lower))

        if firmware_version:
            indicators.append(f"Firmware version {firmware_version} identified")

    else:
        device_type, confidence = _fallback_device_type(services_lower)
        platform = "Embedded Linux"
        architecture = "Unknown"
        indicators.append("Vendor not in database — service-based detection used")
        indicators.extend(_collect_service_indicators(services_lower))

    return {
        "device_type": device_type,
        "platform": platform,
        "architecture": architecture,
        "confidence": confidence,
        "indicators": indicators,
    }


def get_attack_surface(device_type: str, services: List[str]) -> List[str]:
    """
    Return a list of attack surface notes based on device type and services.
    Used by the recommendation engine to tailor guidance.
    """
    surface = []
    services_lower = [s.lower() for s in services]

    if "telnet" in services_lower:
        surface.append("Unencrypted remote management via Telnet (port 23)")
    if "rtsp" in services_lower:
        surface.append("Live video stream accessible via RTSP (port 554)")
    if "onvif" in services_lower:
        surface.append("Device management and discovery via ONVIF (port 80/8080)")
    if "ftp" in services_lower:
        surface.append("File transfer exposed via FTP (port 21)")
    if "http" in services_lower and "https" not in services_lower:
        surface.append("Web interface served over unencrypted HTTP")
    if "https" in services_lower:
        surface.append("Web interface served over HTTPS")

    if device_type in ("DVR", "DVR/NVR", "NVR"):
        surface.append("Multi-channel recording device — compromise affects all connected cameras")
    if device_type == "IP Camera":
        surface.append("Single-channel device — direct video feed exposure risk")

    return surface


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_vendor(vendor: str) -> Optional[str]:
    """Case-insensitive vendor lookup."""
    for key in _VENDOR_PROFILES:
        if key.lower() == vendor.lower():
            return key
    return None


def _infer_device_type(profile: Dict, services: List[str]) -> str:
    """
    Match service set against vendor-specific device type hints.
    Falls back to vendor default if no strong match found.
    """
    hints = profile["device_types"]["service_hints"]
    best_match = None
    best_score = 0

    for dtype, required_services in hints.items():
        score = sum(1 for s in required_services if s in services)
        if score > best_score:
            best_score = score
            best_match = dtype

    type_labels = {
        "dvr": "DVR",
        "nvr": "NVR",
        "ipc": "IP Camera",
        "ptz": "PTZ Camera",
    }

    if best_match and best_score >= 2:
        return type_labels.get(best_match, profile["device_types"]["default"])

    return profile["device_types"]["default"]


def _fallback_device_type(services: List[str]) -> tuple:
    """Vendor-agnostic device type detection based on service patterns."""
    best_match = ("Unknown Device", "low")
    best_score = 0

    for hint in _SERVICE_DEVICE_HINTS:
        score = sum(1 for s in hint["services"] if s in services)
        if score > best_score:
            best_score = score
            best_match = (hint["device_type"], hint["confidence"])

    return best_match


def _collect_service_indicators(services: List[str]) -> List[str]:
    """Build human-readable indicator strings from detected services."""
    labels = {
        "telnet": "Telnet service present",
        "rtsp":   "RTSP stream detected",
        "onvif":  "ONVIF interface detected",
        "http":   "HTTP web interface detected",
        "https":  "HTTPS web interface detected",
        "ftp":    "FTP service detected",
    }
    return [labels[s] for s in services if s in labels]
