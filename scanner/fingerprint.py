from __future__ import annotations

import json
import re
from hashlib import sha1
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
VENDORS_PATH = DATA_DIR / "vendors.json"
DEFAULT_CREDENTIALS_PATH = DATA_DIR / "default_credentials.json"

FALLBACK_VENDORS = [
    {"vendor": "Hikvision", "model_prefix": "DS-2CD", "firmware": "5.6.18", "default_services": ["http", "rtsp", "onvif"]},
    {"vendor": "Dahua", "model_prefix": "IPC-HFW", "firmware": "3.210", "default_services": ["http", "rtsp", "telnet"]},
    {"vendor": "Axis", "model_prefix": "M30", "firmware": "10.12", "default_services": ["http", "https", "onvif"]},
    {"vendor": "Uniview", "model_prefix": "IPC23", "firmware": "2.4.1", "default_services": ["http", "rtsp", "telnet"]},
]

# Vendor aliases are only accepted when a banner, CPE, hostname or other
# observed Nmap field actually contains the signature.
_VENDOR_SIGNATURES = {
    "hikvision": ("Hikvision", ("hikvision", "ds-2cd", "ds-2cv", "ivms")),
    "dahua": ("Dahua", ("dahua", "dahua technology", "dh-", "ipc-hfw")),
    "axis": ("Axis", ("axis communications", "axis camera", "vapix")),
    "uniview": ("Uniview", ("uniview", "ipc23")),
    "reolink": ("Reolink", ("reolink",)),
    "tp-link": ("TP-Link", ("tp-link", "tplink")),
    "netgear": ("NETGEAR", ("netgear",)),
    "cisco": ("Cisco", ("cisco",)),
    "mikrotik": ("MikroTik", ("mikrotik", "routeros")),
    "ubiquiti": ("Ubiquiti", ("ubiquiti", "unifi")),
}


def fingerprint_device(device: Dict[str, Any]) -> Dict[str, Any]:
    """Build a fingerprint without inventing vendor/model/firmware data."""
    nmap_ports = device.get("ports") or []
    scan_mode = str(device.get("scan_mode", "")).strip().lower()
    if nmap_ports or scan_mode == "live":
        return _fingerprint_from_nmap(device, nmap_ports)
    return _fingerprint_simulated(device)


def _fingerprint_from_nmap(
    device: Dict[str, Any],
    nmap_ports: List[Dict[str, Any]],
) -> Dict[str, Any]:
    services: List[str] = []
    evidence: List[str] = []
    products: List[str] = []
    versions: List[str] = []
    cpes: List[str] = []
    firmware_versions: List[str] = []

    for port in nmap_ports:
        if str(port.get("state", "")).lower() != "open":
            continue

        service = str(
            port.get("service") or port.get("nmap_service") or ""
        ).strip().lower()
        if service:
            services.append(service)

        product = str(port.get("product") or "").strip()
        version = str(port.get("version") or "").strip()
        cpe = str(port.get("cpe") or "").strip()
        extrainfo = str(port.get("extrainfo") or "").strip()

        if product:
            products.append(product)
            evidence.append(
                f"Nmap identified {service or 'service'} product: {product}"
            )
        if version:
            versions.append(version)
        if cpe:
            cpes.append(cpe)

        # Nmap sometimes reports device firmware explicitly in extrainfo.
        match = re.search(r"firmware\s*[:=]\s*([^,;\s]+)", extrainfo, re.I)
        if match:
            firmware_versions.append(match.group(1))

    services = _dedupe(services)
    products = _dedupe(products)
    versions = _dedupe(versions)
    cpes = _dedupe(cpes)
    firmware_versions = _dedupe(firmware_versions)

    evidence_blob = " | ".join(
        [
            str(device.get("hostname") or ""),
            str(device.get("hostnames") or ""),
            str(device.get("mac_vendor") or ""),
            str(device.get("os_guess") or ""),
            *products,
            *cpes,
        ]
    ).lower()

    vendor, vendor_evidence = _identify_vendor(evidence_blob)
    if vendor:
        evidence.append(vendor_evidence)
    else:
        evidence.append(
            "No vendor-specific Nmap banner, CPE, hostname, or OUI evidence"
        )

    model = _identify_model(vendor, evidence_blob)
    firmware = _identify_firmware(
        vendor,
        firmware_versions,
        cpes,
    )

    if model != "Unknown":
        evidence.append(f"Model identified from observed fingerprint: {model}")
    if firmware != "Unknown":
        evidence.append(f"Firmware version explicitly observed: {firmware}")

    device_type, confidence = _infer_device_type(services, vendor)
    if not vendor:
        confidence = "low"

    for service, message in (
        ("rtsp", "RTSP service detected"),
        ("onvif", "ONVIF service detected"),
        ("http", "HTTP web interface detected"),
        ("https", "HTTPS web interface detected"),
        ("ftp", "FTP service detected"),
    ):
        if service in services:
            evidence.append(message)

    return {
        **device,
        "services": services,
        "vendor": vendor or "Unknown",
        "model": model,
        "firmware_version": firmware,
        "auth_mode": "unknown",
        "default_credentials": _default_credentials_for(vendor) if vendor else [],
        "device_type": device_type,
        "detection_confidence": confidence,
        "fingerprint_evidence": _dedupe(evidence),
        "observed_products": products,
        "observed_versions": versions,
        "observed_cpes": cpes,
        "exposure_profile": {
            "has_telnet": "telnet" in services,
            "has_rtsp": "rtsp" in services,
            "has_onvif": "onvif" in services,
            "uses_https": "https" in services,
        },
        "fingerprint_source": "nmap",
        "scan_mode": "live",
    }


def _identify_vendor(blob: str) -> tuple[Optional[str], str]:
    for _, (display, signatures) in _VENDOR_SIGNATURES.items():
        for signature in signatures:
            if signature in blob:
                return display, f"Vendor evidence matched: {display} ({signature})"
    return None, ""


def _identify_model(vendor: Optional[str], blob: str) -> str:
    if not vendor:
        return "Unknown"

    for token in ("DS-2CD", "DS-2CV", "IPC-HFW", "IPC23", "M30"):
        index = blob.find(token.lower())
        if index >= 0:
            fragment = blob[index:index + 50].split()[0]
            return fragment.upper().strip(";,'\")")
    return "Unknown"


def _identify_firmware(
    vendor: Optional[str],
    firmware_versions: Iterable[str],
    cpes: Iterable[str],
) -> str:
    """Return firmware only when Nmap explicitly identifies firmware/OS data."""
    if not vendor:
        return "Unknown"

    explicit = list(firmware_versions)
    if explicit:
        return explicit[0]

    vendor_key = vendor.lower().replace("-", "_")
    for cpe in cpes:
        parts = cpe.split(":")
        # CPE 2.3 layout: cpe:2.3:<part>:<vendor>:<product>:<version>:...
        if len(parts) >= 6 and parts[2].lower() == "o":
            cpe_vendor = parts[3].lower().replace("-", "_")
            version = parts[5]
            if cpe_vendor == vendor_key and version not in {"", "*", "-"}:
                return version

    return "Unknown"


def _infer_device_type(services: List[str], vendor: Optional[str]) -> tuple[str, str]:
    surveillance = {"rtsp", "onvif"} & set(services)
    if surveillance:
        if vendor in {"Hikvision", "Dahua", "Axis", "Uniview", "Reolink"}:
            return "Surveillance Device", "medium"
        return "Possible Surveillance Device", "low"

    if "http" in services or "https" in services or "domain" in services:
        return "Network Device", "low"
    return "Unknown Device", "low"


def _fingerprint_simulated(device: Dict[str, Any]) -> Dict[str, Any]:
    ip_address = device["ip_address"]
    fingerprint_seed = int(sha1(ip_address.encode("utf-8")).hexdigest(), 16)
    vendor_profiles = _load_vendor_profiles()
    vendor_profile = vendor_profiles[fingerprint_seed % len(vendor_profiles)]
    last_octet = int(ip_address.split(".")[-1]) if ip_address.count(".") == 3 else 0

    services = list(vendor_profile["default_services"])
    if last_octet % 2 == 0:
        services.append("onvif")
    if last_octet % 3 == 0:
        services.append("telnet")
    if last_octet % 5 == 0:
        services.append("https")
    services = _dedupe(services)

    vendor = vendor_profile["vendor"]
    return {
        **device,
        "vendor": vendor,
        "model": f"{vendor_profile['model_prefix']}-{(last_octet % 9) + 1}",
        "firmware_version": vendor_profile["firmware"],
        "services": services,
        "auth_mode": "basic" if "telnet" in services else "digest",
        "default_credentials": _default_credentials_for(vendor),
        "device_type": "Surveillance Device",
        "detection_confidence": "high",
        "fingerprint_evidence": ["Deterministic simulated profile"],
        "exposure_profile": {
            "has_telnet": "telnet" in services,
            "has_rtsp": "rtsp" in services,
            "has_onvif": "onvif" in services,
            "uses_https": "https" in services,
        },
        "fingerprint_source": "simulation",
    }


def _load_vendor_profiles():
    if VENDORS_PATH.exists():
        try:
            data = json.loads(VENDORS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, list) and data:
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return FALLBACK_VENDORS


def _default_credentials_for(vendor_name: Optional[str]):
    if not vendor_name or not DEFAULT_CREDENTIALS_PATH.exists():
        return []
    try:
        data = json.loads(DEFAULT_CREDENTIALS_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return [
        item for item in data
        if str(item.get("vendor", "")).lower() == vendor_name.lower()
    ]


def _dedupe(items):
    seen = set()
    ordered = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered
