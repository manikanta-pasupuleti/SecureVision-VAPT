from __future__ import annotations

import json
from hashlib import sha1
from pathlib import Path


DATA_DIR = Path(__file__).resolve().parent.parent / "data"
VENDORS_PATH = DATA_DIR / "vendors.json"
DEFAULT_CREDENTIALS_PATH = DATA_DIR / "default_credentials.json"

FALLBACK_VENDORS = [
    {"vendor": "Hikvision", "model_prefix": "DS-2CD", "firmware": "5.6.18", "default_services": ["http", "rtsp", "onvif"]},
    {"vendor": "Dahua", "model_prefix": "IPC-HFW", "firmware": "3.210", "default_services": ["http", "rtsp", "telnet"]},
    {"vendor": "Axis", "model_prefix": "M30", "firmware": "10.12", "default_services": ["http", "https", "onvif"]},
    {"vendor": "Uniview", "model_prefix": "IPC23", "firmware": "2.4.1", "default_services": ["http", "rtsp", "telnet"]},
]


def fingerprint_device(device):
    ip_address = device["ip_address"]
    fingerprint_seed = int(sha1(ip_address.encode("utf-8")).hexdigest(), 16)
    vendor_profile = _load_vendor_profiles()[fingerprint_seed % len(_load_vendor_profiles())]
    last_octet = int(ip_address.split(".")[-1]) if ip_address.count(".") == 3 else 0

    services = list(vendor_profile["default_services"])
    if last_octet % 2 == 0:
        services.append("onvif")
    if last_octet % 3 == 0:
        services.append("telnet")
    if last_octet % 5 == 0:
        services.append("https")

    services = _dedupe(services)
    default_credentials = _default_credentials_for(vendor_profile["vendor"])
    auth_mode = "basic" if "telnet" in services else "digest"

    return {
        **device,
        "vendor": vendor_profile["vendor"],
        "model": f"{vendor_profile['model_prefix']}-{(last_octet % 9) + 1}",
        "firmware_version": vendor_profile["firmware"],
        "services": services,
        "auth_mode": auth_mode,
        "default_credentials": default_credentials,
        "exposure_profile": {
            "has_telnet": "telnet" in services,
            "has_rtsp": "rtsp" in services,
            "has_onvif": "onvif" in services,
            "uses_https": "https" in services,
        },
    }


def _load_vendor_profiles():
    if VENDORS_PATH.exists():
        try:
            data = json.loads(VENDORS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, list) and data:
                return data
        except json.JSONDecodeError:
            pass
    return FALLBACK_VENDORS


def _default_credentials_for(vendor_name):
    if not DEFAULT_CREDENTIALS_PATH.exists():
        return []

    try:
        data = json.loads(DEFAULT_CREDENTIALS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    matches = []
    for item in data:
        if item.get("vendor", "").lower() == vendor_name.lower():
            matches.append(item)
    return matches


def _dedupe(items):
    seen = set()
    ordered = []
    for item in items:
        if item not in seen:
            ordered.append(item)
            seen.add(item)
    return ordered
