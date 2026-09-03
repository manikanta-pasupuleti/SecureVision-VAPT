from __future__ import annotations

from typing import Dict, List, Optional


# Firmware support database.
#
# This module is intentionally conservative.  A firmware version being old is
# not, by itself, proof that a particular CVE applies to every model using that
# version.  Confirmed CVEs are correlated by scanner/cve_matcher.py when the
# observed product and version provide sufficient evidence.

_FIRMWARE_DB: Dict[str, Dict] = {
    "Hikvision": {
        "latest": "5.7.16",
        "versions": [
            "5.7.16", "5.7.15", "5.7.0", "5.6.18", "5.6.0",
            "5.5.0", "5.4.5", "5.4.0", "5.3.0", "4.1.0", "3.4.0",
        ],
        "vulnerable": {},
        "eol_versions": ["3.4.0", "4.1.0", "5.3.0"],
        "upgrade_path": "Download the correct firmware for the exact model from the Hikvision support portal.",
    },
    "Dahua": {
        "latest": "4.001.0000001.0",
        "versions": [
            "4.001.0000001.0", "3.218.0000001.0", "3.210",
            "3.200", "3.100", "2.800", "2.400",
        ],
        "vulnerable": {},
        "eol_versions": ["2.400", "2.800", "3.100"],
        "upgrade_path": "Download the correct firmware for the exact model from the Dahua support portal.",
    },
    "Axis": {
        "latest": "11.8.57",
        "versions": [
            "11.8.57", "11.7.57", "11.6.94", "10.12", "10.9",
            "9.80", "8.40", "7.20", "6.50",
        ],
        "vulnerable": {},
        "eol_versions": ["6.50", "7.20", "8.40"],
        "upgrade_path": "Download the correct firmware for the exact model from the Axis support portal.",
    },
    "Uniview": {
        "latest": "4.0.1.G",
        "versions": [
            "4.0.1.G", "3.6.2.F", "3.4.1.E", "2.4.1", "2.2.0", "1.8.0",
        ],
        "vulnerable": {},
        "eol_versions": ["1.8.0", "2.2.0"],
        "upgrade_path": "Download the correct firmware for the exact model from the Uniview support portal.",
    },
}


def analyze_firmware(vendor: str, current_version: str) -> Dict:
    """Compare a known vendor firmware version with the local baseline."""
    vendor_key = _find_vendor(vendor)

    if vendor_key is None:
        return _unknown_vendor_result(vendor, current_version)

    db = _FIRMWARE_DB[vendor_key]
    latest = db["latest"]
    current = str(current_version or "Unknown")
    eol_versions = db.get("eol_versions", [])

    return {
        "vendor": vendor_key,
        "current_version": current,
        "latest_version": latest,
        "is_outdated": _is_outdated(current, latest),
        "is_vulnerable": False,
        "is_eol": current in eol_versions,
        "cves": [],
        "upgrade_path": db.get(
            "upgrade_path",
            "Use the vendor's official support channel for the exact model.",
        ),
    }


def get_cves_for_version(vendor: str, version: str) -> List[str]:
    """Return confirmed firmware CVEs; product-level correlation is separate."""
    return analyze_firmware(vendor, version).get("cves", [])


def is_firmware_eol(vendor: str, version: str) -> bool:
    return analyze_firmware(vendor, version).get("is_eol", False)


def get_supported_vendors() -> List[str]:
    return list(_FIRMWARE_DB.keys())


def _find_vendor(vendor: str) -> Optional[str]:
    value = str(vendor or "").lower()
    for key in _FIRMWARE_DB:
        if key.lower() == value:
            return key
    return None


def _is_outdated(current: str, latest: str) -> bool:
    if not current or current.lower() in {"unknown", "none", "n/a", "na", "0"}:
        return False
    if current == latest:
        return False
    return _version_tuple(current) < _version_tuple(latest)


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for token in str(version).replace("-", ".").split("."):
        digits = "".join(ch for ch in token if ch.isdigit())
        if digits:
            parts.append(int(digits))
    return tuple(parts or [0])


def _unknown_vendor_result(vendor: str, current_version: str) -> Dict:
    return {
        "vendor": vendor,
        "current_version": current_version,
        "latest_version": "unknown",
        "is_outdated": False,
        "is_vulnerable": False,
        "is_eol": False,
        "cves": [],
        "upgrade_path": "Vendor not in firmware database. Check the vendor's official support resources.",
    }
