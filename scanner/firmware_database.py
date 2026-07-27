from __future__ import annotations

from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Firmware knowledge base
# Each entry contains:
#   versions        - all known firmware versions for that vendor
#   latest          - current stable recommended version
#   vulnerable      - versions with known security issues + their CVEs
#   eol_versions    - versions that are end-of-life (no patches available)
#   upgrade_path    - human-readable upgrade instruction
# ---------------------------------------------------------------------------

_FIRMWARE_DB: Dict[str, Dict] = {
    "Hikvision": {
        "latest": "5.7.16",
        "versions": [
            "5.7.16", "5.7.15", "5.7.0", "5.6.18", "5.6.0",
            "5.5.0", "5.4.5", "5.4.0", "5.3.0", "4.1.0", "3.4.0",
        ],
        "vulnerable": {
            "5.4.5": ["CVE-2017-7921", "CVE-2017-7923"],
            "5.4.0": ["CVE-2017-7921", "CVE-2017-7923"],
            "5.3.0": ["CVE-2017-7921", "CVE-2017-7923", "CVE-2014-4878"],
            "5.6.0": ["CVE-2021-36260"],
            "5.6.18": [],
            "4.1.0": ["CVE-2014-4878", "CVE-2014-4879"],
            "3.4.0": ["CVE-2014-4878", "CVE-2014-4879", "CVE-2013-4975"],
        },
        "eol_versions": ["3.4.0", "4.1.0", "5.3.0"],
        "upgrade_path": "Download latest firmware from Hikvision official portal at hikvision.com/en/support/download/firmware/",
    },
    "Dahua": {
        "latest": "4.001.0000001.0",
        "versions": [
            "4.001.0000001.0", "3.218.0000001.0", "3.210",
            "3.200", "3.100", "2.800", "2.400",
        ],
        "vulnerable": {
            "3.210": ["CVE-2021-33044", "CVE-2021-33045"],
            "3.200": ["CVE-2021-33044", "CVE-2021-33045", "CVE-2019-9082"],
            "3.100": ["CVE-2021-33044", "CVE-2021-33045", "CVE-2019-9082", "CVE-2017-6343"],
            "2.800": ["CVE-2017-6343", "CVE-2017-6341"],
            "2.400": ["CVE-2017-6343", "CVE-2017-6341", "CVE-2013-6117"],
        },
        "eol_versions": ["2.400", "2.800", "3.100"],
        "upgrade_path": "Download latest firmware from Dahua official portal at dahuasecurity.com/support/downloadCenter/",
    },
    "Axis": {
        "latest": "11.8.57",
        "versions": [
            "11.8.57", "11.7.57", "11.6.94", "10.12", "10.9",
            "9.80", "8.40", "7.20", "6.50",
        ],
        "vulnerable": {
            "10.9":  ["CVE-2022-31199"],
            "9.80":  ["CVE-2022-31199", "CVE-2018-10660"],
            "8.40":  ["CVE-2018-10660", "CVE-2018-10661", "CVE-2018-10662"],
            "7.20":  ["CVE-2018-10660", "CVE-2018-10661", "CVE-2018-10662", "CVE-2015-8257"],
            "6.50":  ["CVE-2015-8257", "CVE-2014-1937"],
        },
        "eol_versions": ["6.50", "7.20", "8.40"],
        "upgrade_path": "Download latest firmware from Axis official portal at axis.com/support/firmware",
    },
    "Uniview": {
        "latest": "4.0.1.G",
        "versions": [
            "4.0.1.G", "3.6.2.F", "3.4.1.E", "2.4.1", "2.2.0", "1.8.0",
        ],
        "vulnerable": {
            "2.4.1": ["CVE-2020-17473", "CVE-2019-16676"],
            "2.2.0": ["CVE-2020-17473", "CVE-2019-16676", "CVE-2018-14933"],
            "1.8.0": ["CVE-2020-17473", "CVE-2019-16676", "CVE-2018-14933"],
        },
        "eol_versions": ["1.8.0", "2.2.0"],
        "upgrade_path": "Download latest firmware from Uniview official portal at uniview.com/Support/",
    },
}


def analyze_firmware(vendor: str, current_version: str) -> Dict:
    """
    Analyze a device firmware version against the knowledge base.

    Returns a structured result with upgrade status, CVEs, and EOL flag.
    Falls back gracefully if vendor is not in the database.
    """
    vendor_key = _find_vendor(vendor)

    if vendor_key is None:
        return _unknown_vendor_result(vendor, current_version)

    db = _FIRMWARE_DB[vendor_key]
    latest = db["latest"]
    vulnerable_map = db.get("vulnerable", {})
    eol_versions = db.get("eol_versions", [])

    is_outdated = _is_outdated(current_version, latest)
    is_eol = current_version in eol_versions
    cves = vulnerable_map.get(current_version, [])
    is_vulnerable = len(cves) > 0

    return {
        "vendor": vendor_key,
        "current_version": current_version,
        "latest_version": latest,
        "is_outdated": is_outdated,
        "is_vulnerable": is_vulnerable,
        "is_eol": is_eol,
        "cves": cves,
        "upgrade_path": db.get("upgrade_path", "Contact vendor support for upgrade instructions."),
    }


def get_cves_for_version(vendor: str, version: str) -> List[str]:
    """Return CVE list for a specific vendor + firmware version."""
    result = analyze_firmware(vendor, version)
    return result.get("cves", [])


def is_firmware_eol(vendor: str, version: str) -> bool:
    """Return True if the firmware version is end-of-life."""
    result = analyze_firmware(vendor, version)
    return result.get("is_eol", False)


def get_supported_vendors() -> List[str]:
    """Return list of vendors covered by the firmware database."""
    return list(_FIRMWARE_DB.keys())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_vendor(vendor: str) -> Optional[str]:
    """Case-insensitive vendor lookup."""
    for key in _FIRMWARE_DB:
        if key.lower() == vendor.lower():
            return key
    return None


def _is_outdated(current: str, latest: str) -> bool:
    """Compare version strings. Returns True if current is behind latest."""
    if current == latest:
        return False
    try:
        return _version_tuple(current) < _version_tuple(latest)
    except Exception:
        return current != latest


def _version_tuple(version: str) -> tuple:
    """Convert a version string to a comparable tuple of integers."""
    parts = []
    for token in version.replace("-", ".").split("."):
        digits = "".join(c for c in token if c.isdigit())
        if digits:
            parts.append(int(digits))
    return tuple(parts or [0])


def _unknown_vendor_result(vendor: str, current_version: str) -> Dict:
    """Fallback result for vendors not in the database."""
    return {
        "vendor": vendor,
        "current_version": current_version,
        "latest_version": "unknown",
        "is_outdated": False,
        "is_vulnerable": False,
        "is_eol": False,
        "cves": [],
        "upgrade_path": "Vendor not in firmware database. Check vendor website for latest firmware.",
    }
