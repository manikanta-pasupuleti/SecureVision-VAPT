from __future__ import annotations

from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Service knowledge base
# Each entry defines the full technical profile of a known surveillance
# device service including port, protocol, encryption, auth, and risk.
# ---------------------------------------------------------------------------

_SERVICE_PROFILES: Dict[str, Dict] = {
    "telnet": {
        "port": 23,
        "protocol": "TCP",
        "encrypted": False,
        "auth_required": False,
        "exposure_risk": "high",
        "attack_vector": "network",
        "description": "Unencrypted remote shell — credentials transmitted in plaintext",
        "cve_tags": ["credential-exposure", "remote-access", "plaintext"],
    },
    "rtsp": {
        "port": 554,
        "protocol": "TCP/UDP",
        "encrypted": False,
        "auth_required": False,
        "exposure_risk": "medium",
        "attack_vector": "network",
        "description": "Real-time video stream — may allow unauthenticated feed access",
        "cve_tags": ["video-exposure", "stream-access", "unauthenticated"],
    },
    "onvif": {
        "port": 80,
        "protocol": "TCP",
        "encrypted": False,
        "auth_required": True,
        "exposure_risk": "medium",
        "attack_vector": "network",
        "description": "Device management and discovery protocol — weak auth common",
        "cve_tags": ["device-management", "discovery", "weak-auth"],
    },
    "http": {
        "port": 80,
        "protocol": "TCP",
        "encrypted": False,
        "auth_required": True,
        "exposure_risk": "low",
        "attack_vector": "network",
        "description": "Unencrypted web management interface",
        "cve_tags": ["web-interface", "plaintext", "credential-exposure"],
    },
    "https": {
        "port": 443,
        "protocol": "TCP",
        "encrypted": True,
        "auth_required": True,
        "exposure_risk": "info",
        "attack_vector": "network",
        "description": "Encrypted web management interface",
        "cve_tags": ["web-interface", "encrypted"],
    },
    "ftp": {
        "port": 21,
        "protocol": "TCP",
        "encrypted": False,
        "auth_required": True,
        "exposure_risk": "medium",
        "attack_vector": "network",
        "description": "Unencrypted file transfer — credentials and data exposed in plaintext",
        "cve_tags": ["file-transfer", "plaintext", "credential-exposure"],
    },
    "ssh": {
        "port": 22,
        "protocol": "TCP",
        "encrypted": True,
        "auth_required": True,
        "exposure_risk": "info",
        "attack_vector": "network",
        "description": "Encrypted remote shell — secure if properly configured",
        "cve_tags": ["remote-access", "encrypted"],
    },
    "smtp": {
        "port": 25,
        "protocol": "TCP",
        "encrypted": False,
        "auth_required": False,
        "exposure_risk": "low",
        "attack_vector": "network",
        "description": "Mail transfer — used for alert notifications on some DVRs",
        "cve_tags": ["notification", "email"],
    },
    "snmp": {
        "port": 161,
        "protocol": "UDP",
        "encrypted": False,
        "auth_required": False,
        "exposure_risk": "high",
        "attack_vector": "network",
        "description": "Network management protocol — community strings often default",
        "cve_tags": ["network-management", "default-credentials", "information-disclosure"],
    },
}

# Risk ordering for sorting and comparison
_RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "unknown": 4}


def enumerate_services(services: List[str]) -> List[Dict]:
    """
    Enrich a flat list of service name strings into full structured profiles.

    Unknown services are included with a generic fallback profile so nothing
    is silently dropped from the pipeline.
    """
    enriched = []
    for service_name in services:
        profile = _get_service_profile(service_name)
        enriched.append(profile)

    return sorted(enriched, key=lambda s: _RISK_ORDER.get(s["exposure_risk"], 4))


def get_high_risk_services(services: List[str]) -> List[Dict]:
    """Return only services with high exposure risk."""
    return [s for s in enumerate_services(services) if s["exposure_risk"] == "high"]


def get_unencrypted_services(services: List[str]) -> List[Dict]:
    """Return services that transmit data without encryption."""
    return [s for s in enumerate_services(services) if not s["encrypted"]]


def get_service_port_map(services: List[str]) -> Dict[str, int]:
    """Return a simple name -> port mapping for a list of services."""
    return {s["name"]: s["port"] for s in enumerate_services(services)}


def calculate_exposure_score(services: List[str]) -> Dict:
    """
    Calculate an overall exposure score and breakdown for a service set.

    Score is additive:
      high    = 30 points each
      medium  = 15 points each
      low     =  5 points each
      info    =  0 points
    Capped at 100.
    """
    weights = {"high": 30, "medium": 15, "low": 5, "info": 0}
    breakdown = {"high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0

    for profile in enumerate_services(services):
        risk = profile["exposure_risk"]
        points = weights.get(risk, 0)
        breakdown[risk] = breakdown.get(risk, 0) + 1
        total += points

    return {
        "score": min(100, total),
        "breakdown": breakdown,
        "unencrypted_count": len(get_unencrypted_services(services)),
        "high_risk_count": len(get_high_risk_services(services)),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_service_profile(service_name: str) -> Dict:
    """Look up a service profile by name, returning a fallback for unknowns."""
    key = service_name.lower().strip()
    if key in _SERVICE_PROFILES:
        return {"name": key, **_SERVICE_PROFILES[key]}

    return {
        "name": key,
        "port": 0,
        "protocol": "unknown",
        "encrypted": False,
        "auth_required": False,
        "exposure_risk": "unknown",
        "attack_vector": "network",
        "description": f"Unrecognised service: {service_name}",
        "cve_tags": [],
    }
