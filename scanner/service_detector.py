from __future__ import annotations

from typing import Dict, List


# ---------------------------------------------------------------------------
# Service knowledge base
# ---------------------------------------------------------------------------

_SERVICE_PROFILES: Dict[str, Dict] = {
    "mysql": {
        "port": 3306,
        "protocol": "TCP",
        "encrypted": False,
        "auth_required": True,
        "exposure_risk": "medium",
        "attack_vector": "network",
        "description": (
            "MySQL database service — remote database exposure "
            "should be restricted and authenticated"
        ),
        "cve_tags": ["database", "remote-access", "credential-exposure"],
    },
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
    "domain": {
        "port": 53,
        "protocol": "TCP/UDP",
        "encrypted": None,
        "auth_required": None,
        "exposure_risk": "unknown",
        "attack_vector": "network",
        "description": "DNS/domain service detected by Nmap.",
        "cve_tags": ["dns", "network-exposure"],
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
    "msrpc": {
        "port": 135,
        "protocol": "TCP",
        "encrypted": None,
        "auth_required": True,
        "exposure_risk": "medium",
        "attack_vector": "network",
        "description": (
            "Microsoft RPC service — remote procedure calls should be "
            "restricted to trusted hosts and protected by host firewall rules"
        ),
        "cve_tags": ["remote-access", "rpc", "network-exposure"],
    },
    "microsoft-ds": {
        "port": 445,
        "protocol": "TCP",
        "encrypted": None,
        "auth_required": True,
        "exposure_risk": "high",
        "attack_vector": "network",
        "description": (
            "Microsoft SMB service — network file and printer sharing "
            "should be restricted and securely configured"
        ),
        "cve_tags": ["smb", "file-sharing", "remote-access", "network-exposure"],
    },
    "afrog": {
        "port": 1042,
        "protocol": "TCP",
        "encrypted": None,
        "auth_required": None,
        "exposure_risk": "unknown",
        "attack_vector": "network",
        "description": (
            "Nmap identified an AFROG service on TCP 1042. "
            "Encryption and authentication could not be determined "
            "from service identification alone."
        ),
        "cve_tags": ["network-exposure", "service-detection"],
    },
    "interwise": {
        "port": 7778,
        "protocol": "TCP",
        "encrypted": None,
        "auth_required": None,
        "exposure_risk": "unknown",
        "attack_vector": "network",
        "description": (
            "Interwise service detected on TCP 7778. "
            "Encryption and authentication could not be determined "
            "from service identification alone."
        ),
        "cve_tags": ["network-exposure", "service-detection"],
    },
    "tcpwrapped": {
        "port": 8090,
        "protocol": "TCP",
        "encrypted": None,
        "auth_required": None,
        "exposure_risk": "unknown",
        "attack_vector": "network",
        "description": (
            "TCP-wrapped service detected on TCP 8090. "
            "The underlying application service could not be identified."
        ),
        "cve_tags": ["tcpwrapped", "service-detection", "network-exposure"],
    },
}

_RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "unknown": 4}


def _canonical_service_name(service_name: str, port: int | None = None) -> str:
    """Return the application's canonical service name."""
    key = str(service_name or "").strip().lower()

    if port == 443 and key in {"http", "ssl/http", "ssl", "https"}:
        return "https"
    if port == 80 and key in {"http", "www", "http-proxy"}:
        return "http"

    aliases = {
        "ssl/http": "https",
        "https-alt": "https",
        "www": "http",
    }
    return aliases.get(key, key)


def enumerate_services(services: List[str]) -> List[Dict]:
    """Enrich service names into structured security profiles."""
    enriched: List[Dict] = []

    seen = set()
    for service_name in services or []:
        key = _canonical_service_name(service_name)
        if not key or key in seen:
            continue
        seen.add(key)
        enriched.append(_get_service_profile(key))

    return sorted(
        enriched,
        key=lambda s: _RISK_ORDER.get(s["exposure_risk"], 4),
    )


def get_high_risk_services(services: List[str]) -> List[Dict]:
    return [
        s for s in enumerate_services(services)
        if s["exposure_risk"] == "high"
    ]


def get_unencrypted_services(services: List[str]) -> List[Dict]:
    return [
        s for s in enumerate_services(services)
        if s.get("encrypted") is False
    ]


def get_service_port_map(services: List[str]) -> Dict[str, int]:
    return {
        s["name"]: s["port"]
        for s in enumerate_services(services)
    }


def calculate_exposure_score(services: List[str]) -> Dict:
    """
    Calculate exposure from the service set.

    high=30, medium=15, low=5, info=0.
    """
    weights = {"high": 30, "medium": 15, "low": 5, "info": 0}
    breakdown = {"high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0

    for profile in enumerate_services(services):
        risk = profile["exposure_risk"]
        breakdown[risk] = breakdown.get(risk, 0) + 1
        total += weights.get(risk, 0)

    return {
        "score": min(100, total),
        "breakdown": breakdown,
        "unencrypted_count": len(get_unencrypted_services(services)),
        "high_risk_count": len(get_high_risk_services(services)),
    }


def _get_service_profile(service_name: str) -> Dict:
    key = _canonical_service_name(service_name)

    if key in _SERVICE_PROFILES:
        return {"name": key, **_SERVICE_PROFILES[key]}

    return {
        "name": key,
        "port": 0,
        "protocol": "unknown",
        "encrypted": None,
        "auth_required": None,
        "exposure_risk": "unknown",
        "attack_vector": "network",
        "description": f"Unrecognised service: {service_name}",
        "cve_tags": [],
    }
