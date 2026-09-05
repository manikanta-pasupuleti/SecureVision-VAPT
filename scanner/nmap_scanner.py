from __future__ import annotations

from typing import Dict, List

import nmap


def _normalize_service(port_number: int, service_name: str, tunnel: str = "") -> str:
    """
    Normalize Nmap's service name without throwing away the original evidence.

    Nmap commonly reports HTTPS as:
        name=http, tunnel=ssl
    or:
        name=ssl/http

    The application should represent TCP/443 as HTTPS and TCP/80 as HTTP.
    Port is authoritative for these standard web services.
    """
    name = (service_name or "").strip().lower()
    tunnel = (tunnel or "").strip().lower()

    if port_number == 443 and (
        name in {"http", "ssl/http", "https", "ssl"}
        or "ssl" in name
        or tunnel == "ssl"
    ):
        return "https"

    if port_number == 80 and name in {"http", "http-proxy", "www"}:
        return "http"

    # Other common Nmap aliases.
    aliases = {
        "ssl/http": "https",
        "https-alt": "https",
        "domain": "domain",
        "ftp": "ftp",
        "ssh": "ssh",
        "telnet": "telnet",
        "rtsp": "rtsp",
        "mysql": "mysql",
        "smtp": "smtp",
        "snmp": "snmp",
        "microsoft-ds": "microsoft-ds",
        "msrpc": "msrpc",
    }

    return aliases.get(name, name)


def scan_host(host: str) -> Dict:
    """
    Run Nmap service/version detection against one authorized host.

    Returns normalized scan information while preserving Nmap's original
    service/product/version evidence.
    """
    scanner = nmap.PortScanner()

    scanner.scan(
        hosts=host,
        arguments="-Pn -sV",
    )

    if host not in scanner.all_hosts():
        return {
            "ip_address": host,
            "host_status": "down",
            "ports": [],
        }

    host_data = scanner[host]
    ports: List[Dict] = []

    for protocol in host_data.all_protocols():
        protocol_data = host_data[protocol]

        for port_number in sorted(protocol_data.keys()):
            port_info = protocol_data[port_number]

            raw_service = str(port_info.get("name", "") or "").strip()
            tunnel = str(port_info.get("tunnel", "") or "").strip()

            normalized_service = _normalize_service(
                port_number,
                raw_service,
                tunnel,
            )

            ports.append(
                {
                    "port": int(port_number),
                    "protocol": str(protocol).lower(),
                    "state": port_info.get("state", "unknown"),

                    # Service used by the rest of SecureVision.
                    "service": normalized_service,

                    # Original Nmap evidence is retained for audit/debugging.
                    "nmap_service": raw_service,
                    "tunnel": tunnel,

                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "extrainfo": port_info.get("extrainfo", ""),
                    "reason": port_info.get("reason", ""),
                    "cpe": port_info.get("cpe", ""),
                }
            )

    return {
        "ip_address": host,
        "host_status": host_data.get("status", {}).get("state", "unknown"),
        "ports": ports,
    }


if __name__ == "__main__":
    import json

    result = scan_host("127.0.0.1")
    print(json.dumps(result, indent=2))
