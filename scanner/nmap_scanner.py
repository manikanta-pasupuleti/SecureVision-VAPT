from __future__ import annotations

from typing import Dict, List
from ipaddress import ip_address
import socket

import nmap


def _normalize_service(
    port_number: int,
    service_name: str,
    tunnel: str = "",
) -> str:
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


def _resolve_host(host: str) -> str:
    """
    Resolve a hostname to an IPv4 address.

    If host is already an IP address, return it unchanged.
    """

    try:
        ip_address(host)
        return host

    except ValueError:
        pass

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(
            f"Unable to resolve hostname: {host}"
        ) from exc

    print(
        f"[NMAP] Resolved hostname: "
        f"{host} -> {resolved_ip}"
    )

    return resolved_ip


def scan_host(host: str) -> Dict:
    """
    Run Nmap service/version detection against one authorized host.

    Hostnames are resolved to IPv4 before Nmap results are processed.

    -Pn       Skip host discovery
    -sT       TCP connect scan
    -sV       Service/version detection
    --reason  Preserve Nmap's reason for port states
    """

    print("\n========================================")
    print("[NMAP] STARTING HOST SCAN")
    print("========================================")
    print(f"[NMAP] Requested target: {host}")

    resolved_host = _resolve_host(host)

    print(f"[NMAP] Scan target: {resolved_host}")

    scanner = nmap.PortScanner()

    arguments = "-Pn -sT -sV --reason"

    print(f"[NMAP] Arguments: {arguments}")

    try:
        scanner.scan(
            hosts=resolved_host,
            arguments=arguments,
        )

    except Exception as exc:
        print(
            f"[NMAP] Scan exception: "
            f"{type(exc).__name__}: {exc}"
        )
        raise

    try:
        print(
            f"[NMAP] Command: "
            f"{scanner.command_line()}"
        )
    except Exception:
        print(
            "[NMAP] Command line unavailable."
        )

    all_hosts = scanner.all_hosts()

    print(
        f"[NMAP] Hosts returned by Nmap: "
        f"{all_hosts}"
    )

    if resolved_host not in all_hosts:

        print(
            f"[NMAP] {resolved_host} "
            f"was not returned by Nmap."
        )

        print(
            "[NMAP] Treating target as DOWN / unreachable."
        )

        print("========================================\n")

        return {
            "ip_address": resolved_host,
            "host_status": "down",
            "ports": [],
        }

    host_data = scanner[resolved_host]

    raw_status = host_data.get(
        "status",
        {},
    )

    print(
        f"[NMAP] Raw host status: "
        f"{raw_status}"
    )

    ports: List[Dict] = []

    for protocol in host_data.all_protocols():

        protocol_data = host_data[protocol]

        for port_number in sorted(
            protocol_data.keys()
        ):

            port_info = protocol_data[
                port_number
            ]

            raw_service = str(
                port_info.get(
                    "name",
                    "",
                ) or ""
            ).strip()

            tunnel = str(
                port_info.get(
                    "tunnel",
                    "",
                ) or ""
            ).strip()

            normalized_service = _normalize_service(
                port_number,
                raw_service,
                tunnel,
            )

            port_record = {
                "port": int(port_number),
                "protocol": str(
                    protocol
                ).lower(),

                "state": port_info.get(
                    "state",
                    "unknown",
                ),

                "service": normalized_service,

                "nmap_service": raw_service,
                "tunnel": tunnel,

                "product": port_info.get(
                    "product",
                    "",
                ),

                "version": port_info.get(
                    "version",
                    "",
                ),

                "extrainfo": port_info.get(
                    "extrainfo",
                    "",
                ),

                "reason": port_info.get(
                    "reason",
                    "",
                ),

                "cpe": port_info.get(
                    "cpe",
                    "",
                ),
            }

            ports.append(
                port_record
            )

            print(
                f"[NMAP] Port "
                f"{port_number}/"
                f"{protocol}: "
                f"{port_record['state']} "
                f"{normalized_service} "
                f"{port_record['product']} "
                f"{port_record['version']}"
            )

    host_status = str(
        host_data.get(
            "status",
            {},
        ).get(
            "state",
            "unknown",
        )
    ).lower()

    print(
        f"[NMAP] Final status: "
        f"{host_status}"
    )

    print(
        f"[NMAP] Ports detected: "
        f"{len(ports)}"
    )

    print(
        "========================================\n"
    )

    return {
        "ip_address": resolved_host,
        "host_status": host_status,
        "ports": ports,
    }


if __name__ == "__main__":
    import json

    result = scan_host(
        "127.0.0.1"
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )