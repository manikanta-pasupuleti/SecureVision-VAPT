from __future__ import annotations

from typing import Dict, List

import nmap


def scan_host(host: str) -> Dict:
    """
    Run Nmap service/version detection against one authorized host
    and return normalized scan information.
    """

    scanner = nmap.PortScanner()

    scanner.scan(
        hosts=host,
        arguments="-sV"
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

            ports.append({
                "port": port_number,
                "protocol": protocol,
                "state": port_info.get("state", "unknown"),
                "service": port_info.get("name", ""),
                "product": port_info.get("product", ""),
                "version": port_info.get("version", ""),
            })

    return {
        "ip_address": host,
        "host_status": host_data.get("status", {}).get("state", "unknown"),
        "ports": ports,
    }

if __name__ == "__main__":
    result = scan_host("127.0.0.1")
    print(result)