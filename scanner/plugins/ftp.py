from __future__ import annotations

from typing import Dict, List

from scanner.plugins.base import PluginResult, ServicePlugin


class FTPPlugin(ServicePlugin):
    name = "ftp"

    def matches(self, device: Dict) -> bool:
        services = device.get("services", [])
        return "ftp" in services

    def evaluate(self, device: Dict) -> List[PluginResult]:
        return [
            PluginResult(
                severity="medium",
                title="FTP service detected",
                description="FTP was found in the simulated service profile and may expose insecure file transfer.",
                remediation="Disable FTP unless it is strictly required and enforce secure alternatives.",
                evidence="FTP service detected during fingerprinting.",
            )
        ]
