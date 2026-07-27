from __future__ import annotations

from typing import Dict, List

from scanner.plugins.base import PluginResult, ServicePlugin


class TelnetPlugin(ServicePlugin):
    name = "telnet"

    def matches(self, device: Dict) -> bool:
        services = device.get("services", [])
        exposure = device.get("exposure_profile", {})
        return "telnet" in services or exposure.get("has_telnet")

    def evaluate(self, device: Dict) -> List[PluginResult]:
        return [
            PluginResult(
                severity="high",
                title="Telnet service exposed",
                description="Telnet is enabled on the device, increasing the likelihood of credential interception.",
                remediation="Disable Telnet and use SSH or vendor-supported secure management interfaces.",
                evidence="Port 23 is reachable in the simulated service profile.",
            )
        ]
