from __future__ import annotations

from typing import Dict, List

from scanner.plugins.base import PluginResult, ServicePlugin


class HTTPPlugin(ServicePlugin):
    name = "http"

    def matches(self, device: Dict) -> bool:
        services = device.get("services", [])
        return "http" in services or "https" in services

    def evaluate(self, device: Dict) -> List[PluginResult]:
        return [
            PluginResult(
                severity="low",
                title="Web management interface present",
                description="An HTTP-based management interface was detected on the device profile.",
                remediation="Enforce HTTPS and disable insecure administrative access where possible.",
                evidence="HTTP or HTTPS service detected during fingerprinting.",
            )
        ]
