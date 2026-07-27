from __future__ import annotations

from typing import Dict, List

from scanner.plugins.base import PluginResult, ServicePlugin


class ONVIFPlugin(ServicePlugin):
    name = "onvif"

    def matches(self, device: Dict) -> bool:
        services = device.get("services", [])
        exposure = device.get("exposure_profile", {})
        return "onvif" in services or exposure.get("has_onvif")

    def evaluate(self, device: Dict) -> List[PluginResult]:
        return [
            PluginResult(
                severity="medium",
                title="ONVIF management interface reachable",
                description="ONVIF is exposed, which can allow discovery and device control if credentials are weak.",
                remediation="Restrict ONVIF exposure and change any default administrative credentials.",
                evidence="ONVIF service detected during fingerprinting.",
            )
        ]
