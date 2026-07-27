from __future__ import annotations

from typing import Dict, List

from scanner.plugins.base import PluginResult, ServicePlugin


class RTSPPlugin(ServicePlugin):
    name = "rtsp"

    def matches(self, device: Dict) -> bool:
        services = device.get("services", [])
        exposure = device.get("exposure_profile", {})
        return "rtsp" in services or exposure.get("has_rtsp")

    def evaluate(self, device: Dict) -> List[PluginResult]:
        return [
            PluginResult(
                severity="medium",
                title="RTSP stream exposure",
                description="RTSP is available and may allow unauthenticated or weakly authenticated video access.",
                remediation="Require strong authentication for stream access and restrict exposure with network ACLs.",
                evidence="RTSP service detected during fingerprinting.",
            )
        ]
