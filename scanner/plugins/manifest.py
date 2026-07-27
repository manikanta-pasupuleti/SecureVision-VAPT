from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class PluginManifest:
    name: str
    description: str
    severity: str
    service_name: str


PLUGIN_MANIFESTS: List[PluginManifest] = [
    PluginManifest(name="telnet", description="Detects Telnet exposure", severity="high", service_name="telnet"),
    PluginManifest(name="rtsp", description="Detects RTSP exposure", severity="medium", service_name="rtsp"),
    PluginManifest(name="onvif", description="Detects ONVIF exposure", severity="medium", service_name="onvif"),
    PluginManifest(name="http", description="Detects HTTP and HTTPS exposure", severity="low", service_name="http"),
    PluginManifest(name="ftp", description="Detects FTP exposure", severity="medium", service_name="ftp"),
]


def get_manifest_map() -> Dict[str, PluginManifest]:
    return {manifest.name: manifest for manifest in PLUGIN_MANIFESTS}
