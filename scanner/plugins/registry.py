from __future__ import annotations

from typing import Dict, List

from scanner.plugins.loader import discover_plugin_classes
from scanner.plugins.manifest import get_manifest_map


_PLUGINS = {}


def _load_plugins() -> None:
    manifests = get_manifest_map()
    for plugin_class in discover_plugin_classes():
        plugin = plugin_class()
        manifest = manifests.get(plugin.name)
        if manifest is not None:
            plugin.metadata = {
                "description": manifest.description,
                "severity": manifest.severity,
                "service_name": manifest.service_name,
            }
        _PLUGINS[plugin.name] = plugin


_load_plugins()


def get_plugins() -> List[object]:
    return list(_PLUGINS.values())


def get_plugin(name: str):
    return _PLUGINS.get(name)


def run_plugins(device: Dict) -> List[Dict]:
    findings = []
    for plugin in get_plugins():
        if plugin.matches(device):
            for result in plugin.evaluate(device):
                findings.append(
                    {
                        "device_ip": device["ip_address"],
                        "severity": result.severity,
                        "title": result.title,
                        "description": result.description,
                        "remediation": result.remediation,
                        "evidence": result.evidence,
                    }
                )
    return findings
