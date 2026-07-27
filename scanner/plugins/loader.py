from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Type

from scanner.plugins.base import ServicePlugin


def discover_plugin_classes(package_name: str = "scanner.plugins") -> List[Type[ServicePlugin]]:
    """Discover plugin classes from the plugins package dynamically."""

    package = importlib.import_module(package_name)
    discovered = []
    package_path = Path(package.__file__).resolve().parent

    for module_info in pkgutil.iter_modules([str(package_path)]):
        if module_info.name in {"__init__", "base", "registry", "loader"}:
            continue
        module = importlib.import_module(f"{package_name}.{module_info.name}")
        for _, obj in vars(module).items():
            if isinstance(obj, type) and issubclass(obj, ServicePlugin) and obj is not ServicePlugin:
                discovered.append(obj)

    return discovered
