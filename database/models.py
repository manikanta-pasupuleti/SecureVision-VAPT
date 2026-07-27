from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List


@dataclass
class ReportRecord:
    """Lightweight report model for the assessment workflow."""

    id: int | None = None
    created_at: str = ""
    target_spec: str = ""
    device_count: int = 0
    finding_count: int = 0
    risk_score: int = 0
    summary_json: str = "{}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeviceRecord:
    """Lightweight device model for persisted scan results."""

    id: int | None = None
    report_id: int = 0
    ip_address: str = ""
    vendor: str = ""
    model: str = ""
    firmware_version: str = ""
    services: List[str] | None = None
    risk_score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
