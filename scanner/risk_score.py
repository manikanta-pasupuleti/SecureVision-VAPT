from __future__ import annotations


SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 4,
    "info": 1,
}


def calculate_risk_score(findings):
    return min(100, sum(SEVERITY_WEIGHTS.get(finding["severity"].lower(), 0) for finding in findings))
