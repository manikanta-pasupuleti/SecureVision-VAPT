from __future__ import annotations


def generate_report(device_rows, findings):
    risk_score = min(100, sum(device["risk_score"] for device in device_rows))

    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding["severity"].lower()
        if severity in severity_breakdown:
            severity_breakdown[severity] += 1

    prioritized_findings = sorted(
        findings,
        key=lambda finding: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(finding["severity"].lower(), 4),
    )

    # Aggregate CVE intelligence across all devices
    all_cve_ids = []
    all_recommendations = []
    top_cvss = 0.0
    for device in device_rows:
        intel = device.get("intelligence", {})
        for cve in intel.get("cve_matches", []):
            if cve["cve_id"] not in all_cve_ids:
                all_cve_ids.append(cve["cve_id"])
            if cve["cvss_score"] > top_cvss:
                top_cvss = cve["cvss_score"]
        all_recommendations.extend(intel.get("recommendations", []))

    # Deduplicate and take top recommendations by priority
    seen_titles = set()
    unique_recommendations = []
    for rec in sorted(all_recommendations, key=lambda r: r.get("priority_order", 3)):
        if rec["title"] not in seen_titles:
            seen_titles.add(rec["title"])
            unique_recommendations.append(rec)

    return {
        "risk_score": risk_score,
        "severity_breakdown": severity_breakdown,
        "prioritized_findings": prioritized_findings,
        "device_total": len(device_rows),
        "finding_total": len(findings),
        "cve_ids": all_cve_ids,
        "cve_count": len(all_cve_ids),
        "top_cvss": top_cvss,
        "top_recommendations": unique_recommendations[:5],
        "remediation_priority": [
            "Remove default credentials from all exposed devices.",
            "Close Telnet and restrict management services to trusted subnets.",
            "Upgrade firmware and validate vendor advisories before re-exposure.",
        ],
    }
