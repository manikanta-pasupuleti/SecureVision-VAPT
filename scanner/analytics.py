from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from database.db import get_connection


def _safe_json(value, fallback):
    try:
        return json.loads(value) if value else fallback
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def _date_only(value):
    text = str(value or "")
    return text[:10] if len(text) >= 10 else text


def _canonical_service(name, port=0):
    name = str(name or "").strip().lower()
    try:
        port = int(port or 0)
    except (TypeError, ValueError):
        port = 0

    if port == 443 and name in {"http", "ssl/http", "ssl", "https"}:
        return "https"
    if port == 80 and name in {"http", "www", "http-proxy"}:
        return "http"
    if name in {"ssl/http", "https-alt"}:
        return "https"
    if name == "www":
        return "http"
    return name


def get_dashboard_analytics():
    """Build dashboard analytics strictly from persisted scan evidence.

    - Risk Distribution = persisted finding severities.
    - CVE analytics = only persisted intelligence CVE matches.
    - Device Risk Timeline = only dates on which a real report exists.
    - Service Exposure = one canonical service entry per device/service.
    """
    now = datetime.utcnow().date()
    start = now - timedelta(days=29)

    with get_connection() as connection:
        report_rows = connection.execute(
            "SELECT id, created_at, risk_score FROM reports ORDER BY id ASC"
        ).fetchall()
        device_rows = connection.execute(
            "SELECT report_id, ip_address, services_json, risk_score, intelligence_json "
            "FROM devices ORDER BY id ASC"
        ).fetchall()
        finding_rows = connection.execute(
            "SELECT report_id, severity, title FROM findings ORDER BY id ASC"
        ).fetchall()
        asset_rows = connection.execute(
            "SELECT status, current_risk_score FROM assets"
        ).fetchall()

    report_dates = {row["id"]: _date_only(row["created_at"]) for row in report_rows}

    # Risk distribution is the actual finding severity distribution.
    # This makes a report containing one medium + one low finding display
    # exactly medium=1 and low=1 instead of classifying the whole device as low.
    risk_distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for row in finding_rows:
        severity = str(row["severity"] or "info").strip().lower()
        if severity not in risk_distribution:
            severity = "info"
        risk_distribution[severity] += 1

    # CVE analytics: only persisted intelligence matches count.
    cve_counts = Counter()
    cve_by_date = Counter()
    for row in device_rows:
        intelligence = _safe_json(row["intelligence_json"], {})
        for cve in intelligence.get("cve_matches", []) or []:
            if not isinstance(cve, dict):
                continue
            cve_id = cve.get("cve_id")
            if not cve_id:
                continue
            cve_counts[cve_id] += 1
            report_date = report_dates.get(row["report_id"], "")
            if report_date:
                cve_by_date[report_date] += 1

    top_cves = [
        {"cve_id": cve_id, "count": count}
        for cve_id, count in cve_counts.most_common(10)
    ]

    cve_trends = []
    cursor = start
    while cursor <= now:
        day = cursor.isoformat()
        cve_trends.append({"date": day, "count": cve_by_date.get(day, 0)})
        cursor += timedelta(days=1)

    # Timeline contains ONLY actual report dates. No synthetic zero-valued
    # dates are inserted for days where the user did not run a scan.
    daily_risks = defaultdict(list)
    for row in device_rows:
        report_date = report_dates.get(row["report_id"], "")
        if not report_date or report_date < start.isoformat() or report_date > now.isoformat():
            continue
        daily_risks[report_date].append(int(row["risk_score"] or 0))

    device_risk_timeline = [
        {
            "date": day,
            "avg_risk": round(sum(values) / len(values), 2),
        }
        for day, values in sorted(daily_risks.items())
        if values
    ]

    # Service exposure: deduplicate by canonical service name within each
    # device/report, and normalize 443/http -> https.
    service_counts = Counter()
    for row in device_rows:
        intelligence = _safe_json(row["intelligence_json"], {})
        seen = set()

        for item in intelligence.get("enriched_services", []) or []:
            if not isinstance(item, dict):
                continue
            name = _canonical_service(item.get("name"), item.get("port"))
            if name:
                seen.add(name)

        # Older reports may have only services_json. Use it as fallback and
        # never allow it to create a second copy of an already-known service.
        for service in _safe_json(row["services_json"], []) or []:
            name = _canonical_service(service)
            if name:
                seen.add(name)

        for service in seen:
            service_counts[service] += 1

    service_exposure = [
        {"service": service, "count": count}
        for service, count in sorted(
            service_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )[:10]
    ]

    total_assets = len(asset_rows)
    active_assets = sum(
        1 for row in asset_rows if str(row["status"] or "").lower() == "active"
    )
    high_risk_assets = sum(
        1 for row in asset_rows if int(row["current_risk_score"] or 0) >= 70
    )
    critical_assets = sum(
        1 for row in asset_rows if int(row["current_risk_score"] or 0) >= 90
    )

    return {
        "cve_trends": cve_trends,
        "risk_distribution": risk_distribution,
        "asset_health": {
            "total": total_assets,
            "active": active_assets,
            "high_risk": high_risk_assets,
            "critical": critical_assets,
        },
        "top_cves": top_cves,
        "device_risk_timeline": device_risk_timeline,
        "service_exposure": service_exposure,
    }
