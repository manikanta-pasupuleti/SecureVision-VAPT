import json
from datetime import datetime, timedelta
from database.db import get_connection


def get_cve_trends(days=30):
    """Get CVE discovery trends over time."""
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT DATE(r.created_at) as date, COUNT(DISTINCT f.id) as count
            FROM reports r
            JOIN findings f ON f.report_id = r.id
            WHERE r.created_at >= ? AND f.cve_references_json != '[]'
            GROUP BY DATE(r.created_at)
            ORDER BY date ASC
            """,
            (cutoff,),
        ).fetchall()
    
    return [{"date": row["date"], "count": row["count"]} for row in rows]


def get_risk_distribution():
    """Get distribution of findings by severity."""
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT LOWER(severity) as severity, COUNT(*) as count
            FROM findings
            GROUP BY LOWER(severity)
            """
        ).fetchall()
    
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    data = {row["severity"]: row["count"] for row in rows}
    return {sev: data.get(sev, 0) for sev in sorted(severity_order.keys(), key=lambda x: severity_order[x])}


def get_asset_health():
    """Get asset health metrics."""
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        active = connection.execute("SELECT COUNT(*) FROM assets WHERE status = 'active'").fetchone()[0]
        high_risk = connection.execute(
            "SELECT COUNT(*) FROM assets WHERE current_risk_score >= 70"
        ).fetchone()[0]
        critical = connection.execute(
            "SELECT COUNT(*) FROM assets WHERE current_risk_score >= 85"
        ).fetchone()[0]
    
    return {
        "total": total,
        "active": active,
        "high_risk": high_risk,
        "critical": critical,
        "healthy": max(0, total - high_risk),
    }


def get_top_cves(limit=10):
    """Get most frequently discovered CVEs."""
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT f.cve_references_json
            FROM findings f
            WHERE f.cve_references_json != '' AND f.cve_references_json != '[]'
            """
        ).fetchall()
    
    cve_counts = {}
    for row in rows:
        try:
            cves = json.loads(row["cve_references_json"] or "[]")
            for cve in cves:
                cve_id = cve.get("id", "Unknown") if isinstance(cve, dict) else str(cve)
                cve_counts[cve_id] = cve_counts.get(cve_id, 0) + 1
        except (json.JSONDecodeError, TypeError):
            pass
    
    sorted_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{"cve_id": cve_id, "count": count} for cve_id, count in sorted_cves]


def get_device_risk_timeline(days=30):
    """Get average device risk score over time."""
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT DATE(r.created_at) as date, AVG(d.risk_score) as avg_risk
            FROM reports r
            JOIN devices d ON d.report_id = r.id
            WHERE r.created_at >= ?
            GROUP BY DATE(r.created_at)
            ORDER BY date ASC
            """,
            (cutoff,),
        ).fetchall()
    
    return [{"date": row["date"], "avg_risk": round(row["avg_risk"], 1)} for row in rows]


def get_service_exposure():
    """Get most exposed services across all devices."""
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT d.services_json
            FROM devices d
            """
        ).fetchall()
    
    service_counts = {}
    for row in rows:
        services = json.loads(row["services_json"])
        for service in services:
            service_name = service if isinstance(service, str) else service.get("name", "Unknown")
            service_counts[service_name] = service_counts.get(service_name, 0) + 1
    
    sorted_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return [{"service": svc, "count": count} for svc, count in sorted_services]


def get_firmware_outdated():
    """Get count of devices with outdated firmware."""
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT COUNT(*) as count
            FROM devices d
            WHERE d.intelligence_json LIKE '%"firmware_eol": true%'
            """
        ).fetchone()
    
    return rows["count"] if rows else 0


def get_dashboard_analytics():
    """Aggregate all analytics for dashboard."""
    return {
        "cve_trends": get_cve_trends(),
        "risk_distribution": get_risk_distribution(),
        "asset_health": get_asset_health(),
        "top_cves": get_top_cves(),
        "device_risk_timeline": get_device_risk_timeline(),
        "service_exposure": get_service_exposure(),
        "firmware_outdated": get_firmware_outdated(),
    }
