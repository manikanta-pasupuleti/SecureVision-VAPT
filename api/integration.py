"""
SIEM/SOC Integration API
Provides comprehensive REST endpoints for external system integration.
"""

from flask import Blueprint, jsonify, request
from database.db import get_connection, get_report, list_reports, list_devices
from database.assets import list_assets, get_asset, get_asset_stats
import json
from datetime import datetime, timedelta

integration_bp = Blueprint("integration", __name__, url_prefix="/api/v1")


# ============================================================================
# ASSETS ENDPOINTS
# ============================================================================

@integration_bp.route("/assets", methods=["GET"])
def get_assets():
    """Get all assets with optional filtering."""
    status = request.args.get("status", type=str)
    risk_min = request.args.get("risk_min", 0, type=int)
    risk_max = request.args.get("risk_max", 100, type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    
    assets = list_assets()
    
    # Apply filters
    if status:
        assets = [a for a in assets if a.get("status") == status]
    
    assets = [a for a in assets if risk_min <= a.get("current_risk_score", 0) <= risk_max]
    
    # Pagination
    total = len(assets)
    assets = assets[offset:offset + limit]
    
    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "assets": assets
    })


@integration_bp.route("/assets/<int:asset_id>", methods=["GET"])
def get_asset_detail(asset_id):
    """Get detailed asset information."""
    asset = get_asset(asset_id)
    if not asset:
        return jsonify({"error": "Asset not found"}), 404
    
    return jsonify(asset)


@integration_bp.route("/assets/search", methods=["POST"])
def search_assets():
    """Search assets by criteria."""
    data = request.get_json() or {}
    
    assets = list_assets()
    
    # Filter by vendor
    if "vendor" in data:
        assets = [a for a in assets if data["vendor"].lower() in a.get("vendor", "").lower()]
    
    # Filter by IP range (simple substring match)
    if "ip_pattern" in data:
        assets = [a for a in assets if data["ip_pattern"] in a.get("ip_address", "")]
    
    # Filter by risk score range
    if "risk_range" in data:
        min_risk = data["risk_range"].get("min", 0)
        max_risk = data["risk_range"].get("max", 100)
        assets = [a for a in assets if min_risk <= a.get("current_risk_score", 0) <= max_risk]
    
    # Filter by status
    if "status" in data:
        assets = [a for a in assets if a.get("status") == data["status"]]
    
    return jsonify({
        "total": len(assets),
        "assets": assets
    })


@integration_bp.route("/assets/stats", methods=["GET"])
def get_assets_stats():
    """Get asset statistics."""
    stats = get_asset_stats()
    return jsonify(stats)


# ============================================================================
# FINDINGS ENDPOINTS
# ============================================================================

@integration_bp.route("/findings", methods=["GET"])
def get_findings():
    """Get all findings with optional filtering."""
    severity = request.args.get("severity", type=str)
    device_ip = request.args.get("device_ip", type=str)
    report_id = request.args.get("report_id", type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    
    with get_connection() as connection:
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        
        if severity:
            query += " AND LOWER(severity) = ?"
            params.append(severity.lower())
        
        if device_ip:
            query += " AND device_ip = ?"
            params.append(device_ip)
        
        if report_id:
            query += " AND report_id = ?"
            params.append(report_id)
        
        # Get total count
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        total = connection.execute(count_query, params).fetchone()[0]
        
        # Get paginated results
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        rows = connection.execute(query, params).fetchall()
    
    findings = [_row_to_finding(row) for row in rows]
    
    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "findings": findings
    })


@integration_bp.route("/findings/<int:finding_id>", methods=["GET"])
def get_finding_detail(finding_id):
    """Get detailed finding information."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM findings WHERE id = ?",
            (finding_id,)
        ).fetchone()
    
    if not row:
        return jsonify({"error": "Finding not found"}), 404
    
    return jsonify(_row_to_finding(row))


@integration_bp.route("/findings/search", methods=["POST"])
def search_findings():
    """Search findings by criteria."""
    data = request.get_json() or {}
    
    with get_connection() as connection:
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        
        # Search by title/description
        if "keyword" in data:
            keyword = f"%{data['keyword']}%"
            query += " AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ?)"
            params.extend([keyword.lower(), keyword.lower()])
        
        # Filter by severity
        if "severity" in data:
            query += " AND LOWER(severity) = ?"
            params.append(data["severity"].lower())
        
        # Filter by CVE
        if "cve_id" in data:
            query += " AND cve_references_json LIKE ?"
            params.append(f"%{data['cve_id']}%")
        
        # Filter by device
        if "device_ip" in data:
            query += " AND device_ip = ?"
            params.append(data["device_ip"])
        
        # Filter by date range
        if "date_range" in data:
            start_date = data["date_range"].get("start")
            end_date = data["date_range"].get("end")
            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)
            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)
        
        query += " ORDER BY id DESC LIMIT 100"
        rows = connection.execute(query, params).fetchall()
    
    findings = [_row_to_finding(row) for row in rows]
    
    return jsonify({
        "total": len(findings),
        "findings": findings
    })


@integration_bp.route("/findings/by-cve/<cve_id>", methods=["GET"])
def get_findings_by_cve(cve_id):
    """Get all findings for a specific CVE."""
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM findings WHERE cve_references_json LIKE ? ORDER BY id DESC",
            (f"%{cve_id}%",)
        ).fetchall()
    
    findings = [_row_to_finding(row) for row in rows]
    
    return jsonify({
        "cve_id": cve_id,
        "total": len(findings),
        "findings": findings
    })


@integration_bp.route("/findings/stats", methods=["GET"])
def get_findings_stats():
    """Get findings statistics."""
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        
        severity_stats = {}
        rows = connection.execute(
            "SELECT LOWER(severity) as severity, COUNT(*) as count FROM findings GROUP BY LOWER(severity)"
        ).fetchall()
        for row in rows:
            severity_stats[row["severity"]] = row["count"]
        
        # Get top CVEs
        cve_rows = connection.execute(
            """
            SELECT cve_references_json, COUNT(*) as count 
            FROM findings 
            WHERE cve_references_json != '[]'
            GROUP BY cve_references_json
            ORDER BY count DESC
            LIMIT 10
            """
        ).fetchall()
        
        top_cves = []
        for row in cve_rows:
            try:
                cves = json.loads(row["cve_references_json"])
                for cve in cves:
                    cve_id = cve.get("id", "Unknown") if isinstance(cve, dict) else str(cve)
                    top_cves.append({"cve_id": cve_id, "count": row["count"]})
            except:
                pass
    
    return jsonify({
        "total": total,
        "by_severity": severity_stats,
        "top_cves": top_cves[:10]
    })


# ============================================================================
# REPORTS ENDPOINTS
# ============================================================================

@integration_bp.route("/reports", methods=["GET"])
def get_reports():
    """Get all reports with optional filtering."""
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    
    reports = list_reports()
    total = len(reports)
    reports = reports[offset:offset + limit]
    
    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "reports": reports
    })


@integration_bp.route("/reports/<int:report_id>", methods=["GET"])
def get_report_detail(report_id):
    """Get detailed report information."""
    report = get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    return jsonify(report)


@integration_bp.route("/reports/<int:report_id>/summary", methods=["GET"])
def get_report_summary(report_id):
    """Get report summary without detailed findings."""
    report = get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    return jsonify({
        "id": report["id"],
        "created_at": report["created_at"],
        "target_spec": report["target_spec"],
        "device_count": report["device_count"],
        "finding_count": report["finding_count"],
        "risk_score": report["risk_score"],
        "summary": report["summary"]
    })


@integration_bp.route("/reports/<int:report_id>/devices", methods=["GET"])
def get_report_devices(report_id):
    """Get devices from a report."""
    report = get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    return jsonify({
        "report_id": report_id,
        "total": len(report.get("devices", [])),
        "devices": report.get("devices", [])
    })


@integration_bp.route("/reports/<int:report_id>/findings", methods=["GET"])
def get_report_findings(report_id):
    """Get findings from a report."""
    severity = request.args.get("severity", type=str)
    
    report = get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    findings = report.get("findings", [])
    
    if severity:
        findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]
    
    return jsonify({
        "report_id": report_id,
        "total": len(findings),
        "findings": findings
    })


@integration_bp.route("/reports/search", methods=["POST"])
def search_reports():
    """Search reports by criteria."""
    data = request.get_json() or {}
    
    reports = list_reports()
    
    # Filter by target
    if "target" in data:
        reports = [r for r in reports if data["target"] in r.get("target_spec", "")]
    
    # Filter by risk score range
    if "risk_range" in data:
        min_risk = data["risk_range"].get("min", 0)
        max_risk = data["risk_range"].get("max", 100)
        reports = [r for r in reports if min_risk <= r.get("risk_score", 0) <= max_risk]
    
    # Filter by date range
    if "date_range" in data:
        start_date = data["date_range"].get("start")
        end_date = data["date_range"].get("end")
        for report in reports:
            report_date = report.get("created_at", "")
            if start_date and report_date < start_date:
                reports.remove(report)
            if end_date and report_date > end_date:
                reports.remove(report)
    
    return jsonify({
        "total": len(reports),
        "reports": reports
    })


# ============================================================================
# DEVICES ENDPOINTS
# ============================================================================

@integration_bp.route("/devices", methods=["GET"])
def get_devices():
    """Get all devices with optional filtering."""
    vendor = request.args.get("vendor", type=str)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    
    devices = list_devices()
    
    if vendor:
        devices = [d for d in devices if vendor.lower() in d.get("vendor", "").lower()]
    
    total = len(devices)
    devices = devices[offset:offset + limit]
    
    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "devices": devices
    })


@integration_bp.route("/devices/<device_ip>", methods=["GET"])
def get_device_by_ip(device_ip):
    """Get device by IP address."""
    devices = list_devices()
    device = next((d for d in devices if d.get("ip_address") == device_ip), None)
    
    if not device:
        return jsonify({"error": "Device not found"}), 404
    
    return jsonify(device)


@integration_bp.route("/devices/<device_ip>/findings", methods=["GET"])
def get_device_findings(device_ip):
    """Get all findings for a device."""
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM findings WHERE device_ip = ? ORDER BY id DESC",
            (device_ip,)
        ).fetchall()
    
    findings = [_row_to_finding(row) for row in rows]
    
    return jsonify({
        "device_ip": device_ip,
        "total": len(findings),
        "findings": findings
    })


# ============================================================================
# HEALTH & STATUS ENDPOINTS
# ============================================================================

@integration_bp.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "1.0"
    })


@integration_bp.route("/stats", methods=["GET"])
def get_system_stats():
    """Get overall system statistics."""
    with get_connection() as connection:
        total_reports = connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        total_devices = connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        total_findings = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        total_assets = connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        total_alerts = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    
    return jsonify({
        "reports": total_reports,
        "devices": total_devices,
        "findings": total_findings,
        "assets": total_assets,
        "alerts": total_alerts,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _row_to_finding(row):
    """Convert database row to finding dict."""
    return {
        "id": row["id"],
        "report_id": row["report_id"],
        "device_ip": row["device_ip"],
        "severity": row["severity"],
        "title": row["title"],
        "description": row["description"],
        "remediation": row["remediation"],
        "evidence": row["evidence"],
        "technical_explanation": row["technical_explanation"] or "",
        "business_impact": row["business_impact"] or "",
        "exploitability": row["exploitability"] or "",
        "attack_scenario": row["attack_scenario"] or "",
        "risk_justification": row["risk_justification"] or "",
        "cve_references": json.loads(row["cve_references_json"] or "[]"),
        "references": json.loads(row["references_json"] or "[]")
    }
