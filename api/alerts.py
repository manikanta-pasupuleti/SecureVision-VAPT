from flask import Blueprint, jsonify, request, render_template
from scanner.alerting import AlertManager, AlertDetector, init_alerts_db
from database.db import get_report

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@alerts_bp.route("/")
def alerts_page():
    """Display alerts dashboard page."""
    return render_template("alerts.html")


@alerts_bp.route("/list")
def list_alerts():
    """Get all alerts."""
    limit = request.args.get("limit", 50, type=int)
    unacknowledged_only = request.args.get("unacknowledged", False, type=bool)
    
    alert_manager = AlertManager()
    alerts = alert_manager.get_alerts(limit=limit, unacknowledged_only=unacknowledged_only)
    
    return jsonify({
        "total": len(alerts),
        "alerts": alerts
    })


@alerts_bp.route("/summary")
def alert_summary():
    """Get alert summary statistics."""
    alert_manager = AlertManager()
    summary = alert_manager.get_alert_summary()
    
    return jsonify(summary)


@alerts_bp.route("/device/<device_ip>")
def device_alerts(device_ip):
    """Get alerts for a specific device."""
    limit = request.args.get("limit", 20, type=int)
    
    alert_manager = AlertManager()
    alerts = alert_manager.get_alerts_by_device(device_ip, limit=limit)
    
    return jsonify({
        "device_ip": device_ip,
        "total": len(alerts),
        "alerts": alerts
    })


@alerts_bp.route("/<alert_id>/acknowledge", methods=["POST"])
def acknowledge_alert(alert_id):
    """Acknowledge an alert."""
    data = request.get_json() or {}
    acknowledged_by = data.get("acknowledged_by", "system")
    
    alert_manager = AlertManager()
    alert_manager.acknowledge_alert(alert_id, acknowledged_by)
    
    return jsonify({
        "status": "acknowledged",
        "alert_id": alert_id,
        "acknowledged_by": acknowledged_by
    })


@alerts_bp.route("/report/<int:report_id>/detect", methods=["POST"])
def detect_report_alerts(report_id):
    """Detect and generate alerts for a report."""
    report = get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    # Initialize alerts table if needed
    init_alerts_db()
    
    alert_manager = AlertManager()
    detector = AlertDetector(alert_manager)
    
    # Get previous CVEs for comparison
    previous_cves = _get_previous_cves()
    
    # Detect all alerts
    alerts = detector.detect_all_alerts(report, previous_cves)
    
    return jsonify({
        "report_id": report_id,
        "alerts_generated": len(alerts),
        "alerts": alerts
    })


@alerts_bp.route("/thresholds", methods=["GET", "POST"])
def manage_thresholds():
    """Get or update alert thresholds."""
    if request.method == "GET":
        thresholds = _get_thresholds()
        return jsonify(thresholds)
    
    # POST - Update thresholds
    data = request.get_json()
    _save_thresholds(data)
    
    return jsonify({
        "status": "updated",
        "thresholds": data
    })


def _get_previous_cves():
    """Get CVEs from previous scans."""
    from database.db import get_connection
    
    cves = set()
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT DISTINCT cve_references_json FROM findings WHERE cve_references_json != '[]'"
        ).fetchall()
        
        for row in rows:
            try:
                import json
                cve_refs = json.loads(row["cve_references_json"])
                for cve in cve_refs:
                    cve_id = cve.get("id", "") if isinstance(cve, dict) else str(cve)
                    if cve_id:
                        cves.add(cve_id)
            except:
                pass
    
    return cves


def _get_thresholds():
    """Get current alert thresholds."""
    from database.db import get_connection
    import json
    
    with get_connection() as connection:
        row = connection.execute(
            "SELECT value FROM config WHERE key = 'alert_thresholds'"
        ).fetchone()
    
    if row:
        return json.loads(row["value"])
    
    return {
        "critical": 85,
        "high": 70,
        "medium": 50
    }


def _save_thresholds(thresholds):
    """Save alert thresholds to database."""
    from database.db import get_connection
    import json
    
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM config WHERE key = 'alert_thresholds'"
        )
        connection.execute(
            "INSERT INTO config (key, value) VALUES (?, ?)",
            ("alert_thresholds", json.dumps(thresholds))
        )
        connection.commit()
