from flask import Blueprint, request, render_template, jsonify

from database.db import get_dashboard_stats, get_latest_report, get_report
from scanner.plugins.manifest import PLUGIN_MANIFESTS
from scanner.analytics import get_dashboard_analytics

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
def dashboard():
    report_id = request.args.get("report_id", type=int)
    report = get_report(report_id) if report_id else get_latest_report()
    stats = get_dashboard_stats()
    return render_template("dashboard.html", report=report, stats=stats, plugins=PLUGIN_MANIFESTS)


@dashboard_bp.route("/api/analytics")
def analytics():
    return jsonify(get_dashboard_analytics())
