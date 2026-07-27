from flask import Blueprint, render_template

from database.db import get_dashboard_stats, list_reports

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports")
def reports():
    return render_template("reports.html", reports=list_reports(), stats=get_dashboard_stats())
