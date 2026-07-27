from flask import Blueprint, flash, redirect, render_template, request, url_for

from database.db import get_dashboard_stats, get_latest_report, save_scan
from database.assets import get_or_create_asset, update_asset_from_scan
from scanner.discovery import discover_devices
from scanner.fingerprint import fingerprint_device
from scanner.pipeline import get_assessment_pipeline
from scanner.report import generate_report
from scanner.risk_score import calculate_risk_score
from scanner.vulnerability import scan_vulnerabilities
from utils.helpers import parse_target_input
from utils.logger import get_logger

scan_bp = Blueprint("scan", __name__)
logger = get_logger(__name__)


def run_scan(target_spec: str, mode: str = "simulated"):
    targets = parse_target_input(target_spec)
    discovered = discover_devices(targets, mode=mode)

    device_rows = []
    findings = []

    for device in discovered:
        fingerprinted = fingerprint_device(device)
        device_findings = scan_vulnerabilities(fingerprinted)
        risk_score = calculate_risk_score(device_findings)

        device_rows.append({**fingerprinted, "risk_score": risk_score})
        findings.extend(device_findings)

    summary = generate_report(device_rows, findings)
    report_id = save_scan(target_spec, device_rows, findings, summary)

    # Phase 2: Update assets
    for device in device_rows:
        asset_id = get_or_create_asset(
            device["ip_address"],
            device["vendor"],
            device["model"],
            report_id,
        )
        update_asset_from_scan(
            asset_id,
            device["firmware_version"],
            device["risk_score"],
            report_id,
        )

    return report_id


@scan_bp.route("/scan", methods=["POST"])
def scan():
    target_spec = request.form.get("targets", "").strip()
    live_flag = request.form.get("live")
    mode = "live" if live_flag else "simulated"
    if not target_spec:
        flash("Provide at least one IP address, CIDR block, or comma-separated device list.", "error")
        return redirect(url_for("dashboard.dashboard"))

    try:
        report_id = run_scan(target_spec, mode=mode)
        flash("Scan completed and stored in the report history.", "success")
        return redirect(url_for("dashboard.dashboard", report_id=report_id))
    except ValueError as exc:
        logger.exception("Scan failed")
        flash(str(exc), "error")
        return redirect(url_for("dashboard.dashboard"))


@scan_bp.route("/")
def index():
    stats = get_dashboard_stats()
    latest_report = get_latest_report()
    pipeline = get_assessment_pipeline()
    return render_template("index.html", stats=stats, latest_report=latest_report, pipeline=pipeline)
