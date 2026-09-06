from flask import Blueprint, flash, redirect, render_template, request, url_for

from database.db import get_dashboard_stats, get_latest_report, save_scan
from database.assets import get_or_create_asset, update_asset_from_scan

from scanner.discovery import discover_devices
from scanner.fingerprint import fingerprint_device
from scanner.pipeline import get_assessment_pipeline
from scanner.report import generate_report
from scanner.risk_score import calculate_risk_score
from scanner.vulnerability import scan_vulnerabilities
from ml.risk_anomaly import analyze_device_ml_risk

from utils.helpers import parse_target_input
from utils.logger import get_logger


scan_bp = Blueprint("scan", __name__)
logger = get_logger(__name__)


def run_scan(target_spec: str, mode: str = "live"):
    """
    Run a SecureVision VAPT scan.

    live:
        Uses the real Nmap discovery pipeline.

    simulated:
        Uses the project's deterministic simulated profiles.

    Live is the default so a normal dashboard scan cannot silently
    fall back to simulated surveillance data.
    """
    targets = parse_target_input(target_spec)

    if not targets:
        raise ValueError("No valid scan targets were supplied.")

    print("\n" + "=" * 70)
    print("SECUREVISION VAPT SCAN")
    print("=" * 70)
    print("Target specification:", target_spec)
    print("Parsed targets:", targets)
    print("Scan mode:", mode)
    print("=" * 70 + "\n")

    discovered = discover_devices(targets, mode=mode)

    print("\n========== DISCOVERY RESULT ==========")
    print("Devices discovered:", len(discovered))
    for item in discovered:
        print(item)
    print("======================================\n")

    if mode == "live" and not discovered:
        raise ValueError(
            "Live Nmap scan completed but no live hosts were discovered."
        )

    device_rows = []
    findings = []

    for device in discovered:
        print("\n========== DEVICE ==========")
        print(device.get("ip_address"))
        print("Ports:", device.get("ports", []))
        print("============================\n")

        fingerprinted = fingerprint_device(device)

        print("\n========== FINGERPRINT ==========")
        print(fingerprinted)
        print("=================================\n")

        device_findings = scan_vulnerabilities(fingerprinted)

        # ML layer: detect unusual exposure profiles independently of the
        # deterministic risk score.  The ML signal is stored in intelligence
        # and does not replace evidence-based CVE matching.
        ml_analysis = analyze_device_ml_risk(fingerprinted, device_findings)
        fingerprinted["intelligence"]["ml_analysis"] = ml_analysis

        print("\n========== ML RISK ANALYSIS ==========")
        print(ml_analysis)
        print("======================================\n")

        print("\n========== FINDINGS ==========")
        for finding in device_findings:
            print(finding)
        print("==============================\n")

        risk_score = calculate_risk_score(device_findings)

        device_rows.append({
            **fingerprinted,
            "risk_score": risk_score,
        })
        findings.extend(device_findings)

    summary = generate_report(device_rows, findings)

    print("\n========== REPORT SUMMARY ==========")
    print(summary)
    print("====================================\n")

    report_id = save_scan(
        target_spec,
        device_rows,
        findings,
        summary,
    )

    print("Saved report ID:", report_id)

    for device in device_rows:
        asset_id = get_or_create_asset(
            device["ip_address"],
            device.get("vendor", "Unknown"),
            device.get("model", "Unknown"),
            report_id,
        )

        update_asset_from_scan(
            asset_id,
            device.get("firmware_version", "Unknown"),
            device.get("risk_score", 0),
            report_id,
        )

    return report_id


@scan_bp.route("/scan", methods=["POST"])
def scan():
    target_spec = request.form.get("targets", "").strip()

    requested_mode = request.form.get("mode", "").strip().lower()
    live_flag = request.form.get("live")

    # Live is the safe/default web-scanner behaviour.
    # Simulation must be explicitly requested.
    if requested_mode == "simulated":
        mode = "simulated"
    else:
        mode = "live"

    print("\n" + "=" * 70)
    print("SECUREVISION VAPT")
    print("=" * 70)
    print("Target:", target_spec)
    print("Live flag:", live_flag)
    print("Requested mode:", requested_mode or "(not specified)")
    print("FINAL MODE:", mode)
    print("=" * 70 + "\n")

    if not target_spec:
        flash(
            "Provide at least one IP address, CIDR block, "
            "or comma-separated device list.",
            "error",
        )
        return redirect(url_for("dashboard.dashboard"))

    try:
        report_id = run_scan(target_spec, mode=mode)

        message = (
            "Live Nmap scan completed and stored in the report history."
            if mode == "live"
            else "Simulated scan completed and stored in the report history."
        )

        flash(message, "success")

        return redirect(
            url_for(
                "dashboard.dashboard",
                report_id=report_id,
            )
        )

    except ValueError as exc:
        logger.exception("Scan failed")
        flash(str(exc), "error")
        return redirect(url_for("dashboard.dashboard"))

    except Exception as exc:
        logger.exception("Unexpected SecureVision scan failure")
        flash(f"Scan failed: {exc}", "error")
        return redirect(url_for("dashboard.dashboard"))


@scan_bp.route("/")
def index():
    stats = get_dashboard_stats()
    latest_report = get_latest_report()
    pipeline = get_assessment_pipeline()

    return render_template(
        "index.html",
        stats=stats,
        latest_report=latest_report,
        pipeline=pipeline,
    )
