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


def run_scan(target_spec: str, mode: str = "live"):
    """
    Run a SecureVision scan.

    LIVE mode:
        Uses real device discovery / Nmap data.

    SIMULATED mode:
        Uses the existing deterministic simulated device profiles.

    Live is the default because the web scanner should use real
    Nmap observations unless simulation is explicitly requested.
    """

    targets = parse_target_input(target_spec)

    print("\n========== RUN SCAN ==========")
    print("Target specification:", target_spec)
    print("Parsed targets:", targets)
    print("Scan mode:", mode)
    print("==============================\n")

    discovered = discover_devices(targets, mode=mode)

    print("\n========== DISCOVERY RESULT ==========")
    print(discovered)
    print("======================================\n")

    device_rows = []
    findings = []

    for device in discovered:

        print("\n========== DEVICE DISCOVERED ==========")
        print(device)
        print("=======================================\n")

        # ---------------------------------------------------------
        # Fingerprinting
        # ---------------------------------------------------------
        fingerprinted = fingerprint_device(device)

        print("\n========== FINGERPRINT RESULT ==========")
        print(fingerprinted)
        print("========================================\n")

        # ---------------------------------------------------------
        # Vulnerability / intelligence analysis
        # ---------------------------------------------------------
        device_findings = scan_vulnerabilities(fingerprinted)

        print("\n========== VULNERABILITY FINDINGS ==========")
        for finding in device_findings:
            print(finding)
        print("============================================\n")

        # ---------------------------------------------------------
        # Risk calculation
        # ---------------------------------------------------------
        risk_score = calculate_risk_score(device_findings)

        print("Risk score:", risk_score)

        # Keep all fingerprint/intelligence information.
        device_rows.append(
            {
                **fingerprinted,
                "risk_score": risk_score,
            }
        )

        findings.extend(device_findings)

    # -------------------------------------------------------------
    # Generate report
    # -------------------------------------------------------------
    summary = generate_report(device_rows, findings)

    print("\n========== REPORT SUMMARY ==========")
    print(summary)
    print("====================================\n")

    # -------------------------------------------------------------
    # Save scan
    # -------------------------------------------------------------
    report_id = save_scan(
        target_spec,
        device_rows,
        findings,
        summary,
    )

    print("Saved report ID:", report_id)

    # -------------------------------------------------------------
    # Update assets
    # -------------------------------------------------------------
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

    # -------------------------------------------------------------
    # Determine scan mode
    #
    # IMPORTANT:
    # Live/Nmap is now the default.
    #
    # Existing forms using:
    #     <input name="live" ...>
    # will still work.
    #
    # You can explicitly request simulation with:
    #     mode=simulated
    # -------------------------------------------------------------

    requested_mode = (
        request.form.get("mode", "")
        .strip()
        .lower()
    )

    live_flag = request.form.get("live")

    mode = "live"

    print("\n========================================")
    print("     SECUREVISION VAPT SCAN")
    print("========================================")
    print("Target:", target_spec)
    print("Live flag:", live_flag)
    print("Requested mode:", requested_mode)
    print("FINAL MODE:", mode)
    print("========================================\n")

    if not target_spec:
        flash(
            "Provide at least one IP address, CIDR block, "
            "or comma-separated device list.",
            "error",
        )

        return redirect(
            url_for("dashboard.dashboard")
        )

    try:

        report_id = run_scan(
            target_spec,
            mode=mode,
        )

        flash(
            "Live Nmap scan completed and stored in the report history.",
            "success",
        )

        return redirect(
            url_for(
                "dashboard.dashboard",
                report_id=report_id,
            )
        )

    except ValueError as exc:

        logger.exception("Scan failed")

        flash(
            str(exc),
            "error",
        )

        return redirect(
            url_for("dashboard.dashboard")
        )

    except Exception as exc:

        logger.exception(
            "Unexpected SecureVision scan failure"
        )

        flash(
            f"Scan failed: {exc}",
            "error",
        )

        return redirect(
            url_for("dashboard.dashboard")
        )


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