from flask import Blueprint, flash, redirect, render_template, url_for

from database.db import get_dashboard_stats, list_devices, get_device_detail

devices_bp = Blueprint("devices", __name__)


@devices_bp.route("/devices")
def devices():
    return render_template("devices.html", devices=list_devices(), stats=get_dashboard_stats())


@devices_bp.route("/devices/<int:report_id>/<path:ip_address>")
def device_detail(report_id, ip_address):
    device = get_device_detail(report_id, ip_address)
    if device is None:
        flash("Device not found for the selected report.", "error")
        return redirect(url_for("devices.devices"))

    return render_template("device_detail.html", device=device, stats=get_dashboard_stats())
