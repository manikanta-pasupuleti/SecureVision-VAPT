from flask import Blueprint, render_template, request, redirect, url_for, flash

from database.assets import (
    list_assets,
    get_asset,
    update_asset_metadata,
    get_asset_stats,
)
from database.db import get_dashboard_stats

assets_bp = Blueprint("assets", __name__)


@assets_bp.route("/assets")
def assets():
    """List all discovered assets."""
    assets_list = list_assets()
    asset_stats = get_asset_stats()
    stats = get_dashboard_stats()
    return render_template(
        "assets.html",
        assets=assets_list,
        asset_stats=asset_stats,
        stats=stats,
    )


@assets_bp.route("/assets/<int:asset_id>")
def asset_detail(asset_id):
    """View asset detail with history."""
    asset = get_asset(asset_id)
    if not asset:
        flash("Asset not found.", "error")
        return redirect(url_for("assets.assets"))
    stats = get_dashboard_stats()
    return render_template("asset_detail.html", asset=asset, stats=stats)


@assets_bp.route("/assets/<int:asset_id>/metadata", methods=["POST"])
def update_metadata(asset_id):
    """Update asset metadata (owner, location, notes)."""
    owner = request.form.get("owner", "").strip()
    location = request.form.get("location", "").strip()
    notes = request.form.get("notes", "").strip()

    update_asset_metadata(asset_id, owner=owner, location=location, notes=notes)
    flash("Asset metadata updated.", "success")
    return redirect(url_for("assets.asset_detail", asset_id=asset_id))
