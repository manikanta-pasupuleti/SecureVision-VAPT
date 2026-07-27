from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("SECUREVISION_DB_PATH", Path(__file__).resolve().parent / "database.db"))


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def get_or_create_asset(ip_address: str, vendor: str, model: str, report_id: int) -> int:
    """Get existing asset by IP or create new one. Returns asset_id."""
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT id FROM assets WHERE ip_address = ?", (ip_address,)
        ).fetchone()
        if existing:
            return existing["id"]
        cursor = connection.execute(
            """
            INSERT INTO assets (
                ip_address, vendor, model, first_seen, last_seen, current_firmware, current_risk_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ip_address, vendor, model, now, now, "", 0),
        )
        connection.commit()
        return cursor.lastrowid


def update_asset_from_scan(asset_id: int, firmware: str, risk_score: int, report_id: int) -> None:
    """Update asset with latest scan data and record history."""
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with get_connection() as connection:
        asset = connection.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if not asset:
            return
        old_firmware = asset["current_firmware"]
        old_risk = asset["current_risk_score"]
        connection.execute(
            "UPDATE assets SET last_seen = ?, current_firmware = ?, current_risk_score = ? WHERE id = ?",
            (now, firmware, risk_score, asset_id),
        )
        if old_firmware != firmware:
            connection.execute(
                """
                INSERT INTO asset_history (asset_id, timestamp, event_type, old_value, new_value, report_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (asset_id, now, "firmware_change", old_firmware, firmware, report_id),
            )
        if old_risk != risk_score:
            connection.execute(
                """
                INSERT INTO asset_history (asset_id, timestamp, event_type, old_value, new_value, report_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (asset_id, now, "risk_change", str(old_risk), str(risk_score), report_id),
            )
        connection.commit()


def list_assets() -> list:
    """Return all assets with current status."""
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM assets ORDER BY last_seen DESC"
        ).fetchall()
    return [
        {
            "id": row["id"],
            "ip_address": row["ip_address"],
            "vendor": row["vendor"],
            "model": row["model"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "current_firmware": row["current_firmware"],
            "current_risk_score": row["current_risk_score"],
            "status": row["status"],
            "owner": row["owner"],
            "location": row["location"],
            "notes": row["notes"],
        }
        for row in rows
    ]


def get_asset(asset_id: int) -> dict:
    """Get asset detail with full history."""
    with get_connection() as connection:
        asset_row = connection.execute(
            "SELECT * FROM assets WHERE id = ?", (asset_id,)
        ).fetchone()
        if not asset_row:
            return None
        history_rows = connection.execute(
            "SELECT * FROM asset_history WHERE asset_id = ? ORDER BY timestamp DESC",
            (asset_id,),
        ).fetchall()
    return {
        "id": asset_row["id"],
        "ip_address": asset_row["ip_address"],
        "vendor": asset_row["vendor"],
        "model": asset_row["model"],
        "first_seen": asset_row["first_seen"],
        "last_seen": asset_row["last_seen"],
        "current_firmware": asset_row["current_firmware"],
        "current_risk_score": asset_row["current_risk_score"],
        "status": asset_row["status"],
        "owner": asset_row["owner"],
        "location": asset_row["location"],
        "notes": asset_row["notes"],
        "history": [
            {
                "timestamp": h["timestamp"],
                "event_type": h["event_type"],
                "old_value": h["old_value"],
                "new_value": h["new_value"],
                "report_id": h["report_id"],
            }
            for h in history_rows
        ],
    }


def update_asset_metadata(asset_id: int, owner: str = None, location: str = None, notes: str = None) -> None:
    """Update asset metadata (owner, location, notes)."""
    with get_connection() as connection:
        updates = []
        params = []
        if owner is not None:
            updates.append("owner = ?")
            params.append(owner)
        if location is not None:
            updates.append("location = ?")
            params.append(location)
        if notes is not None:
            updates.append("notes = ?")
            params.append(notes)
        if updates:
            params.append(asset_id)
            query = f"UPDATE assets SET {', '.join(updates)} WHERE id = ?"
            connection.execute(query, params)
            connection.commit()


def get_asset_stats() -> dict:
    """Return aggregate asset statistics."""
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        active = connection.execute(
            "SELECT COUNT(*) FROM assets WHERE status = 'active'"
        ).fetchone()[0]
        high_risk = connection.execute(
            "SELECT COUNT(*) FROM assets WHERE current_risk_score >= 70"
        ).fetchone()[0]
        critical_risk = connection.execute(
            "SELECT COUNT(*) FROM assets WHERE current_risk_score >= 90"
        ).fetchone()[0]
    return {
        "total_assets": total,
        "active_assets": active,
        "high_risk_assets": high_risk,
        "critical_risk_assets": critical_risk,
    }
