from __future__ import annotations

import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("SECUREVISION_DB_PATH", Path(__file__).resolve().parent / "database.db"))

DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                target_spec TEXT NOT NULL,
                device_count INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                summary_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                vendor TEXT NOT NULL,
                model TEXT NOT NULL,
                firmware_version TEXT NOT NULL,
                services_json TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                intelligence_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(report_id) REFERENCES reports(id)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                device_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                remediation TEXT NOT NULL,
                evidence TEXT NOT NULL,
                technical_explanation TEXT DEFAULT '',
                business_impact TEXT DEFAULT '',
                exploitability TEXT DEFAULT '',
                attack_scenario TEXT DEFAULT '',
                risk_justification TEXT DEFAULT '',
                cve_references_json TEXT DEFAULT '[]',
                references_json TEXT DEFAULT '[]',
                FOREIGN KEY(report_id) REFERENCES reports(id)
            );

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                vendor TEXT NOT NULL,
                model TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                current_firmware TEXT NOT NULL,
                current_risk_score INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                owner TEXT DEFAULT '',
                location TEXT DEFAULT '',
                notes TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS asset_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                report_id INTEGER,
                FOREIGN KEY(asset_id) REFERENCES assets(id),
                FOREIGN KEY(report_id) REFERENCES reports(id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL UNIQUE,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                device_ip TEXT,
                report_id INTEGER,
                timestamp TEXT NOT NULL,
                metadata TEXT DEFAULT '{}',
                acknowledged INTEGER DEFAULT 0,
                acknowledged_at TEXT,
                acknowledged_by TEXT,
                FOREIGN KEY(report_id) REFERENCES reports(id)
            );
            """
        )
        # Migrate existing databases that predate intelligence_json column
        existing = {row[1] for row in connection.execute("PRAGMA table_info(devices)").fetchall()}
        if "intelligence_json" not in existing:
            connection.execute("ALTER TABLE devices ADD COLUMN intelligence_json TEXT NOT NULL DEFAULT '{}'")
            connection.commit()

        # Migrate existing databases that predate assets tables
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "assets" not in tables:
            connection.executescript(
                """
                CREATE TABLE assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    vendor TEXT NOT NULL,
                    model TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    current_firmware TEXT NOT NULL,
                    current_risk_score INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    owner TEXT DEFAULT '',
                    location TEXT DEFAULT '',
                    notes TEXT DEFAULT ''
                );
                CREATE TABLE asset_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    report_id INTEGER,
                    FOREIGN KEY(asset_id) REFERENCES assets(id),
                    FOREIGN KEY(report_id) REFERENCES reports(id)
                );
                """
            )
            connection.commit()

        # Migrate existing databases that predate intelligence columns in findings
        findings_cols = {row[1] for row in connection.execute("PRAGMA table_info(findings)").fetchall()}
        if "technical_explanation" not in findings_cols:
            for col in ["technical_explanation", "business_impact", "exploitability", "attack_scenario", "risk_justification", "cve_references_json", "references_json"]:
                try:
                    connection.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT DEFAULT ''")
                except sqlite3.OperationalError:
                    pass
            connection.commit()

        # Migrate existing databases that predate alerts table
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "alerts" not in tables:
            connection.execute(
                """
                CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL UNIQUE,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    device_ip TEXT,
                    report_id INTEGER,
                    timestamp TEXT NOT NULL,
                    metadata TEXT DEFAULT '{}',
                    acknowledged INTEGER DEFAULT 0,
                    acknowledged_at TEXT,
                    acknowledged_by TEXT,
                    FOREIGN KEY(report_id) REFERENCES reports(id)
                )
                """
            )
            connection.commit()


def save_scan(target_spec, device_rows, findings, summary):
    created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO reports (created_at, target_spec, device_count, finding_count, risk_score, summary_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                target_spec,
                len(device_rows),
                len(findings),
                summary["risk_score"],
                json.dumps(summary),
            ),
        )
        report_id = cursor.lastrowid

        for device in device_rows:
            connection.execute(
                """
                INSERT INTO devices (
                    report_id, ip_address, vendor, model, firmware_version, services_json, risk_score, intelligence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    device["ip_address"],
                    device["vendor"],
                    device["model"],
                    device["firmware_version"],
                    json.dumps(device["services"]),
                    device["risk_score"],
                    json.dumps(device.get("intelligence", {})),
                ),
            )

        for finding in findings:
            connection.execute(
                """
                INSERT INTO findings (
                    report_id, device_ip, severity, title, description, remediation, evidence,
                    technical_explanation, business_impact, exploitability, attack_scenario,
                    risk_justification, cve_references_json, references_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    finding["device_ip"],
                    finding["severity"],
                    finding["title"],
                    finding["description"],
                    finding["remediation"],
                    finding["evidence"],
                    finding.get("technical_explanation", ""),
                    finding.get("business_impact", ""),
                    finding.get("exploitability", ""),
                    finding.get("attack_scenario", ""),
                    finding.get("risk_justification", ""),
                    json.dumps(finding.get("cve_references", [])),
                    json.dumps(finding.get("references", [])),
                ),
            )

        connection.commit()
        return report_id


def get_dashboard_stats():
    with get_connection() as connection:
        report_count = connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        device_count = connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        finding_count = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        critical_count = connection.execute(
            "SELECT COUNT(*) FROM findings WHERE LOWER(severity) = 'critical'"
        ).fetchone()[0]

    return {
        "report_count": report_count,
        "device_count": device_count,
        "finding_count": finding_count,
        "critical_count": critical_count,
    }


def get_latest_report():
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 1").fetchone()
    return _build_report(row) if row else None


def get_report(report_id):
    if report_id is None:
        return None

    with get_connection() as connection:
        row = connection.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    return _build_report(row) if row else None


def list_reports():
    with get_connection() as connection:
        rows = connection.execute("SELECT * FROM reports ORDER BY id DESC").fetchall()
    return [_build_report(row, include_details=False) for row in rows]


def list_devices():
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT d.*, r.created_at, r.target_spec
            FROM devices d
            JOIN reports r ON r.id = d.report_id
            ORDER BY d.id DESC
            """
        ).fetchall()

    devices = []
    for row in rows:
        devices.append(
            {
                "report_id": row["report_id"],
                "created_at": row["created_at"],
                "target_spec": row["target_spec"],
                "ip_address": row["ip_address"],
                "vendor": row["vendor"],
                "model": row["model"],
                "firmware_version": row["firmware_version"],
                "services": json.loads(row["services_json"]),
                "risk_score": row["risk_score"],
                "intelligence": json.loads(row["intelligence_json"]) if row["intelligence_json"] else {},
            }
        )
    return devices


def get_device_detail(report_id, ip_address):
    with get_connection() as connection:
        device_row = connection.execute(
            """
            SELECT d.*, r.created_at, r.target_spec, r.risk_score AS report_risk_score, r.summary_json
            FROM devices d
            JOIN reports r ON r.id = d.report_id
            WHERE d.report_id = ? AND d.ip_address = ?
            LIMIT 1
            """,
            (report_id, ip_address),
        ).fetchone()

        if device_row is None:
            return None

        finding_rows = connection.execute(
            """
            SELECT *
            FROM findings
            WHERE report_id = ? AND device_ip = ?
            ORDER BY id ASC
            """,
            (report_id, ip_address),
        ).fetchall()

    return {
        "report_id": device_row["report_id"],
        "created_at": device_row["created_at"],
        "target_spec": device_row["target_spec"],
        "report_risk_score": device_row["report_risk_score"],
        "ip_address": device_row["ip_address"],
        "vendor": device_row["vendor"],
        "model": device_row["model"],
        "firmware_version": device_row["firmware_version"],
        "services": json.loads(device_row["services_json"]),
        "risk_score": device_row["risk_score"],
        "intelligence": json.loads(device_row["intelligence_json"]) if device_row["intelligence_json"] else {},
        "summary": json.loads(device_row["summary_json"]),
        "findings": [
            {
                "severity": finding_row["severity"],
                "title": finding_row["title"],
                "description": finding_row["description"],
                "remediation": finding_row["remediation"],
                "evidence": finding_row["evidence"],
                "technical_explanation": finding_row["technical_explanation"] or "",
                "business_impact": finding_row["business_impact"] or "",
                "exploitability": finding_row["exploitability"] or "",
                "attack_scenario": finding_row["attack_scenario"] or "",
                "risk_justification": finding_row["risk_justification"] or "",
                "cve_references": json.loads(finding_row["cve_references_json"] or "[]"),
                "references": json.loads(finding_row["references_json"] or "[]"),
            }
            for finding_row in finding_rows
        ],
    }


def _build_report(row, include_details=True):
    if row is None:
        return None

    report = {
        "id": row["id"],
        "created_at": row["created_at"],
        "target_spec": row["target_spec"],
        "device_count": row["device_count"],
        "finding_count": row["finding_count"],
        "risk_score": row["risk_score"],
        "summary": json.loads(row["summary_json"]),
    }

    if not include_details:
        return report

    with get_connection() as connection:
        device_rows = connection.execute(
            "SELECT * FROM devices WHERE report_id = ? ORDER BY id ASC", (row["id"],)
        ).fetchall()
        finding_rows = connection.execute(
            "SELECT * FROM findings WHERE report_id = ? ORDER BY id ASC", (row["id"],)
        ).fetchall()

    report["devices"] = [
        {
            "ip_address": device_row["ip_address"],
            "vendor": device_row["vendor"],
            "model": device_row["model"],
            "firmware_version": device_row["firmware_version"],
            "services": json.loads(device_row["services_json"]),
            "risk_score": device_row["risk_score"],
            "intelligence": json.loads(device_row["intelligence_json"]) if device_row["intelligence_json"] else {},
        }
        for device_row in device_rows
    ]
    report["findings"] = [
        {
            "device_ip": finding_row["device_ip"],
            "severity": finding_row["severity"],
            "title": finding_row["title"],
            "description": finding_row["description"],
            "remediation": finding_row["remediation"],
            "evidence": finding_row["evidence"],
            "technical_explanation": finding_row["technical_explanation"] or "",
            "business_impact": finding_row["business_impact"] or "",
            "exploitability": finding_row["exploitability"] or "",
            "attack_scenario": finding_row["attack_scenario"] or "",
            "risk_justification": finding_row["risk_justification"] or "",
            "cve_references": json.loads(finding_row["cve_references_json"] or "[]"),
            "references": json.loads(finding_row["references_json"] or "[]"),
        }
        for finding_row in finding_rows
    ]
    return report
