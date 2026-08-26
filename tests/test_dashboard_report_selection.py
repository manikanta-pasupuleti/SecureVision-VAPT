from core.app_factory import create_app
from database import db as db_module


def _create_report(target_spec, *, vendor="Dahua", model="IPC-HFW-2", firmware="3.210"):
    return db_module.save_scan(
        target_spec,
        [
            {
                "ip_address": "127.0.0.1",
                "vendor": vendor,
                "model": model,
                "firmware_version": firmware,
                "services": ["http"],
                "risk_score": 75,
                "intelligence": {"cve_matches": [], "recommendations": []},
            }
        ],
        [
            {
                "device_ip": "127.0.0.1",
                "severity": "high",
                "title": "Demo finding",
                "description": "demo description",
                "remediation": "fix it",
                "evidence": "demo evidence",
                "technical_explanation": "",
                "business_impact": "",
                "exploitability": "",
                "attack_scenario": "",
                "risk_justification": "",
                "cve_references": [],
                "references": [],
            }
        ],
        {
            "risk_score": 75,
            "severity_breakdown": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "prioritized_findings": [],
            "device_total": 1,
            "finding_total": 1,
            "cve_ids": [],
            "cve_count": 0,
            "top_cvss": 0.0,
            "top_recommendations": [],
            "remediation_priority": [],
        },
    )


def test_dashboard_uses_latest_live_report_for_same_target(monkeypatch, tmp_path):
    db_path = tmp_path / "dashboard-test.db"
    monkeypatch.setenv("SECUREVISION_DB_PATH", str(db_path))
    db_module.DB_PATH = db_path
    db_module.init_db()

    stale_id = _create_report("127.0.0.1", vendor="Dahua", model="IPC-HFW-2", firmware="3.210")
    latest_id = _create_report("127.0.0.1", vendor="Unknown", model="Unknown", firmware="Unknown")

    latest_report = db_module.get_latest_report()
    assert latest_report is not None
    assert latest_report["id"] == latest_id
    assert latest_report["devices"][0]["vendor"] == "Unknown"
    assert db_module.get_report(stale_id) is None

    app = create_app()
    with app.test_client() as client:
        response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"Unknown" in response.data


def test_live_scan_prunes_old_reports_for_same_target(monkeypatch, tmp_path):
    db_path = tmp_path / "live-scan-test.db"
    monkeypatch.setenv("SECUREVISION_DB_PATH", str(db_path))
    db_module.DB_PATH = db_path
    db_module.init_db()

    _create_report("127.0.0.1", vendor="Dahua", model="IPC-HFW-2", firmware="3.210")

    from api.scan import run_scan

    newest_id = run_scan("127.0.0.1", mode="live")

    rows = db_module.get_connection().execute(
        "SELECT id FROM reports WHERE target_spec = ? ORDER BY id ASC",
        ("127.0.0.1",),
    ).fetchall()
    report_ids = [row[0] for row in rows]

    assert newest_id in report_ids
    assert report_ids == [newest_id]
