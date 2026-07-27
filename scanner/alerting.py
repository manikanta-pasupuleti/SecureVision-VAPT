"""
Alerting and Notification Engine
Monitors for risk thresholds, new CVEs, and firmware updates.
"""

import json
from datetime import datetime, timedelta
from database.db import get_connection


class AlertManager:
    """Manages alerts and notifications for security events."""
    
    ALERT_TYPES = {
        "risk_threshold": "Risk Score Threshold Exceeded",
        "critical_finding": "Critical Vulnerability Found",
        "new_cve": "New CVE Detected",
        "firmware_update": "Firmware Update Available",
        "device_offline": "Device Offline",
        "credential_exposure": "Default Credentials Detected",
        "service_exposure": "Dangerous Service Exposed"
    }
    
    SEVERITY_LEVELS = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }
    
    def __init__(self):
        self.alerts = []
    
    def create_alert(self, alert_type, severity, title, description, device_ip=None, 
                    report_id=None, metadata=None):
        """Create a new alert."""
        alert = {
            "id": self._generate_alert_id(),
            "type": alert_type,
            "severity": severity,
            "title": title,
            "description": description,
            "device_ip": device_ip,
            "report_id": report_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "metadata": metadata or {},
            "acknowledged": False,
            "acknowledged_at": None,
            "acknowledged_by": None
        }
        self._save_alert(alert)
        return alert
    
    def _generate_alert_id(self):
        """Generate unique alert ID."""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _save_alert(self, alert):
        """Save alert to database."""
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                    alert_id, alert_type, severity, title, description, device_ip, 
                    report_id, timestamp, metadata, acknowledged
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["id"],
                    alert["type"],
                    alert["severity"],
                    alert["title"],
                    alert["description"],
                    alert["device_ip"],
                    alert["report_id"],
                    alert["timestamp"],
                    json.dumps(alert["metadata"]),
                    alert["acknowledged"]
                )
            )
            connection.commit()
    
    def acknowledge_alert(self, alert_id, acknowledged_by=None):
        """Mark alert as acknowledged."""
        with get_connection() as connection:
            connection.execute(
                """
                UPDATE alerts 
                SET acknowledged = 1, acknowledged_at = ?, acknowledged_by = ?
                WHERE alert_id = ?
                """,
                (datetime.utcnow().isoformat() + "Z", acknowledged_by, alert_id)
            )
            connection.commit()
    
    def get_alerts(self, limit=50, unacknowledged_only=False):
        """Get alerts from database."""
        with get_connection() as connection:
            query = "SELECT * FROM alerts"
            params = []
            
            if unacknowledged_only:
                query += " WHERE acknowledged = 0"
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            rows = connection.execute(query, params).fetchall()
        
        return [self._row_to_alert(row) for row in rows]
    
    def get_alerts_by_device(self, device_ip, limit=20):
        """Get alerts for a specific device."""
        with get_connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM alerts 
                WHERE device_ip = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
                """,
                (device_ip, limit)
            ).fetchall()
        
        return [self._row_to_alert(row) for row in rows]
    
    def get_alert_summary(self):
        """Get summary of alerts."""
        with get_connection() as connection:
            total = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            unacknowledged = connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
            ).fetchone()[0]
            
            severity_counts = {}
            rows = connection.execute(
                "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
            ).fetchall()
            for row in rows:
                severity_counts[row["severity"]] = row["count"]
        
        return {
            "total": total,
            "unacknowledged": unacknowledged,
            "by_severity": severity_counts
        }
    
    def _row_to_alert(self, row):
        """Convert database row to alert dict."""
        return {
            "id": row["alert_id"],
            "type": row["alert_type"],
            "severity": row["severity"],
            "title": row["title"],
            "description": row["description"],
            "device_ip": row["device_ip"],
            "report_id": row["report_id"],
            "timestamp": row["timestamp"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "acknowledged": bool(row["acknowledged"]),
            "acknowledged_at": row["acknowledged_at"],
            "acknowledged_by": row["acknowledged_by"]
        }


class AlertDetector:
    """Detects security events and generates alerts."""
    
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
    
    def check_risk_thresholds(self, report_data, thresholds=None):
        """Check if risk scores exceed thresholds."""
        if thresholds is None:
            thresholds = {
                "critical": 85,
                "high": 70,
                "medium": 50
            }
        
        alerts = []
        risk_score = report_data.get("risk_score", 0)
        
        if risk_score >= thresholds["critical"]:
            alert = self.alert_manager.create_alert(
                alert_type="risk_threshold",
                severity="critical",
                title="Critical Risk Score Threshold Exceeded",
                description=f"Overall risk score {risk_score}/100 exceeds critical threshold ({thresholds['critical']})",
                report_id=report_data.get("id"),
                metadata={"risk_score": risk_score, "threshold": thresholds["critical"]}
            )
            alerts.append(alert)
        elif risk_score >= thresholds["high"]:
            alert = self.alert_manager.create_alert(
                alert_type="risk_threshold",
                severity="high",
                title="High Risk Score Threshold Exceeded",
                description=f"Overall risk score {risk_score}/100 exceeds high threshold ({thresholds['high']})",
                report_id=report_data.get("id"),
                metadata={"risk_score": risk_score, "threshold": thresholds["high"]}
            )
            alerts.append(alert)
        
        # Check per-device thresholds
        for device in report_data.get("devices", []):
            device_risk = device.get("risk_score", 0)
            if device_risk >= thresholds["critical"]:
                alert = self.alert_manager.create_alert(
                    alert_type="risk_threshold",
                    severity="critical",
                    title=f"Device Critical Risk: {device.get('vendor')} {device.get('model')}",
                    description=f"Device {device.get('ip_address')} risk score {device_risk}/100 exceeds critical threshold",
                    device_ip=device.get("ip_address"),
                    report_id=report_data.get("id"),
                    metadata={"device_risk": device_risk, "vendor": device.get("vendor")}
                )
                alerts.append(alert)
        
        return alerts
    
    def check_critical_findings(self, report_data):
        """Alert on critical findings."""
        alerts = []
        summary = report_data.get("summary", {})
        critical_count = summary.get("severity_breakdown", {}).get("critical", 0)
        
        if critical_count > 0:
            alert = self.alert_manager.create_alert(
                alert_type="critical_finding",
                severity="critical",
                title=f"{critical_count} Critical Vulnerabilities Found",
                description=f"Report {report_data.get('id')} contains {critical_count} critical findings",
                report_id=report_data.get("id"),
                metadata={"critical_count": critical_count}
            )
            alerts.append(alert)
        
        return alerts
    
    def check_new_cves(self, report_data, previous_cves=None):
        """Detect new CVEs not seen before."""
        if previous_cves is None:
            previous_cves = set()
        
        alerts = []
        current_cves = set()
        
        for finding in report_data.get("findings", []):
            cve_refs = finding.get("cve_references", [])
            for cve in cve_refs:
                cve_id = cve.get("id", "") if isinstance(cve, dict) else str(cve)
                current_cves.add(cve_id)
        
        new_cves = current_cves - previous_cves
        
        for cve_id in new_cves:
            alert = self.alert_manager.create_alert(
                alert_type="new_cve",
                severity="high",
                title=f"New CVE Detected: {cve_id}",
                description=f"CVE {cve_id} detected in scan results",
                report_id=report_data.get("id"),
                metadata={"cve_id": cve_id}
            )
            alerts.append(alert)
        
        return alerts
    
    def check_firmware_updates(self, report_data):
        """Check for available firmware updates."""
        alerts = []
        
        for device in report_data.get("devices", []):
            intelligence = device.get("intelligence", {})
            firmware_info = intelligence.get("firmware_analysis", {})
            
            if firmware_info.get("firmware_eol"):
                alert = self.alert_manager.create_alert(
                    alert_type="firmware_update",
                    severity="high",
                    title=f"Firmware End-of-Life: {device.get('vendor')} {device.get('model')}",
                    description=f"Device {device.get('ip_address')} firmware {device.get('firmware_version')} is end-of-life",
                    device_ip=device.get("ip_address"),
                    report_id=report_data.get("id"),
                    metadata={
                        "current_version": device.get("firmware_version"),
                        "latest_version": firmware_info.get("latest_version"),
                        "vendor": device.get("vendor")
                    }
                )
                alerts.append(alert)
            elif firmware_info.get("latest_version") and \
                 firmware_info.get("latest_version") != device.get("firmware_version"):
                alert = self.alert_manager.create_alert(
                    alert_type="firmware_update",
                    severity="medium",
                    title=f"Firmware Update Available: {device.get('vendor')} {device.get('model')}",
                    description=f"Device {device.get('ip_address')} has firmware update available",
                    device_ip=device.get("ip_address"),
                    report_id=report_data.get("id"),
                    metadata={
                        "current_version": device.get("firmware_version"),
                        "latest_version": firmware_info.get("latest_version"),
                        "vendor": device.get("vendor")
                    }
                )
                alerts.append(alert)
        
        return alerts
    
    def check_credential_exposure(self, report_data):
        """Alert on default credential findings."""
        alerts = []
        
        for finding in report_data.get("findings", []):
            title_lower = finding.get("title", "").lower()
            if "default" in title_lower and "credential" in title_lower:
                alert = self.alert_manager.create_alert(
                    alert_type="credential_exposure",
                    severity="critical",
                    title=f"Default Credentials Exposed: {finding.get('device_ip')}",
                    description=finding.get("description", ""),
                    device_ip=finding.get("device_ip"),
                    report_id=report_data.get("report_id"),
                    metadata={"finding_title": finding.get("title")}
                )
                alerts.append(alert)
        
        return alerts
    
    def check_service_exposure(self, report_data):
        """Alert on dangerous service exposure."""
        alerts = []
        dangerous_services = ["telnet", "ftp", "http", "rtsp", "onvif"]
        
        for device in report_data.get("devices", []):
            services = device.get("services", [])
            exposed_services = []
            
            for service in services:
                service_name = service if isinstance(service, str) else service.get("name", "")
                if any(dangerous in service_name.lower() for dangerous in dangerous_services):
                    exposed_services.append(service_name)
            
            if exposed_services:
                alert = self.alert_manager.create_alert(
                    alert_type="service_exposure",
                    severity="high",
                    title=f"Dangerous Services Exposed: {device.get('ip_address')}",
                    description=f"Device exposes: {', '.join(exposed_services)}",
                    device_ip=device.get("ip_address"),
                    report_id=report_data.get("id"),
                    metadata={"services": exposed_services}
                )
                alerts.append(alert)
        
        return alerts
    
    def detect_all_alerts(self, report_data, previous_cves=None):
        """Run all alert detection checks."""
        all_alerts = []
        
        all_alerts.extend(self.check_risk_thresholds(report_data))
        all_alerts.extend(self.check_critical_findings(report_data))
        all_alerts.extend(self.check_new_cves(report_data, previous_cves))
        all_alerts.extend(self.check_firmware_updates(report_data))
        all_alerts.extend(self.check_credential_exposure(report_data))
        all_alerts.extend(self.check_service_exposure(report_data))
        
        return all_alerts


def init_alerts_db():
    """Initialize alerts table in database."""
    with get_connection() as connection:
        connection.execute(
            """
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
            )
            """
        )
        connection.commit()
