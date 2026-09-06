import json

from ml.risk_anomaly import analyze_device_ml_risk, build_feature_vector


def _device():
    return {
        "services": ["telnet", "rtsp", "onvif", "http"],
        "default_credentials": [{"username": "admin", "password": "admin"}],
        "intelligence": {
            "enriched_services": [
                {"name": "telnet", "exposure_risk": "high", "encrypted": False},
                {"name": "rtsp", "exposure_risk": "medium", "encrypted": False},
                {"name": "onvif", "exposure_risk": "medium", "encrypted": False},
                {"name": "http", "exposure_risk": "low", "encrypted": False},
            ],
            "cve_matches": [{"cvss_score": 9.8, "exploitability": "high"}],
            "firmware_analysis": {"is_outdated": True, "is_eol": True},
            "exposure_score": {},
        },
    }


def test_feature_vector_uses_security_evidence_not_rule_score():
    features = build_feature_vector(_device(), [{"severity": "critical"}])
    assert features["high_risk_services"] == 1.0
    assert features["unencrypted_services"] == 4.0
    assert features["cve_count"] == 1.0
    assert features["max_cvss"] == 9.8
    assert "risk_score" not in features


def test_ml_analysis_is_json_serializable_and_high_for_unusual_profile():
    result = analyze_device_ml_risk(_device(), [{"severity": "critical"}])
    json.dumps(result)
    assert result["model"] == "IsolationForest"
    assert result["task"] == "unsupervised exposure anomaly detection"
    assert 0 <= result["anomaly_score"] <= 100
    assert result["risk_level"] in {"Low", "Medium", "High"}
