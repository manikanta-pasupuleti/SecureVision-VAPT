from __future__ import annotations

from typing import Any, Dict, Iterable, List

from sklearn.ensemble import IsolationForest


FEATURE_NAMES = [
    "open_services",
    "high_risk_services",
    "medium_risk_services",
    "unencrypted_services",
    "cve_count",
    "max_cvss",
    "known_exploitable_cves",
    "default_credential_exposure",
    "firmware_outdated",
    "firmware_eol",
    "surveillance_services",
]

# Bootstrap baseline used only when there is not yet enough historical scan
# data.  It represents ordinary network-device exposure patterns rather than
# known vulnerable products.  IsolationForest is unsupervised, so no labels
# are fabricated and no accuracy claim is made from this baseline.
_BOOTSTRAP_BASELINE = [
    [2, 0, 1, 1, 0, 0.0, 0, 0, 0, 0, 0],
    [3, 0, 1, 1, 0, 0.0, 0, 0, 0, 0, 0],
    [4, 0, 2, 1, 0, 0.0, 0, 0, 0, 0, 0],
    [3, 0, 1, 1, 0, 0.0, 0, 0, 1, 0, 0],
    [4, 1, 1, 1, 0, 0.0, 0, 0, 0, 0, 1],
    [5, 1, 2, 2, 0, 0.0, 0, 0, 0, 0, 1],
    [2, 0, 1, 0, 0, 0.0, 0, 0, 0, 0, 0],
    [4, 0, 2, 2, 0, 0.0, 0, 0, 0, 0, 1],
    [5, 1, 2, 2, 0, 0.0, 0, 0, 1, 0, 1],
    [6, 1, 2, 2, 0, 0.0, 0, 0, 0, 0, 1],
    [3, 0, 1, 1, 0, 0.0, 0, 0, 0, 0, 0],
    [4, 0, 2, 1, 0, 0.0, 0, 0, 0, 0, 0],
]


def build_feature_vector(device: Dict[str, Any], findings: Iterable[Dict[str, Any]]) -> Dict[str, float]:
    """Convert scanner evidence into a numeric ML feature vector.

    The features intentionally come from observed scan/security evidence.
    The existing deterministic risk score is NOT used as an input, avoiding
    a circular model that merely learns the rule-based score.
    """
    findings_list = list(findings or [])
    intel = device.get("intelligence") or {}
    exposure = intel.get("exposure_score") or {}
    firmware = intel.get("firmware_analysis") or {}
    services = intel.get("enriched_services") or []

    high = sum(1 for item in services if item.get("exposure_risk") == "high")
    medium = sum(1 for item in services if item.get("exposure_risk") == "medium")
    unencrypted = sum(1 for item in services if item.get("encrypted") is False)

    cves = intel.get("cve_matches") or []
    cvss_values = []
    exploitable = 0
    for cve in cves:
        try:
            cvss_values.append(float(cve.get("cvss_score", 0) or 0))
        except (TypeError, ValueError):
            pass
        exploitability = str(cve.get("exploitability", "")).lower()
        if exploitability in {"high", "known", "yes", "exploitable"}:
            exploitable += 1

    default_credentials = device.get("default_credentials") or []
    surveillance_services = len(
        set(device.get("services") or []) & {"rtsp", "onvif"}
    )

    return {
        "open_services": float(len(services) or len(device.get("services") or [])),
        "high_risk_services": float(high),
        "medium_risk_services": float(medium),
        "unencrypted_services": float(unencrypted),
        "cve_count": float(len(cves)),
        "max_cvss": float(max(cvss_values) if cvss_values else 0.0),
        "known_exploitable_cves": float(exploitable),
        "default_credential_exposure": float(bool(default_credentials)),
        "firmware_outdated": float(bool(firmware.get("is_outdated"))),
        "firmware_eol": float(bool(firmware.get("is_eol"))),
        "surveillance_services": float(surveillance_services),
    }


def _fit_model(training_rows: List[List[float]]) -> IsolationForest:
    model = IsolationForest(
        n_estimators=200,
        contamination=0.15,
        random_state=42,
    )
    model.fit(training_rows)
    return model


def _percentile_anomaly_score(model: IsolationForest, training_rows: List[List[float]], vector: List[float]) -> float:
    """Map the IsolationForest score to an explainable 0-100 anomaly score."""
    observed = float(model.score_samples([vector])[0])
    baseline_scores = model.score_samples(training_rows)
    percentile = sum(score <= observed for score in baseline_scores) / len(baseline_scores)
    return float(round(max(0.0, min(100.0, (1.0 - percentile) * 100.0)), 1))


def analyze_device_ml_risk(
    device: Dict[str, Any],
    findings: Iterable[Dict[str, Any]],
    *,
    training_rows: List[List[float]] | None = None,
) -> Dict[str, Any]:
    """Run unsupervised anomaly detection on a scanned device.

    The model detects exposure profiles that are unusual compared with the
    baseline. It is a prioritization signal, not proof that a CVE exists.
    """
    features = build_feature_vector(device, findings)
    rows = training_rows or _BOOTSTRAP_BASELINE
    vector = [features[name] for name in FEATURE_NAMES]
    model = _fit_model(rows)
    anomaly_score = _percentile_anomaly_score(model, rows, vector)

    if anomaly_score >= 75:
        level = "High"
    elif anomaly_score >= 50:
        level = "Medium"
    else:
        level = "Low"

    top_signals = []
    signal_labels = {
        "high_risk_services": "high-risk service exposure",
        "unencrypted_services": "unencrypted services",
        "cve_count": "known CVE matches",
        "max_cvss": "high CVSS vulnerability evidence",
        "known_exploitable_cves": "potentially exploitable CVE evidence",
        "default_credential_exposure": "default credential exposure",
        "firmware_outdated": "outdated firmware",
        "firmware_eol": "end-of-life firmware",
        "surveillance_services": "surveillance protocol exposure",
        "open_services": "large exposed service surface",
    }
    ranked = sorted(
        ((name, value) for name, value in features.items() if value > 0),
        key=lambda item: item[1],
        reverse=True,
    )
    for name, value in ranked[:4]:
        label = signal_labels.get(name, name.replace("_", " "))
        top_signals.append(f"{label}: {value:g}")

    return {
        "model": "IsolationForest",
        "task": "unsupervised exposure anomaly detection",
        "anomaly_score": anomaly_score,
        "risk_level": level,
        "top_signals": top_signals,
        "features": features,
        "training_source": "bootstrap baseline" if training_rows is None else "historical scan baseline",
        "interpretation": (
            "Higher scores indicate an exposure profile that is unusual compared "
            "with the learned baseline. This is a prioritization signal and does "
            "not by itself confirm a vulnerability."
        ),
    }
