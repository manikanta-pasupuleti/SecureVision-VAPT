from flask import Blueprint, jsonify, request, render_template
from scanner.remediation_guide import (
    get_remediation_workflow,
    get_all_workflows,
    get_workflow_summary,
    get_workflow_steps,
    map_finding_to_workflow,
    generate_remediation_plan
)
from database.db import get_report

remediation_bp = Blueprint("remediation", __name__, url_prefix="/api/remediation")


@remediation_bp.route("/")
def list_workflows():
    """Display remediation guidance page."""
    return render_template("remediation.html")


@remediation_bp.route("/workflows")
def list_workflows_api():
    """Get all available remediation workflows (API)."""
    workflows = get_all_workflows()
    return jsonify({
        "total": len(workflows),
        "workflows": [
            {
                "id": wf_id,
                "title": wf["title"],
                "severity": wf["severity"],
                "time_estimate": wf["time_estimate"],
                "steps": len(wf["steps"])
            }
            for wf_id, wf in workflows.items()
        ]
    })


@remediation_bp.route("/workflow/<workflow_id>")
def get_workflow(workflow_id):
    """Get detailed remediation workflow."""
    workflow = get_remediation_workflow(workflow_id)
    if not workflow:
        return jsonify({"error": "Workflow not found"}), 404
    
    return jsonify({
        "id": workflow_id,
        "title": workflow["title"],
        "severity": workflow["severity"],
        "time_estimate": workflow["time_estimate"],
        "steps": workflow["steps"],
        "verification": workflow["verification"],
        "rollback": workflow["rollback"]
    })


@remediation_bp.route("/workflow/<workflow_id>/summary")
def get_workflow_summary_endpoint(workflow_id):
    """Get quick summary of remediation workflow."""
    summary = get_workflow_summary(workflow_id)
    if not summary:
        return jsonify({"error": "Workflow not found"}), 404
    
    return jsonify(summary)


@remediation_bp.route("/map-finding", methods=["POST"])
def map_finding():
    """Map a finding to appropriate remediation workflow."""
    data = request.get_json()
    title = data.get("title", "")
    description = data.get("description", "")
    
    workflow_type = map_finding_to_workflow(title, description)
    if not workflow_type:
        return jsonify({
            "finding": {"title": title, "description": description},
            "workflow": None,
            "message": "No matching workflow found"
        })
    
    workflow = get_remediation_workflow(workflow_type)
    return jsonify({
        "finding": {"title": title, "description": description},
        "workflow": {
            "id": workflow_type,
            "title": workflow["title"],
            "severity": workflow["severity"],
            "time_estimate": workflow["time_estimate"],
            "steps": len(workflow["steps"])
        }
    })


@remediation_bp.route("/report/<int:report_id>/plan")
def get_report_remediation_plan(report_id):
    """Generate remediation plan for a report."""
    report = get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    findings = report.get("findings", [])
    plan = generate_remediation_plan(findings)
    
    return jsonify({
        "report_id": report_id,
        "plan": plan,
        "estimated_total_time": _calculate_total_time(plan["workflows"])
    })


@remediation_bp.route("/report/<int:report_id>/device/<device_ip>/plan")
def get_device_remediation_plan(report_id, device_ip):
    """Generate remediation plan for a specific device."""
    report = get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    # Filter findings for this device
    device_findings = [f for f in report.get("findings", []) if f.get("device_ip") == device_ip]
    if not device_findings:
        return jsonify({"error": "No findings for this device"}), 404
    
    plan = generate_remediation_plan(device_findings)
    
    return jsonify({
        "report_id": report_id,
        "device_ip": device_ip,
        "plan": plan,
        "estimated_total_time": _calculate_total_time(plan["workflows"])
    })


def _calculate_total_time(workflows):
    """Calculate total remediation time from workflows."""
    time_map = {
        "5 minutes": 5,
        "10 minutes": 10,
        "15 minutes": 15,
        "20 minutes": 20,
        "30 minutes": 30,
        "1 hour": 60,
        "2 hours": 120
    }
    
    total = 0
    for workflow in workflows:
        time_str = workflow.get("time_estimate", "0 minutes")
        total += time_map.get(time_str, 0)
    
    if total < 60:
        return f"{total} minutes"
    else:
        hours = total // 60
        minutes = total % 60
        if minutes == 0:
            return f"{hours} hour{'s' if hours > 1 else ''}"
        else:
            return f"{hours}h {minutes}m"
