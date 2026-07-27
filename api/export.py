from flask import Blueprint, request, send_file, jsonify
from io import BytesIO
from database.db import get_report
from scanner.report_generator import generate_pdf_report, generate_csv_report, generate_json_report

export_bp = Blueprint("export", __name__, url_prefix="/api/export")


@export_bp.route("/report/<int:report_id>/pdf")
def export_pdf(report_id):
    """Export report as PDF."""
    report = get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    pdf_data = generate_pdf_report(report)
    return send_file(
        BytesIO(pdf_data),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"report_{report_id}.pdf"
    )


@export_bp.route("/report/<int:report_id>/csv")
def export_csv(report_id):
    """Export report as CSV."""
    report = get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    csv_data = generate_csv_report(report)
    return send_file(
        BytesIO(csv_data.encode('utf-8')),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"report_{report_id}.csv"
    )


@export_bp.route("/report/<int:report_id>/json")
def export_json(report_id):
    """Export report as JSON."""
    report = get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    json_data = generate_json_report(report)
    return send_file(
        BytesIO(json_data.encode('utf-8')),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"report_{report_id}.json"
    )


@export_bp.route("/report/<int:report_id>/formats")
def export_formats(report_id):
    """Get available export formats for a report."""
    report = get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    return jsonify({
        "report_id": report_id,
        "formats": [
            {
                "name": "PDF",
                "url": f"/api/export/report/{report_id}/pdf",
                "description": "Professional PDF report with formatting"
            },
            {
                "name": "CSV",
                "url": f"/api/export/report/{report_id}/csv",
                "description": "Spreadsheet-compatible CSV format"
            },
            {
                "name": "JSON",
                "url": f"/api/export/report/{report_id}/json",
                "description": "Raw JSON data for integration"
            }
        ]
    })
