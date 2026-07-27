import csv
import json
from io import BytesIO, StringIO
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


def generate_pdf_report(report_data):
    """Generate PDF report from scan data."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#4dd6c0'),
        spaceAfter=12,
        alignment=TA_CENTER
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#7bb7ff'),
        spaceAfter=10,
        spaceBefore=10
    )
    
    # Title
    story.append(Paragraph("SecureVision VAPT Assessment Report", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    summary_data = [
        ["Report ID", str(report_data.get('id', 'N/A'))],
        ["Generated", report_data.get('created_at', 'N/A')],
        ["Target Scope", report_data.get('target_spec', 'N/A')],
        ["Overall Risk Score", f"{report_data.get('risk_score', 0)}/100"],
        ["Devices Assessed", str(report_data.get('device_count', 0))],
        ["Total Findings", str(report_data.get('finding_count', 0))],
    ]
    summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#0a1422')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Severity Breakdown
    story.append(Paragraph("Severity Breakdown", heading_style))
    summary = report_data.get('summary', {})
    if isinstance(summary, str):
        summary = json.loads(summary)
    severity_breakdown = summary.get('severity_breakdown', {})
    severity_data = [
        ["Severity", "Count"],
        ["Critical", str(severity_breakdown.get('critical', 0))],
        ["High", str(severity_breakdown.get('high', 0))],
        ["Medium", str(severity_breakdown.get('medium', 0))],
        ["Low", str(severity_breakdown.get('low', 0))],
    ]
    severity_table = Table(severity_data, colWidths=[2*inch, 2*inch])
    severity_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7bb7ff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
    ]))
    story.append(severity_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Devices Discovered
    story.append(Paragraph("Devices Discovered", heading_style))
    devices = report_data.get('devices', [])
    device_data = [["IP Address", "Vendor", "Model", "Firmware", "Risk Score"]]
    for device in devices:
        device_data.append([
            device.get('ip_address', 'N/A'),
            device.get('vendor', 'N/A'),
            device.get('model', 'N/A'),
            device.get('firmware_version', 'N/A'),
            str(device.get('risk_score', 0))
        ])
    
    device_table = Table(device_data, colWidths=[1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch, 1*inch])
    device_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7bb7ff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
    ]))
    story.append(device_table)
    story.append(PageBreak())
    
    # Findings Detail
    story.append(Paragraph("Detailed Findings", heading_style))
    findings = report_data.get('findings', [])
    
    for idx, finding in enumerate(findings[:20], 1):  # Limit to first 20 findings
        severity = finding.get('severity', 'Unknown').upper()
        title = finding.get('title', 'Unknown Finding')
        
        finding_style = ParagraphStyle(
            f'FindingTitle{idx}',
            parent=styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#ff9ab3') if severity == 'CRITICAL' else colors.HexColor('#ffe2a0'),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        )
        
        story.append(Paragraph(f"{idx}. [{severity}] {title}", finding_style))
        
        description = finding.get('description', '')
        if description:
            story.append(Paragraph(f"<b>Description:</b> {description}", styles['Normal']))
        
        remediation = finding.get('remediation', '')
        if remediation:
            story.append(Paragraph(f"<b>Remediation:</b> {remediation}", styles['Normal']))
        
        technical_explanation = finding.get('technical_explanation', '')
        if technical_explanation:
            story.append(Paragraph(f"<b>Technical Details:</b> {technical_explanation}", styles['Normal']))
        
        business_impact = finding.get('business_impact', '')
        if business_impact:
            story.append(Paragraph(f"<b>Business Impact:</b> {business_impact}", styles['Normal']))
        
        cve_refs = finding.get('cve_references', [])
        if cve_refs:
            cve_text = ', '.join([cve.get('id', 'Unknown') if isinstance(cve, dict) else str(cve) for cve in cve_refs])
            story.append(Paragraph(f"<b>CVE References:</b> {cve_text}", styles['Normal']))
        
        story.append(Spacer(1, 0.15*inch))
    
    if len(findings) > 20:
        story.append(Paragraph(f"... and {len(findings) - 20} more findings", styles['Normal']))
    
    story.append(PageBreak())
    
    # Recommendations
    story.append(Paragraph("Remediation Recommendations", heading_style))
    recommendations = summary.get('top_recommendations', [])
    
    for idx, rec in enumerate(recommendations, 1):
        rec_title = rec.get('title', 'Recommendation')
        rec_description = rec.get('description', '')
        rec_priority = rec.get('priority', 'Medium')
        
        story.append(Paragraph(f"{idx}. {rec_title} (Priority: {rec_priority})", styles['Heading3']))
        if rec_description:
            story.append(Paragraph(rec_description, styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def generate_csv_report(report_data):
    """Generate CSV report from scan data."""
    output = StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['SecureVision VAPT Assessment Report'])
    writer.writerow([])
    
    # Summary
    writer.writerow(['Report Summary'])
    writer.writerow(['Report ID', report_data.get('id', 'N/A')])
    writer.writerow(['Generated', report_data.get('created_at', 'N/A')])
    writer.writerow(['Target Scope', report_data.get('target_spec', 'N/A')])
    writer.writerow(['Overall Risk Score', f"{report_data.get('risk_score', 0)}/100"])
    writer.writerow(['Devices Assessed', report_data.get('device_count', 0)])
    writer.writerow(['Total Findings', report_data.get('finding_count', 0)])
    writer.writerow([])
    
    # Severity Breakdown
    writer.writerow(['Severity Breakdown'])
    summary = report_data.get('summary', {})
    if isinstance(summary, str):
        summary = json.loads(summary)
    severity_breakdown = summary.get('severity_breakdown', {})
    writer.writerow(['Severity', 'Count'])
    for severity in ['critical', 'high', 'medium', 'low']:
        writer.writerow([severity.capitalize(), severity_breakdown.get(severity, 0)])
    writer.writerow([])
    
    # Devices
    writer.writerow(['Devices Discovered'])
    writer.writerow(['IP Address', 'Vendor', 'Model', 'Firmware', 'Risk Score', 'Services'])
    for device in report_data.get('devices', []):
        services = ', '.join(device.get('services', []))
        writer.writerow([
            device.get('ip_address', 'N/A'),
            device.get('vendor', 'N/A'),
            device.get('model', 'N/A'),
            device.get('firmware_version', 'N/A'),
            device.get('risk_score', 0),
            services
        ])
    writer.writerow([])
    
    # Findings
    writer.writerow(['Detailed Findings'])
    writer.writerow(['IP Address', 'Severity', 'Title', 'Description', 'Remediation', 'Technical Explanation', 'Business Impact', 'CVE References'])
    for finding in report_data.get('findings', []):
        cve_refs = ', '.join([cve.get('id', 'Unknown') if isinstance(cve, dict) else str(cve) for cve in finding.get('cve_references', [])])
        writer.writerow([
            finding.get('device_ip', 'N/A'),
            finding.get('severity', 'Unknown'),
            finding.get('title', 'Unknown'),
            finding.get('description', ''),
            finding.get('remediation', ''),
            finding.get('technical_explanation', ''),
            finding.get('business_impact', ''),
            cve_refs
        ])
    writer.writerow([])
    
    # Recommendations
    writer.writerow(['Remediation Recommendations'])
    writer.writerow(['Title', 'Description', 'Priority', 'Affected Devices'])
    for rec in summary.get('top_recommendations', []):
        writer.writerow([
            rec.get('title', ''),
            rec.get('description', ''),
            rec.get('priority', 'Medium'),
            rec.get('affected_count', 0)
        ])
    
    return output.getvalue()


def generate_json_report(report_data):
    """Generate JSON report from scan data."""
    return json.dumps(report_data, indent=2, default=str)
