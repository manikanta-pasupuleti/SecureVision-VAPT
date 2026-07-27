"""Assessment pipeline definitions for SecureVision VAPT."""

from typing import List, Dict


ASSESSMENT_STAGES: List[Dict[str, str]] = [
    {
        "name": "Discovery",
        "description": "Identify target devices and network assets within the defined assessment scope.",
    },
    {
        "name": "Fingerprinting",
        "description": "Collect vendor, firmware, and service metadata to understand the asset profile.",
    },
    {
        "name": "Service Detection",
        "description": "Recognize exposed services such as RTSP, Telnet, and ONVIF that may increase risk.",
    },
    {
        "name": "Credential Audit",
        "description": "Evaluate weak or default credential exposure patterns and access assumptions.",
    },
    {
        "name": "Firmware Analysis",
        "description": "Review firmware baseline information and version patterns for outdated components.",
    },
    {
        "name": "CVE Correlation",
        "description": "Map observed weaknesses to known vulnerability context and public advisories.",
    },
    {
        "name": "Risk Scoring",
        "description": "Calculate severity and prioritize findings based on impact and exploitability.",
    },
    {
        "name": "Remediation Engine",
        "description": "Provide actionable mitigation guidance aligned to the assessment findings.",
    },
    {
        "name": "Historical Database",
        "description": "Persist findings so the assessment can be reviewed, compared, and audited over time.",
    },
    {
        "name": "Dashboard",
        "description": "Present results in an interactive interface for operational review and triage.",
    },
    {
        "name": "PDF Report",
        "description": "Generate a structured report suitable for stakeholder review and delivery.",
    },
]


def get_assessment_pipeline() -> List[Dict[str, str]]:
    """Return the product-style assessment workflow used by the application UI."""

    return [stage.copy() for stage in ASSESSMENT_STAGES]
