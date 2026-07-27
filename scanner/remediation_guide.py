"""
Automated Remediation Guidance Engine
Provides vendor-specific, step-by-step remediation workflows for surveillance devices.
"""

REMEDIATION_WORKFLOWS = {
    "default_credentials": {
        "title": "Remove Default Credentials",
        "severity": "Critical",
        "time_estimate": "15 minutes",
        "steps": [
            {
                "step": 1,
                "action": "Access Device Management Interface",
                "details": "Connect to the device via web interface (HTTP/HTTPS) or SSH/Telnet",
                "commands": [
                    "Open browser to http://<device_ip>:80 or https://<device_ip>:443",
                    "Or SSH: ssh admin@<device_ip>"
                ]
            },
            {
                "step": 2,
                "action": "Authenticate with Default Credentials",
                "details": "Log in using the default username and password",
                "commands": [
                    "Username: admin (or root)",
                    "Password: 12345 (or admin)"
                ]
            },
            {
                "step": 3,
                "action": "Navigate to User Management",
                "details": "Find the user/account settings section",
                "commands": [
                    "Look for: Settings > Users, Administration > Accounts, or System > Users"
                ]
            },
            {
                "step": 4,
                "action": "Change Admin Password",
                "details": "Set a strong, unique password (min 12 characters, mixed case, numbers, symbols)",
                "commands": [
                    "Current Password: [default]",
                    "New Password: [strong_password]",
                    "Confirm Password: [strong_password]"
                ]
            },
            {
                "step": 5,
                "action": "Disable Unnecessary Accounts",
                "details": "Remove or disable guest, test, and other default accounts",
                "commands": [
                    "Delete guest account if present",
                    "Disable test/demo accounts",
                    "Keep only required administrative accounts"
                ]
            },
            {
                "step": 6,
                "action": "Save and Verify",
                "details": "Save changes and log out to verify new credentials work",
                "commands": [
                    "Click Save/Apply",
                    "Log out",
                    "Log back in with new credentials"
                ]
            }
        ],
        "verification": "Attempt login with default credentials - should fail",
        "rollback": "Factory reset device if locked out"
    },
    
    "telnet_exposure": {
        "title": "Disable Telnet and Enable SSH",
        "severity": "High",
        "time_estimate": "10 minutes",
        "steps": [
            {
                "step": 1,
                "action": "Access Device Configuration",
                "details": "Connect to device management interface",
                "commands": [
                    "Web UI: http://<device_ip>",
                    "SSH: ssh admin@<device_ip>"
                ]
            },
            {
                "step": 2,
                "action": "Navigate to Network Settings",
                "details": "Find network/service configuration section",
                "commands": [
                    "Look for: Settings > Network, Administration > Services, or System > Network"
                ]
            },
            {
                "step": 3,
                "action": "Disable Telnet Service",
                "details": "Turn off Telnet (port 23) service",
                "commands": [
                    "Find Telnet option",
                    "Uncheck 'Enable Telnet' or set to Disabled",
                    "Confirm port 23 is not listening"
                ]
            },
            {
                "step": 4,
                "action": "Enable SSH Service",
                "details": "Turn on SSH (port 22) service if available",
                "commands": [
                    "Find SSH option",
                    "Check 'Enable SSH' or set to Enabled",
                    "Verify SSH port is 22 (standard)"
                ]
            },
            {
                "step": 5,
                "action": "Configure SSH Security",
                "details": "Set SSH to use strong encryption",
                "commands": [
                    "SSH Version: 2 (not 1)",
                    "Encryption: AES-256 or AES-128",
                    "Authentication: Password + Key (if supported)"
                ]
            },
            {
                "step": 6,
                "action": "Save and Restart Services",
                "details": "Apply changes and restart network services",
                "commands": [
                    "Click Save/Apply",
                    "Device may restart automatically",
                    "Wait 1-2 minutes for services to come online"
                ]
            },
            {
                "step": 7,
                "action": "Verify SSH Access",
                "details": "Test SSH connection to confirm it works",
                "commands": [
                    "ssh -v admin@<device_ip>",
                    "Verify connection succeeds",
                    "Verify Telnet port 23 is closed: telnet <device_ip> 23 (should timeout)"
                ]
            }
        ],
        "verification": "Telnet connection fails, SSH connection succeeds",
        "rollback": "Re-enable Telnet if SSH fails, then disable after SSH is working"
    },
    
    "firmware_update": {
        "title": "Update Firmware to Latest Version",
        "severity": "High",
        "time_estimate": "30 minutes",
        "steps": [
            {
                "step": 1,
                "action": "Check Current Firmware Version",
                "details": "Identify current firmware version before updating",
                "commands": [
                    "Web UI: Settings > System > About or System Information",
                    "SSH: cat /proc/version or uname -a",
                    "Note the current version"
                ]
            },
            {
                "step": 2,
                "action": "Download Latest Firmware",
                "details": "Get the latest firmware from vendor website",
                "commands": [
                    "Visit vendor support page",
                    "Search for device model",
                    "Download latest stable firmware (not beta)",
                    "Verify checksum/signature if provided"
                ]
            },
            {
                "step": 3,
                "action": "Backup Current Configuration",
                "details": "Export current device settings before update",
                "commands": [
                    "Web UI: Settings > Backup/Export",
                    "Save configuration file to safe location",
                    "Note backup filename and location"
                ]
            },
            {
                "step": 4,
                "action": "Access Firmware Update Interface",
                "details": "Navigate to firmware update section",
                "commands": [
                    "Web UI: Settings > System > Firmware Update or Maintenance > Upgrade",
                    "SSH: Use vendor-specific update tool if available"
                ]
            },
            {
                "step": 5,
                "action": "Upload New Firmware",
                "details": "Select and upload the firmware file",
                "commands": [
                    "Click 'Browse' or 'Choose File'",
                    "Select downloaded firmware file",
                    "Click 'Upload' or 'Start Update'"
                ]
            },
            {
                "step": 6,
                "action": "Wait for Update to Complete",
                "details": "Do NOT power off device during update",
                "commands": [
                    "Monitor progress bar",
                    "Wait for completion message",
                    "Device will restart automatically (5-10 minutes typical)"
                ]
            },
            {
                "step": 7,
                "action": "Verify Update Success",
                "details": "Confirm new firmware version is running",
                "commands": [
                    "Wait for device to fully boot",
                    "Log back in",
                    "Check System > About for new version number",
                    "Verify device functions normally"
                ]
            },
            {
                "step": 8,
                "action": "Restore Configuration if Needed",
                "details": "Restore settings if they were reset",
                "commands": [
                    "If settings were lost: Settings > Restore/Import",
                    "Select backup file from step 3",
                    "Click Restore",
                    "Verify all settings are correct"
                ]
            }
        ],
        "verification": "New firmware version confirmed, device functions normally",
        "rollback": "Restore from backup if update causes issues"
    },
    
    "http_to_https": {
        "title": "Enable HTTPS and Disable HTTP",
        "severity": "Medium",
        "time_estimate": "15 minutes",
        "steps": [
            {
                "step": 1,
                "action": "Access Device Configuration",
                "details": "Connect to device management interface",
                "commands": [
                    "Web UI: http://<device_ip>",
                    "SSH: ssh admin@<device_ip>"
                ]
            },
            {
                "step": 2,
                "action": "Navigate to Network/Security Settings",
                "details": "Find HTTPS/SSL configuration section",
                "commands": [
                    "Look for: Settings > Network > HTTPS, Security > SSL/TLS, or Administration > Web Server"
                ]
            },
            {
                "step": 3,
                "action": "Enable HTTPS Service",
                "details": "Turn on HTTPS (port 443) service",
                "commands": [
                    "Check 'Enable HTTPS' or 'Enable SSL'",
                    "Verify HTTPS port is 443 (standard)",
                    "If certificate needed: Generate self-signed or upload CA certificate"
                ]
            },
            {
                "step": 4,
                "action": "Configure SSL Certificate",
                "details": "Set up SSL/TLS certificate",
                "commands": [
                    "Option A: Generate self-signed certificate (device will create one)",
                    "Option B: Upload existing certificate",
                    "Option C: Use Let's Encrypt if supported",
                    "Note: Self-signed will show browser warning (normal)"
                ]
            },
            {
                "step": 5,
                "action": "Disable HTTP Service",
                "details": "Turn off unencrypted HTTP (port 80)",
                "commands": [
                    "Find HTTP option",
                    "Uncheck 'Enable HTTP' or set to Disabled",
                    "Confirm port 80 is not listening"
                ]
            },
            {
                "step": 6,
                "action": "Save and Restart Web Services",
                "details": "Apply changes and restart web server",
                "commands": [
                    "Click Save/Apply",
                    "Web services will restart (may disconnect briefly)",
                    "Wait 30 seconds for services to come online"
                ]
            },
            {
                "step": 7,
                "action": "Verify HTTPS Access",
                "details": "Test HTTPS connection",
                "commands": [
                    "Open browser to https://<device_ip>",
                    "Accept self-signed certificate warning if present",
                    "Verify login works over HTTPS",
                    "Verify HTTP access fails: http://<device_ip> (should timeout or redirect)"
                ]
            }
        ],
        "verification": "HTTPS connection succeeds, HTTP connection fails",
        "rollback": "Re-enable HTTP if HTTPS fails, then disable after HTTPS is working"
    },
    
    "weak_encryption": {
        "title": "Enable Strong Encryption",
        "severity": "High",
        "time_estimate": "10 minutes",
        "steps": [
            {
                "step": 1,
                "action": "Access Security Settings",
                "details": "Navigate to encryption/cipher configuration",
                "commands": [
                    "Web UI: Settings > Security > Encryption or Administration > Cryptography",
                    "SSH: Check device documentation for config files"
                ]
            },
            {
                "step": 2,
                "action": "Review Current Encryption Settings",
                "details": "Identify weak ciphers currently enabled",
                "commands": [
                    "Look for: DES, RC4, MD5, SHA1 (weak)",
                    "Look for: AES, SHA256, SHA512 (strong)",
                    "Note which weak ciphers are enabled"
                ]
            },
            {
                "step": 3,
                "action": "Disable Weak Ciphers",
                "details": "Turn off DES, RC4, and other weak encryption",
                "commands": [
                    "Uncheck DES, 3DES, RC4, MD5",
                    "Disable any ciphers marked as 'weak' or 'deprecated'",
                    "Keep only AES-128 and above"
                ]
            },
            {
                "step": 4,
                "action": "Enable Strong Ciphers",
                "details": "Ensure modern encryption is enabled",
                "commands": [
                    "Check AES-256, AES-128",
                    "Check SHA256, SHA512",
                    "Check TLS 1.2 or higher (if applicable)"
                ]
            },
            {
                "step": 5,
                "action": "Save and Apply Changes",
                "details": "Apply new encryption settings",
                "commands": [
                    "Click Save/Apply",
                    "Device may restart services",
                    "Wait for services to stabilize"
                ]
            },
            {
                "step": 6,
                "action": "Verify Strong Encryption",
                "details": "Confirm strong encryption is in use",
                "commands": [
                    "Use nmap: nmap --script ssl-enum-ciphers -p 443 <device_ip>",
                    "Use openssl: openssl s_client -connect <device_ip>:443",
                    "Verify only strong ciphers are listed"
                ]
            }
        ],
        "verification": "Only strong ciphers (AES-256, AES-128) are available",
        "rollback": "Re-enable weak ciphers if connectivity issues occur"
    },
    
    "rtsp_exposure": {
        "title": "Restrict RTSP Access",
        "severity": "Medium",
        "time_estimate": "10 minutes",
        "steps": [
            {
                "step": 1,
                "action": "Access Network Configuration",
                "details": "Navigate to network/firewall settings",
                "commands": [
                    "Web UI: Settings > Network > Firewall or Administration > Access Control",
                    "SSH: Check iptables or firewall rules"
                ]
            },
            {
                "step": 2,
                "action": "Identify RTSP Port",
                "details": "Confirm RTSP port (usually 554)",
                "commands": [
                    "Check device documentation",
                    "Typical RTSP port: 554",
                    "Some devices use: 8554, 9554"
                ]
            },
            {
                "step": 3,
                "action": "Configure Firewall Rules",
                "details": "Restrict RTSP to trusted networks only",
                "commands": [
                    "Option A: Restrict to specific IP ranges (e.g., 192.168.1.0/24)",
                    "Option B: Disable RTSP if not needed",
                    "Option C: Move RTSP to non-standard port"
                ]
            },
            {
                "step": 4,
                "action": "Set Access Control Lists",
                "details": "Define who can access RTSP stream",
                "commands": [
                    "Allow: Internal network only",
                    "Deny: Internet/external access",
                    "Whitelist specific IP addresses if needed"
                ]
            },
            {
                "step": 5,
                "action": "Save and Apply Rules",
                "details": "Apply firewall configuration",
                "commands": [
                    "Click Save/Apply",
                    "Verify rules are active"
                ]
            },
            {
                "step": 6,
                "action": "Verify Access Restrictions",
                "details": "Test that RTSP is restricted properly",
                "commands": [
                    "From trusted network: ffplay rtsp://<device_ip>:554/stream (should work)",
                    "From untrusted network: ffplay rtsp://<device_ip>:554/stream (should fail)",
                    "Verify port 554 is not open to internet: nmap <device_ip> -p 554"
                ]
            }
        ],
        "verification": "RTSP accessible from trusted networks only",
        "rollback": "Remove firewall rules if legitimate access is blocked"
    },
    
    "onvif_exposure": {
        "title": "Secure ONVIF Interface",
        "severity": "Medium",
        "time_estimate": "15 minutes",
        "steps": [
            {
                "step": 1,
                "action": "Access ONVIF Configuration",
                "details": "Navigate to ONVIF settings",
                "commands": [
                    "Web UI: Settings > Network > ONVIF or Administration > ONVIF",
                    "SSH: Check device documentation for ONVIF config"
                ]
            },
            {
                "step": 2,
                "action": "Enable ONVIF Authentication",
                "details": "Require credentials for ONVIF access",
                "commands": [
                    "Check 'Require Authentication' or 'Enable ONVIF Security'",
                    "Ensure ONVIF uses same credentials as device admin account"
                ]
            },
            {
                "step": 3,
                "action": "Disable ONVIF Discovery",
                "details": "Prevent automatic device discovery if not needed",
                "commands": [
                    "Uncheck 'Enable WS-Discovery' or 'Enable Multicast Discovery'",
                    "This prevents devices from being automatically found on network"
                ]
            },
            {
                "step": 4,
                "action": "Restrict ONVIF Port Access",
                "details": "Limit ONVIF (port 8080) to trusted networks",
                "commands": [
                    "Configure firewall to restrict port 8080",
                    "Allow only internal network access",
                    "Deny internet access"
                ]
            },
            {
                "step": 5,
                "action": "Enable ONVIF over HTTPS",
                "details": "Use encrypted ONVIF if supported",
                "commands": [
                    "Look for: ONVIF over HTTPS, ONVIF over TLS, or Secure ONVIF",
                    "Enable if available",
                    "Verify port 8443 is used instead of 8080"
                ]
            },
            {
                "step": 6,
                "action": "Save and Verify",
                "details": "Apply ONVIF security settings",
                "commands": [
                    "Click Save/Apply",
                    "Test ONVIF access with credentials",
                    "Verify ONVIF discovery is disabled: nmap --script onvif-discovery <device_ip>"
                ]
            }
        ],
        "verification": "ONVIF requires authentication, discovery disabled, port restricted",
        "rollback": "Re-enable ONVIF discovery if management tools cannot find device"
    }
}


def get_remediation_workflow(finding_type):
    """Get remediation workflow for a specific finding type."""
    return REMEDIATION_WORKFLOWS.get(finding_type, None)


def get_all_workflows():
    """Get all available remediation workflows."""
    return REMEDIATION_WORKFLOWS


def get_workflow_summary(finding_type):
    """Get quick summary of remediation workflow."""
    workflow = get_remediation_workflow(finding_type)
    if not workflow:
        return None
    
    return {
        "title": workflow["title"],
        "severity": workflow["severity"],
        "time_estimate": workflow["time_estimate"],
        "step_count": len(workflow["steps"]),
        "verification": workflow["verification"],
        "rollback": workflow["rollback"]
    }


def get_workflow_steps(finding_type):
    """Get detailed steps for a remediation workflow."""
    workflow = get_remediation_workflow(finding_type)
    if not workflow:
        return None
    
    return {
        "title": workflow["title"],
        "steps": workflow["steps"],
        "verification": workflow["verification"],
        "rollback": workflow["rollback"]
    }


def map_finding_to_workflow(finding_title, finding_description):
    """Map a finding to the most appropriate remediation workflow."""
    finding_lower = (finding_title + " " + finding_description).lower()
    
    mapping = {
        "default_credentials": ["default", "credential", "weak password", "admin/admin"],
        "telnet_exposure": ["telnet", "port 23", "unencrypted remote"],
        "firmware_update": ["firmware", "outdated", "eol", "end of life", "version"],
        "http_to_https": ["http", "unencrypted web", "ssl", "tls", "https"],
        "weak_encryption": ["encryption", "cipher", "des", "rc4", "md5", "weak crypto"],
        "rtsp_exposure": ["rtsp", "port 554", "stream", "video exposure"],
        "onvif_exposure": ["onvif", "discovery", "port 8080", "device discovery"]
    }
    
    for workflow_type, keywords in mapping.items():
        if any(keyword in finding_lower for keyword in keywords):
            return workflow_type
    
    return None


def generate_remediation_plan(findings):
    """Generate a prioritized remediation plan from findings."""
    plan = {
        "total_findings": len(findings),
        "workflows": [],
        "priority_order": []
    }
    
    severity_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    
    # Map findings to workflows
    workflow_map = {}
    for finding in findings:
        workflow_type = map_finding_to_workflow(finding.get("title", ""), finding.get("description", ""))
        if workflow_type:
            if workflow_type not in workflow_map:
                workflow_map[workflow_type] = {
                    "type": workflow_type,
                    "findings": [],
                    "severity": finding.get("severity", "medium").lower()
                }
            workflow_map[workflow_type]["findings"].append(finding)
    
    # Sort by severity and add to plan
    sorted_workflows = sorted(
        workflow_map.items(),
        key=lambda x: severity_priority.get(x[1]["severity"], 4)
    )
    
    for workflow_type, data in sorted_workflows:
        workflow = get_remediation_workflow(workflow_type)
        if workflow:
            plan["workflows"].append({
                "type": workflow_type,
                "title": workflow["title"],
                "severity": data["severity"],
                "time_estimate": workflow["time_estimate"],
                "affected_findings": len(data["findings"]),
                "finding_titles": [f.get("title", "") for f in data["findings"]]
            })
            plan["priority_order"].append(workflow_type)
    
    return plan
