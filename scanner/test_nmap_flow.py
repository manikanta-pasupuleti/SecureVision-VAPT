from scanner.nmap_scanner import scan_host
from scanner.fingerprint import fingerprint_device
from scanner.vulnerability import scan_vulnerabilities


device = scan_host("127.0.0.1")

fingerprinted = fingerprint_device(device)

findings = scan_vulnerabilities(fingerprinted)

print("\n=== FINGERPRINT ===")
print(fingerprinted)

print("\n=== FINDINGS ===")

for finding in findings:
    print(finding)