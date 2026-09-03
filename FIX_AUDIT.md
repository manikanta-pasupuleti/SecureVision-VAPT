# SecureVision VAPT — Stability Audit

## Root causes found

1. **Live discovery could create fake devices.** A failed/down Nmap result could reach the fingerprint layer with no ports, where the old fingerprint logic interpreted an empty port list as permission to use the deterministic simulation. Live and simulated paths are now explicitly tagged with `scan_mode`.

2. **The fingerprint layer could promote an application version to firmware.** A web/FTP/DNS product version is not automatically device firmware. Firmware is now accepted only from explicit firmware evidence or a matching firmware/OS CPE.

3. **The local CVE database contained mismatched CVE identities.** Several entries described a different product/vulnerability than the CVE ID. The automatic service-only CVE rules were removed. CVE correlation now requires concrete product + version evidence.

4. **Generic findings were being labeled with CVE IDs.** FTP/RTSP/Telnet/ONVIF findings are configuration/exposure findings unless a separate verified CVE match exists. Their enrichment no longer injects unrelated CVE references.

5. **CVE enrichment could overwrite authoritative CVE exploitability.** A CVE affecting FTP could be reinterpreted as a generic FTP finding and have its exploitability replaced. Verified CVE findings now preserve their own CVE data.

6. **Recommendations were generated before all findings existed.** Credential recommendations therefore saw an incomplete evidence set. Recommendations are now generated after default-credential, plugin, firmware and CVE findings are assembled.

7. **The dashboard test expected old reports to be deleted.** The application/documentation explicitly supports report history, so the test was corrected to retain history and assert that the newest report is selected.

## Verified product/version CVE rules added

- Boa HTTPd 0.93.15 → CVE-2007-4915
- dnsmasq 2.45 → CVE-2017-14491
- GNU Inetutils FTPd 1.4.1 → CVE-2023-40303
- MySQL Server 8.0.44 → CVE-2026-21968 and CVE-2026-21964

These are product/version correlations, not service-presence guesses.

## Validation

- `python -m compileall -q .` — PASS
- CVE smoke tests — PASS
- Unknown + service-only scan produces no CVE — PASS
- Live/down target does not become simulated — PASS
- Live/zero-port host remains live/unknown — PASS
- Synthetic Nmap pipeline preserves product/version evidence — PASS

## Environment limitation

The analysis environment did not have the project's Python dependencies installed and could not download packages, so a full Flask + real-Nmap Docker execution was not performed here. The Dockerfile and requirements were inspected; final live verification should be run with the project's Docker environment.
