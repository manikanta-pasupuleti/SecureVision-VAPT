# SecureVision VAPT - stable pipeline patch

This patch removes the previous evidence/correlation problems instead of adding another
parallel *_corrected.py implementation.

Main fixes:
- Live Nmap mode never falls back to simulated data.
- A down live target is not converted into a simulated device.
- A live host with zero open ports remains a real, unknown device.
- Nmap product/version/CPE evidence is preserved.
- Firmware is not inferred from an unrelated application version.
- Generic FTP/HTTP/RTSP/Telnet/ONVIF findings are configuration findings, not fake CVEs.
- CVEs are matched only when a concrete product + version is supported by the local CVE rule.
- Incorrect CVE titles/descriptions from the previous generic service rules were removed.
- Recommendations are generated after all evidence findings exist.
- CVE exploitability and references are not overwritten by generic service enrichment.
- Report history is retained; the dashboard selects the newest report instead of deleting older evidence.
- Local scan recordings are excluded from Docker build context.

Clean rebuild:
  docker build --no-cache -t securevision-vapt .
  docker run --name securevision-test -p 5001:10000 securevision-vapt

Then open:
  http://127.0.0.1:5001/

For a live target, the report must reflect the actual Nmap result. It must never show a
simulated vendor/model/firmware profile unless mode=simulated was explicitly requested.

For CVE counts, do not hard-code an expected number. The count depends on the actual
product/version evidence returned by Nmap and the verified CVE rules.
