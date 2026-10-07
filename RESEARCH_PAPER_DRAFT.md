# AI-Assisted Vulnerability and Risk Assessment for CCTV Surveillance Devices

**[Student 1 Full Name]**, **[Student 2 Full Name]**, **[Student 3 Full Name]**, **[Student 4 Full Name]**  
Department of Artificial Intelligence and Machine Learning  
School of Engineering, Anurag University, Hyderabad, India  
[Official student email addresses]

**Project Guide:** [Guide Full Name], [Official guide email address]

## Abstract

Internet-connected CCTV cameras, digital video recorders, and network video recorders expose services that can affect confidentiality, integrity, and availability of surveillance infrastructure. Manual assessment of these devices is difficult because service exposure, incomplete device identification, firmware age, credential risk, and vulnerability evidence must be considered together. This paper presents SecureVision VAPT, a web-based vulnerability and exposure assessment platform for authorized surveillance-device assessments. The system combines Nmap discovery, service and version fingerprinting, surveillance-oriented device profiles, conservative CVE correlation, deterministic severity scoring, remediation guidance, historical persistence, and an explainable unsupervised anomaly-detection layer. The machine-learning component uses Isolation Forest over eleven evidence-derived features, including exposed-service counts, encryption status, CVE evidence, credential exposure, firmware state, and RTSP/ONVIF presence. A deterministic simulation mode makes the evaluation repeatable when physical CCTV hardware is unavailable, while live Nmap scanning remains an explicit authorized-network operation. In a representative simulated assessment, the system identified a Hikvision-style profile with HTTP, HTTPS, RTSP, and ONVIF services, produced five findings including one critical credential finding, assigned a rule-based risk score of 93/100, and produced an anomaly score of 100/100. The result demonstrates prioritization rather than proof of exploitability. The paper discusses the architecture, evidence model, ML limitations, reproducibility, and the risks of using simulated data as a substitute for a real camera dataset.

**Keywords:** CCTV security, vulnerability assessment, network scanning, device fingerprinting, Isolation Forest, anomaly detection, CVE correlation, surveillance systems

## I. Introduction

Connected surveillance devices are increasingly deployed in homes, campuses, offices, factories, and public infrastructure. A camera or recorder is no longer an isolated appliance: it can expose web administration, video streaming, device-management, file-transfer, or remote-access services to a local network. Weak credentials, outdated firmware, unencrypted services, and incorrect network segmentation can therefore create security and privacy risks. Standards and guidance for IoT security emphasize secure configuration, vulnerability management, and protection of device interfaces [4], [9]-[12].

A vulnerability assessment for surveillance devices must answer more than whether a port is open. It should identify what device or service is present, distinguish observed evidence from assumptions, correlate vulnerabilities only when product and version evidence is sufficient, and present remediation actions that an operator can understand. Traditional scanners can provide raw ports and service banners, but the results may be difficult to prioritize for a surveillance environment where RTSP and ONVIF have direct operational meaning.

SecureVision VAPT addresses this problem as an integrated assessment workflow. It accepts individual targets, hostnames, comma-separated targets, or CIDR ranges. The live path uses Nmap service and version detection. The fingerprinting layer builds a structured device profile. The intelligence layer analyzes services, firmware, credentials, attack surface, and CVE evidence. A deterministic risk engine produces a severity-oriented score, while an Isolation Forest model provides an independent anomaly-prioritization signal. The system stores reports, devices, findings, assets, and alerts and exposes the results through a web dashboard and export endpoints.

The main contributions of this project are:

1. A surveillance-oriented evidence pipeline that combines discovery, fingerprinting, service analysis, CVE correlation, risk scoring, and remediation.
2. A conservative evidence policy that does not infer a product-specific CVE from service presence alone.
3. An explainable Isolation Forest layer using eleven security-evidence features rather than the rule-based risk score.
4. A deterministic simulation mode for repeatable academic evaluation without requiring a physical CCTV device.
5. A persistent dashboard and reporting workflow suitable for security review and demonstration.

## II. Related Work

Network discovery and service identification are established parts of security assessment practice. Nmap provides host discovery, TCP scanning, service detection, version identification, and CPE-related evidence [1], [2]. NIST SP 800-115 describes technical security testing as a process that includes planning, discovery, vulnerability analysis, and reporting [3]. SecureVision follows this general structure but adds surveillance-specific interpretation and reporting.

IoT and embedded-device security research identifies weak authentication, insecure services, outdated firmware, and poor network isolation as recurring risks [10]-[18]. ONVIF is relevant to surveillance systems because it standardizes device-management and video-related interactions [9]. RTSP and ONVIF exposure are not automatically vulnerabilities, but their exposure changes the security posture of a camera or recorder and should be visible to an assessor.

CVE and CVSS provide common vocabulary for vulnerability identity and severity [5]-[7]. A service-only match is unreliable because the same service name may represent multiple products and versions. SecureVision therefore separates configuration findings, such as an exposed RTSP service, from confirmed CVE matches that have sufficient product and version evidence.

Anomaly detection is useful when labeled vulnerability data is incomplete. Isolation Forest isolates observations through randomized partitioning and assigns lower normality to observations that are easier to isolate [19]. General anomaly-detection surveys describe the importance of feature quality, baseline selection, and domain-specific interpretation [20]. SecureVision uses the model as a prioritization aid and deliberately avoids claiming classification accuracy without a labeled evaluation dataset.

## III. Problem Statement and Objectives

The project addresses the following problem: given an authorized target scope containing networked surveillance devices, how can an assessment system combine observed network evidence and security intelligence into a reproducible, explainable, and actionable risk report?

The objectives are to:

- discover reachable hosts and exposed services;
- identify vendor, model, firmware, platform, and device-type evidence when available;
- recognize surveillance-relevant services such as RTSP and ONVIF;
- detect weak/default credential and firmware-baseline risks in supported profiles;
- correlate CVEs only when product and version evidence is sufficiently concrete;
- calculate a deterministic 0-100 risk score from findings;
- estimate unusual exposure using an unsupervised model;
- produce prioritized remediation guidance;
- preserve reports for historical review; and
- support repeatable evaluation without requiring physical hardware.

## IV. System Architecture

### A. Assessment workflow

The system is implemented as a Flask application with separate API, scanner, database, ML, template, and utility modules. The workflow is:

**Target scope -> discovery -> service/version detection -> fingerprinting -> intelligence enrichment -> vulnerability checks -> risk scoring -> ML anomaly analysis -> persistence -> dashboard and exports.**

**Fig. 1. SecureVision VAPT system architecture.** *Insert an original student-created block diagram showing the Flask interface, discovery, fingerprinting, intelligence, ML, database, and reporting layers.*

In live mode, Nmap is invoked with TCP connect and service/version detection options. A failed live scan raises an error and does not silently create a simulated device. In simulation mode, the target string is used as a deterministic seed to select one of the supported vendor profiles. The simulated path does not contact the supplied address.

### B. Evidence model

The device profile stores the target address, scan mode, observed services, product and version evidence, CPE evidence, vendor and model, firmware state, device type, confidence, credential assumptions, exposure indicators, and intelligence results. The system uses the value `Unknown` when evidence is insufficient rather than fabricating a vendor or firmware version.

### C. Persistence and interface

Reports contain the target scope, creation time, device count, finding count, overall risk score, severity breakdown, and summary information. Device and finding records are linked to reports. Assets preserve first-seen, last-seen, risk, status, ownership, location, notes, and change history. The web interface provides dashboard analytics, report history, asset inventory, device detail, remediation workflows, alerts, and PDF/CSV/JSON exports.

## V. Methodology

### A. Discovery and fingerprinting

Targets are parsed as IP addresses, hostnames, comma-separated values, or CIDR ranges. Live CIDR assessment performs host discovery before service scans. For each discovered host, Nmap evidence is normalized into services, products, versions, CPEs, and explicit firmware indicators. Vendor recognition is based on observed banners, hostnames, MAC vendor information, operating-system hints, products, or CPEs. An empty or unsupported live result remains an unknown live device.

Simulation profiles represent Hikvision, Dahua, Axis, and Uniview-style surveillance devices. The simulation adds deterministic services such as HTTP, HTTPS, RTSP, ONVIF, and Telnet according to the selected profile and target seed. This makes the academic demonstration repeatable while clearly separating simulated evidence from live observations.

**Fig. 2. Assessment workflow.** *Insert an original flowchart showing the live and simulated branches and the explicit no-silent-fallback behavior.*

### B. Service and vulnerability analysis

Service profiles describe encryption, authentication expectations, exposure risk, ports, attack vectors, and surveillance relevance. For example, RTSP may represent video-stream exposure, ONVIF may represent device-management exposure, and HTTP may represent an unencrypted management interface. These are configuration or exposure findings unless a verified vulnerability match exists.

CVE correlation uses observed product and version information, service context, and CPE evidence. The system does not attach a CVE merely because a generic service is open. This reduces false attribution and preserves the distinction between a confirmed vulnerability and an exposed interface. CVSS information is retained when a concrete match is available [5]-[7].

### C. Deterministic risk scoring

Findings are assigned severity according to evidence and impact. The report risk score is calculated from the weighted finding set and normalized to a 0-100 scale. The score is a prioritization measure and should not be interpreted as a probability of compromise. The dashboard presents both the aggregate score and the individual evidence behind each finding.

### D. Machine-learning anomaly detection

The ML layer uses Isolation Forest with 200 estimators, contamination set to 0.15, and a fixed random state of 42. The input vector contains eleven features:

1. number of open services;
2. number of high-risk services;
3. number of medium-risk services;
4. number of unencrypted services;
5. number of CVE matches;
6. maximum CVSS score;
7. number of potentially exploitable CVEs;
8. default-credential exposure;
9. outdated firmware indicator;
10. end-of-life firmware indicator; and
11. number of RTSP/ONVIF surveillance services.

The deterministic risk score is intentionally excluded from the feature vector to avoid circular learning. When insufficient historical scan rows are available, the model uses a documented bootstrap baseline representing ordinary network-device exposure patterns. The raw model output is converted into a bounded anomaly score from 0 to 100 using the position of the observed score relative to baseline scores. Scores below 50 are Low, scores from 50 through 74.9 are Medium, and scores of 75 or higher are High.

The model also reports the feature vector, training source, top non-zero signals, and an interpretation statement. This improves explainability and makes it possible to discuss why a device received a high anomaly priority. Because the training baseline is small and unsupervised, the output is not an accuracy measurement and does not confirm a CVE.

**Table III. ML feature vector used by the Isolation Forest model**

| Feature group | Features | Evidence source |
|---|---|---|
| Exposure | Open, high-risk, medium-risk, and unencrypted service counts | Enriched service profiles |
| Vulnerability | CVE count, maximum CVSS, and exploitable CVE count | Verified CVE matches |
| Configuration | Default credentials, outdated firmware, end-of-life firmware | Device and firmware intelligence |
| Surveillance | RTSP/ONVIF service count | Observed service list |

**Fig. 3. ML feature-extraction and explanation pipeline.** *Insert an original diagram connecting scan evidence to the eleven features, Isolation Forest, percentile score, risk level, and top contributing signals.*

## VI. Implementation

The application is implemented in Python using Flask and scikit-learn. SQLite is used for local development, while PostgreSQL can be selected through `DATABASE_URL` for deployment on Render. The database layer provides a compatibility facade so the existing query-oriented modules can use either backend. Reports and assets are persisted after every completed scan.

The web scan form exposes two modes. Simulation is the default for repeatable academic demonstrations and accepts a private-looking test target such as `192.168.1.50` without contacting it. Live Nmap mode is explicit and should only be used against devices or networks for which the operator has authorization. This design prevents an academic demonstration from depending on unavailable CCTV hardware and prevents live failure from silently becoming fake evidence.

**Fig. 4. Web dashboard and report navigation.** *Insert an original annotated screenshot or manually redrawn interface figure showing the report summary, finding distribution, ML result, and remediation sections.*

## VII. Experimental Evaluation

### A. Test environment and procedure

The software test suite validates CVE matching, dashboard report selection, ML feature construction, plugin loading, plugin manifests, service plugins, and deterministic simulation behavior. The repeatability experiment uses the simulated target `192.168.1.50` twice and verifies identical discovery output and a surveillance-device fingerprint. The representative dashboard experiment uses the same target and records the complete persisted report.

**Table I. Software validation results**

| Test area | Result | Interpretation |
|---|---:|---|
| Full automated test suite | 15 passed | Core behavior is regression-tested |
| Simulation determinism | Passed | Same target produces the same profile |
| Live/simulated separation | Passed | Live failures do not become simulated devices |
| ML feature construction | Passed | Features come from evidence, not rule score |
| CVE matching safeguards | Passed | Service-only evidence does not fabricate CVEs |
| Dashboard report selection | Passed | Latest and historical reports are retained |

### B. Representative simulated assessment

A simulated assessment of `192.168.1.50` selected a Hikvision-style profile with model `DS-2CD-6`, firmware `5.6.18`, and HTTP, HTTPS, RTSP, and ONVIF services.

**Table II. Representative report results**

| Measure | Observed result |
|---|---:|
| Devices assessed | 1 |
| Findings | 5 |
| Critical findings | 1 |
| Overall rule-based risk | 93/100 |
| ML anomaly score | 100/100, High |
| Open services | 4 |
| Unencrypted services | 3 |
| Confirmed CVE matches | 0 |
| Firmware status | Outdated, not EOL |

The critical finding concerned default credentials in the simulated device profile. Additional findings concerned outdated firmware, ONVIF exposure, RTSP exposure, and an HTTP management interface. The ML explanation identified the large service surface, unencrypted services, medium-risk services, and surveillance-protocol exposure as the strongest non-zero signals.

The absence of a CVE match is an expected conservative result for this profile. An exposed service and an outdated version are not by themselves enough to identify a product-specific CVE. This illustrates an important difference between exposure assessment and vulnerability confirmation.

**Table IV. Representative finding evidence and remediation**

| Finding | Severity | Evidence | Recommended action |
|---|---|---|---|
| Default credentials | Critical | Simulated vendor profile contains default credentials | Replace defaults and require unique administrator credentials |
| Outdated firmware | High | Current version is below the local vendor baseline | Verify the model and apply the supported firmware update |
| ONVIF exposure | Medium | ONVIF service present in the profile | Restrict management access and use strong authentication |
| RTSP exposure | Medium | RTSP service present without encryption | Restrict stream access and require authentication |
| HTTP management | Low | HTTP interface present | Prefer HTTPS and restrict administrative access |

**Fig. 5. Risk-score and anomaly-score comparison.** *Insert an original bar chart comparing the deterministic score, ML anomaly score, finding severity counts, and feature signals for at least three simulated profiles.*

### C. Interpretation

The experiment shows that the platform can combine heterogeneous evidence into a prioritized result. The deterministic score emphasizes finding severity and operational impact, while the Isolation Forest score emphasizes deviation from the baseline. The two values are related but not identical; this makes the ML output useful as a secondary signal rather than a duplicate of the rule engine.

The simulation also demonstrates the main evaluation limitation. The profile is deterministic and designed for repeatability, not collected from a representative population of deployed cameras. Therefore, the experiment supports workflow correctness, traceability, and explainability, but it does not establish generalization to all CCTV manufacturers or models.

## VIII. Discussion and Limitations

The strongest contribution of SecureVision is the integration of evidence, context, and action. A raw port list is transformed into a device profile, security findings, risk score, anomaly explanation, and remediation path. The evidence policy also limits a common reporting error: treating every HTTP, FTP, RTSP, or Telnet service as proof of a particular CVE.

The primary limitation is data. The bootstrap baseline contains a small number of manually specified exposure patterns, and the simulated profiles are not a substitute for a labeled camera dataset. The model should therefore be described as an anomaly-prioritization component. Future evaluation should collect authorized scan profiles from multiple device families, label meaningful security conditions, compare Isolation Forest with other methods, and measure stability across repeated scans.

Other limitations include incomplete vendor coverage, dependence on Nmap output quality, possible firewall and authentication effects, and the absence of authenticated firmware verification. The deployed API also requires authentication hardening before production use. Live testing must remain limited to authorized scopes, and reports should avoid exposing credentials, private addresses, or sensitive video-system metadata.

## IX. Conclusion and Future Work

This paper presented SecureVision VAPT, an AI-assisted assessment platform for CCTV and surveillance-device exposure. The system combines live or simulated discovery, fingerprinting, service analysis, conservative CVE correlation, severity scoring, Isolation Forest anomaly detection, persistence, dashboard analytics, and remediation guidance. The representative simulation produced a Hikvision-style profile, five findings, a rule-based risk score of 93/100, and a high anomaly score of 100/100, with explanations tied to observed features.

The results support the use of the platform as an educational and defensive assessment workflow. They do not establish vulnerability-detection accuracy across real-world devices. Future work should expand the device and firmware evidence base, add authenticated assessment where permitted, collect a labeled evaluation dataset, compare multiple anomaly-detection algorithms, add API authentication, and measure performance on authorized real-device studies.

## Acknowledgment

The authors thank **[Project Guide Name]** and the **School of Engineering, Anurag University** for guidance and support. Replace this section with the approved wording before submission.

## References

[1] G. Lyon, *Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning*. Insecure.Com LLC, 2009.

[2] Nmap Project, “Nmap Reference Guide,” 2026. [Online]. Available: https://nmap.org/book/man.html

[3] K. Scarfone, M. Souppaya, A. Cody, and A. Orebaugh, “Technical Guide to Information Security Testing and Assessment,” NIST Special Publication 800-115, 2008.

[4] National Institute of Standards and Technology, “The NIST Cybersecurity Framework (CSF) 2.0,” NIST CSWP 29, 2024.

[5] FIRST, “Common Vulnerability Scoring System Version 3.1: Specification Document,” 2019.

[6] National Institute of Standards and Technology, “National Vulnerability Database,” 2026. [Online]. Available: https://nvd.nist.gov/

[7] MITRE, “Common Weakness Enumeration,” 2026. [Online]. Available: https://cwe.mitre.org/

[8] MITRE, “MITRE ATT&CK Enterprise Matrix,” 2026. [Online]. Available: https://attack.mitre.org/

[9] ONVIF, “ONVIF Core Specification,” ONVIF, 2025. [Online]. Available: https://www.onvif.org/specs/core/

[10] ETSI, “Cyber Security for Consumer Internet of Things: Baseline Requirements,” ETSI EN 303 645 V2.1.1, 2020.

[11] OWASP Foundation, “OWASP Internet of Things Top 10,” 2018. [Online]. Available: https://owasp.org/www-project-internet-of-things/

[12] M. Fagan, K. Megontshola, M. Watrobski, and others, “Foundational Cybersecurity Activities for IoT Device Manufacturers,” NISTIR 8259, 2020.

[13] E. Bertino and N. Islam, “Botnets and Internet of Things Security,” *Computer*, vol. 50, no. 2, pp. 76-79, 2017.

[14] M. Abomhara and G. M. Køien, “Cyber Security and the Internet of Things: Vulnerabilities, Threats, Intruders and Attacks,” *Journal of Cyber Security and Mobility*, vol. 4, no. 1, pp. 65-88, 2015.

[15] A.-R. Sadeghi, C. Wachsmann, and M. Waidner, “Security and Privacy Challenges in Industrial Internet of Things,” in *Proc. 52nd ACM/EDAC/IEEE Design Automation Conference*, 2015.

[16] S. Sicari, A. Rizzardi, L. A. Grieco, and A. Coen-Porisini, “Security, Privacy and Trust in Internet of Things: The Road Ahead,” *Computer Networks*, vol. 76, pp. 146-164, 2015.

[17] E. Fernandes, J. Jung, and A. Prakash, “Security Analysis of Emerging Smart Home Applications,” in *Proc. IEEE Symposium on Security and Privacy*, 2016.

[18] M. Miettinen et al., “IoT Sentinel: Automated Device-Type Identification for Security Enforcement in IoT,” in *Proc. IEEE International Conference on Distributed Computing Systems*, 2017.

[19] F. T. Liu, K. M. Ting, and Z.-H. Zhou, “Isolation Forest,” in *Proc. IEEE International Conference on Data Mining*, 2008, pp. 413-422.

[20] V. Chandola, A. Banerjee, and V. Kumar, “Anomaly Detection: A Survey,” *ACM Computing Surveys*, vol. 41, no. 3, 2009.

[21] A. L. Buczak and E. Guven, “A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection,” *IEEE Communications Surveys & Tutorials*, vol. 18, no. 2, pp. 1153-1176, 2016.

[22] M. Ring et al., “A Survey of Network-Based Intrusion Detection Data Sets,” *Computers & Security*, vol. 86, pp. 147-167, 2019.

[23] C. Kolias, G. Kambourakis, A. Stavrou, and J. Voas, “DDoS in the IoT: Mirai and Other Botnets,” *Computer*, vol. 50, no. 7, pp. 80-84, 2017.

[24] scikit-learn developers, “IsolationForest,” *scikit-learn User Guide*, 2026. [Online]. Available: https://scikit-learn.org/stable/modules/outlier_detection.html

[25] OWASP Foundation, “OWASP API Security Top 10,” 2023. [Online]. Available: https://owasp.org/API-Security/

**Submission checklist:** replace all bracketed placeholders; verify every reference and publication year; create original figures yourself; insert 4-5 figures and 3-4 tables after they are cited; remove all IEEE template guidance text; format this content in the supplied A4 IEEE template; run plagiarism and AI-content checks; and confirm the final paper is at least eight pages.
