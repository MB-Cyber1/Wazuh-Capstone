# Sub-task 2.8 — Board-Level Executive Briefing (4 pts)

> **Audience**: Chief Executive Officer, Board of Directors, Medical Director, and General Counsel — **Medira Health Systems**  
> **Prepared By**: Security Operations & Incident Readiness Capstone Team  
> **Date**: 19 October 2026

---

## 1. Executive Summary: From Blind Spots to Sub-Second Detection

Over the past sprint, Medira Health Systems stood up an end-to-end **Security Operations Center (SOC) & Incident Readiness capability** built on **Wazuh SIEM (`v4.14.9`)**, covering both our **Windows clinical workstations (`Win10`)** and our **Linux patient portal server (`ubuntu-01`)**.

- **100% Visibility Across 3 Core Telemetry Streams**: Windows Security & Sysmon endpoint telemetry, Linux kernel audit logs (`auditd`), and patient portal web access logs (`nginx`) now stream into our central SIEM in **under 0.85 seconds**.
- **10 Custom Threat Detections + Multi-Event Correlation**: We deployed and verified 10 high-priority detection rules mapped to the latest **MITRE ATT&CK v19 (April 2026)** framework, catching password brute-force attacks, malicious PowerShell scripts, living-off-the-land downloads, unauthorized Remote Desktop connections, Linux backdoors, credential theft attempts, and audit-log tampering.
- **Proven Under Live Fire (Incident A)**: During a full-scale multi-stage intrusion simulation (`SOC-2026-INC-A01`), our SOC detected an attacker within **0.6 seconds**, correlated 8 attack steps across a single compromised account, isolated the affected workstation in **under 12 minutes**, and preserved 100% of the forensic evidence even after the attacker wiped the local Windows security log.

---

## 2. Key Operational Metrics Achieved

| Metric | Baseline (Before Project) | Current Verified Posture | Business Value |
| :--- | :---: | :---: | :--- |
| **Log Ingestion Latency** | No centralized SIEM | **0.45 – 0.83 seconds** | Attackers cannot erase their tracks locally (`Rule 100207`) before the SOC captures the evidence. |
| **Validated Detection Rules** | 0 custom rules | **10 Rules + Correlation (`100200`)** | Covers 8 MITRE ATT&CK v19 tactics across Windows & Linux. |
| **False Positive Rate (Post-Tuning)** | High OS background noise (26 FPs / 5m) | **0 False Positives** across 10 benign tests | Analysts spend time on real threats instead of chasing antivirus and OS noise. |
| **P1 Critical Containment Time** | Unmeasured / Ad-hoc | **3m 20s** (Target SLA: ≤ 15m) | Stops lateral movement and ransomware staging before patient data is reached. |

---

## 3. Top Three Residual Risks & Business Impact

1. **Password-Based Remote Access Without Lockout (`RSK-02` — High Priority)**:
   - *Business Risk*: While we now detect brute-force attacks (`100007`) and subsequent logins (`100200`) in seconds, accounts without automatic lockout and Multi-Factor Authentication (MFA) can still be guessed.
2. **Living-Off-the-Land Built-in Windows Utilities (`RSK-01` — Medium Priority)**:
   - *Business Risk*: Built-in Windows tools (`bitsadmin`, `mshta`, `rundll32`) are installed on every workstation by default and can be abused to pull malicious files if not restricted by application control policies.
3. **Single-Node SIEM Availability (`AST-03` — Medium Priority)**:
   - *Business Risk*: Our Wazuh SIEM (`192.168.99.10`) currently runs as a single-node Docker deployment; a hardware failure on the SIEM host would pause real-time alerting until restored.

---

## 4. Prioritized 30 / 60 / 90-Day Security Roadmap

| Horizon | Milestone | Cost / Effort | Expected Risk Reduction |
| :---: | :--- | :---: | :--- |
| **30 Days (Immediate Quick Wins)** | 1. Enforce 5-attempt Account Lockout Policy & RDP Jump-Host restriction on `Win10`.<br/>2. Restrict Linux `/etc/cron.allow` to `root` on `ubuntu-01`.<br/>3. Enable Windows Defender Attack Surface Reduction (ASR) rules for LOLBins. | **$0 (Configuration Only)** | Eliminates automated password brute-forcing (`RSK-02`) and unauthorized user cron jobs (`RSK-03`). |
| **60 Days (Identity & Visibility Expansion)** | 1. Onboard Active Directory Domain Controller (`DC01`) and DNS/Firewall logs into Wazuh.<br/>2. Enforce hardware-token / push MFA for all administrative RDP and SSH logins. | **Low** | Closes our #1 documented ATT&CK v19 visibility gap (Kerberoasting `T1558.003` & DCSync `T1003.006`). |
| **90 Days (Resilience & Automation)** | 1. Configure automated Wazuh Active Response to auto-block external brute-force IPs after Rule `100007`.<br/>2. Add daily off-site immutable backups for Wazuh Indexer (`wazuh-alerts-*`). | **Medium** | Reduces P2/P1 containment time from minutes to **< 5 seconds** and ensures 1-year PDPL/NCA audit retention. |

---

## 5. Financial Cost of Inaction (Industry Benchmark Citations)

| Benchmark Metric | Cited Industry Figure | Source Citation | Relevance to Medira Health Systems |
| :--- | :---: | :--- | :--- |
| **Global Healthcare Average Breach Cost** | **\$9.77 Million** per breach (#1 highest-cost industry for 14 consecutive years) | *IBM Security Cost of a Data Breach Report 2024* | Uncontained `lsass.exe` credential theft (`Rule 100201`) leading to clinic-wide ransomware carries multi-million-dollar recovery and regulatory liability. |
| **Middle East (Saudi Arabia / UAE) Average Breach Cost** | **\$8.75 Million** (SAR 32.8M) per breach | *IBM Cost of a Data Breach Report 2024 (Middle East Regional Analysis)* | Regional healthcare & critical sector breaches rank 2nd highest globally in per-incident cost. |
| **Savings from Fast Detection & Containment (< 200 Days vs > 200 Days)** | **\$1.02 Million – \$1.80 Million** saved when contained rapidly via SIEM + IR Playbooks | *IBM Cost of a Data Breach Report 2024* | Our SOC reduced detection latency to **`0.57 seconds`** and P1 host containment to **`3 minutes 20 seconds`**. |
| **Stolen Credentials & Brute Force Share of Breaches** | **38% – 49%** of non-error breaches involve stolen credentials or brute force (`T1110` / `T1078`) | *Verizon 2024 Data Breach Investigations Report (DBIR)* | Directly validates our investment in Rules `100007`, `100200`, `100201`, and `100204`. |

---

## 6. 10-Minute Executive Presentation Slide Outline (10 Slides)

| Slide # | Time | Slide Title | Key Talking Points & Visuals |
| :---: | :---: | :--- | :--- |
| **Slide 1** | `0:00–0:45` | **Mission & Scope: Protecting Medira Health Systems** | 220 staff, 45,000 patients/year, PDPL/NCA/HIPAA compliance scope; protecting Crown Jewels (`Win10` clinical admin & `ubuntu-01` patient portal). |
| **Slide 2** | `0:45–1:45` | **Why We Built This Now: The Cost of Inaction** | Healthcare breaches average **\$9.77M** globally / **\$8.75M** in the Middle East (IBM 2024); nearly half start with compromised credentials (Verizon DBIR 2024). |
| **Slide 3** | `1:45–2:45` | **Our New SOC Architecture (`SOC-Wazuh`)** | Diagram of `Win10` (Sysmon + WinEvent), `ubuntu-01` (`auditd` + `nginx`), and `SOC-Wazuh` Docker SIEM streaming logs in **`0.45 – 0.83 seconds`**. |
| **Slide 4** | `2:45–3:45` | **10 Custom Threat Detections + Correlation** | Plain-English tour of Rules `100005`–`100207` mapped to MITRE ATT&CK v19 (Credential Access, Execution, Persistence, Lateral Movement, Stealth, Defense Impairment). |
| **Slide 5** | `3:45–4:45` | **Eliminating False Positives (Signal vs. Noise)** | How we tuned out 26 OS/Defender false positives (`Incident B`) so analysts achieve **0 false positives** across 10 benign tests. |
| **Slide 6** | `4:45–6:00` | **Proof Under Fire: Catching Incident A in Seconds** | Visual timeline of `SOC-2026-INC-A01`: Brute force (`100007`) -> Login (`100200`) -> RDP (`100204`) -> PowerShell (`100005`) -> LOLBin (`100013`) -> LSASS (`100201`) -> Log Cleared (`100207`). |
| **Slide 7** | `6:00–7:00` | **Why Log Tampering Failed Against Our SIEM** | Even when the attacker ran `wevtutil cl Security` (`100207`), 100% of prior logs were already safely stored and SHA-256 hashed on `SOC-Wazuh`. |
| **Slide 8** | `7:00–8:00` | **Operational Readiness: Playbooks, SLAs & Crisis Comms** | P1–P4 Severity Matrix (`Ack <= 5m`, `Contain <= 15m`), 3 tested IR Playbooks (`PB-01`–`PB-03`), and 72-hour PDPL regulatory templates. |
| **Slide 9** | `8:00–9:00` | **Top 3 Residual Risks & Visibility Gaps** | Password lockout enforcement (`RSK-02`), LOLBin application control (`RSK-01`), and Kerberoasting (`T1558.003`) gap note. |
| **Slide 10** | `9:00–10:00` | **30 / 60 / 90-Day Roadmap & Board Ask** | 30d zero-cost GPO hardening, 60d AD Domain Controller + MFA onboarding, 90d automated Wazuh Active Response. |
