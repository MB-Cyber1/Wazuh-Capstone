# SOC Analyst & Incident Responder Bootcamp — Capstone Project

> **Live Lab Status**: All 3 VMs (`SOC-Wazuh` `192.168.99.10`, `SOC-Win10` `192.168.99.30`, and `SOC-ubuntu-01` `192.168.99.40`) are live on `VMnet1` (`192.168.99.0/24`). All **10 Detection Rules + Correlation Rule `100200`** have been triggered live in Wazuh v4.14.9 with zero post-tuning false positives.

## Squad Roster & Ownership ([`CONTRIBUTION_MAP.md`](CONTRIBUTION_MAP.md))
- **Mohammad Bustami** — Lead Detection Engineer (`100005`, `100007 + 100200`, `100201`, `100207`), SIEM Architect & Incident A Lead Blue-Team Investigator
- **Saif Asender** — Detection Engineer (`100013`, `100203`, `100202`), Linux/Windows Telemetry Engineer, Incident A Red-Team Operator & Ticket #4 Lead
- **Mohammad Alodeh** — Detection Engineer (`100204`, `100205`, `100206`), Incident B False-Positive/Tuning Lead, Ticket #3 Lead & Incident Readiness Lead

---

## 1. Live Lab Quick-Access Guide

| Resource | Address / URL | Credentials / SSH Key |
| :--- | :--- | :--- |
| **Wazuh Dashboard (SIEM UI)** | `https://192.168.99.10` | Username: `admin`<br/>Password: `SecretPassword` |
| **Custom Tier-1 Dashboard** | `https://192.168.99.10/app/dashboards#/view/soc-capstone-tier1-dashboard` | `admin` / `SecretPassword` |
| **Alerts (Alerting monitor queue)** | `https://192.168.99.10/app/alerting#/dashboard` (Explore → Alerting) — see [`DASHBOARD_GUIDE.md` §4](detections/dashboard/DASHBOARD_GUIDE.md) | `admin` / `SecretPassword` |
| **`SOC-Wazuh` VM (Ubuntu 24.04 + Docker)** | `192.168.99.10` (`Agent 000`) | `ssh -i ~/.ssh/soclab_ed25519 soc@192.168.99.10` (`SocLab!2026`) |
| **`Win10` VM (Windows 11 Enterprise + Sysmon)** | `192.168.99.30` (`Agent 002`) | `ssh -i ~/.ssh/soclab_ed25519 soc@192.168.99.30` (`SocLab!2026`) |
| **`ubuntu-01` VM (Ubuntu 24.04 + `auditd` + `nginx`)** | `192.168.99.40` (`Agent 001`) | `ssh -i ~/.ssh/soclab_ed25519 soc@192.168.99.40` (`SocLab!2026`) |

---

## 2. Complete Rubric & Deliverable Map

### Part 1 — Build, Detect, Triage (60 Points)

| Sub-task | Weight | Deliverables in Repository |
| :--- | :---: | :--- |
| **1.1 Lab & Log Pipeline** | **6 pts** | - [`evidence/PIPELINE_PROOF.md`](evidence/PIPELINE_PROOF.md) — Architecture diagram, `agent_control -l` output, sub-second ingestion latency (`0.45s–0.83s`), and parsed JSON fields across all 3 log sources (`Win10` Sysmon/WinEvent, `ubuntu-01` `auditd`, `ubuntu-01` `nginx`) |
| **1.2 10 Rules Fire with Evidence** | **10 pts** | - **Wazuh XML Rules**: [`detections/wazuh/local_rules.xml`](detections/wazuh/local_rules.xml) (`100005`, `100007`, `100200`, `100201`, `100013`, `100203`, `100202`, `100204`, `100205`, `100206`, `100207`)<br/>- **Live Fired Alert Evidence**: [`evidence/RULE_EVIDENCE_SUMMARY.md`](evidence/RULE_EVIDENCE_SUMMARY.md) & [`evidence/alerts_evidence.json`](evidence/alerts_evidence.json) |
| **1.3 Detection Logic Quality, Sigma & ATT&CK v19** | **12 pts** | - **10 Sigma v2 Rules** (`sigma check` = 0 errors): [`detections/sigma/`](detections/sigma)<br/>- **Sigma -> Wazuh Conversion Log**: [`detections/CONVERSION_LOG.md`](detections/CONVERSION_LOG.md)<br/>- **MITRE ATT&CK v19 Navigator Layer & Gap Note**: [`detections/navigator/attack_navigator_v19.json`](detections/navigator/attack_navigator_v19.json) & [`GAP_NOTE.md`](detections/navigator/GAP_NOTE.md) |
| **1.4 Cards, Benign Testing, Tuning & Dashboard** | **9 pts** | - **10 Detection Cards**: [`detections/cards/card_01_rule_100005.md`](detections/cards/card_01_rule_100005.md) .. [`card_10_rule_100207.md`](detections/cards/card_10_rule_100207.md)<br/>- **Rule Tuning & Benign Testing Report**: [`detections/tuning/TUNING_REPORT.md`](detections/tuning/TUNING_REPORT.md)<br/>- **6-Panel Custom Dashboard**: [`detections/dashboard/soc_capstone_tier1_dashboard.ndjson`](detections/dashboard/soc_capstone_tier1_dashboard.ndjson) & [`DASHBOARD_GUIDE.md`](detections/dashboard/DASHBOARD_GUIDE.md) |
| **1.5 Alert Triage, Escalation & Containment** | **14 pts** | - [`triage/ticket_01_incident_a.md`](triage/ticket_01_incident_a.md) (Incident A True Positive Attack Chain)<br/>- [`triage/ticket_02_incident_b_fp.md`](triage/ticket_02_incident_b_fp.md) (Incident B False Positive + Tuning)<br/>- [`triage/ticket_03_linux_ssh_persistence.md`](triage/ticket_03_linux_ssh_persistence.md) (Linux `authorized_keys` + `crontab` TP)<br/>- [`triage/ticket_04_defense_impairment.md`](triage/ticket_04_defense_impairment.md) (Security Event Log Cleared `1102` TP)<br/>- [`triage/escalation_call_incident_a.md`](triage/escalation_call_incident_a.md) (6-Field Escalation Call)<br/>- [`triage/containment_and_evidence_preservation.md`](triage/containment_and_evidence_preservation.md) & [`evidence/SHA256SUMS.txt`](evidence/SHA256SUMS.txt) |
| **1.6 Incident A Report & 8-Min Demo Script** | **9 pts** | - [`triage/INCIDENT_A_REPORT.md`](triage/INCIDENT_A_REPORT.md)<br/>- [`triage/LIVE_DEMO_SCRIPT_8MIN.md`](triage/LIVE_DEMO_SCRIPT_8MIN.md) |

---

### Part 2 — Incident Readiness Pack (40 Points)

| Sub-task | Weight | Deliverables in Repository |
| :--- | :---: | :--- |
| **2.1 Org Profile & Risk Register** | **6 pts** | - [`readiness/01_org_profile_and_risk_register.md`](readiness/01_org_profile_and_risk_register.md) (Medira Health Systems profile, MTD/RTO/RPO, 12-row Risk Register + Top 3 Deep Dive) |
| **2.2 Severity Classification Matrix** | **4 pts** | - [`readiness/02_severity_classification_matrix.md`](readiness/02_severity_classification_matrix.md) (P1–P4 SLAs, 12 concrete examples + 5 updated Detection Cards) |
| **2.3 Escalation Tree & Contact Roster** | **4 pts** | - [`readiness/03_escalation_tree_and_contacts.md`](readiness/03_escalation_tree_and_contacts.md) (Mermaid decision tree, 10-min fallback, 24/7 roster, SDAIA/NCA national reporting) |
| **2.4 Three IR Playbooks + Chain of Custody** | **5 pts** | - [`readiness/04_ir_playbooks.md`](readiness/04_ir_playbooks.md) (`PB-01`, `PB-02`, `PB-03` + Mermaid flowcharts + Chain-of-Custody Form) |
| **2.5 Playbook Testing & Cold Test** | **6 pts** | - [`readiness/05_playbook_testing_sheet.md`](readiness/05_playbook_testing_sheet.md) (Target vs. actual times, 5 live gaps found & fixed + Cold Test sheet) |
| **2.6 Crisis Communication Plan** | **3 pts** | - [`readiness/06_communication_plan.md`](readiness/06_communication_plan.md) (Matrix + 5 ready-to-send templates: Executive, Staff, Regulator, Customers/Patients, Media) |
| **2.7 Tabletop Exercise (TTX) Package** | **7 pts** | - [`readiness/07_tabletop_exercise_package.md`](readiness/07_tabletop_exercise_package.md) ("Operation Silent Ward" 45-min TTX, 6 timed injects, AAR + Observer Log Sheet) |
| **2.8 Board Executive Briefing** | **5 pts** | - [`readiness/08_executive_briefing.md`](readiness/08_executive_briefing.md) (Executive metrics, top 3 residual risks, 30/60/90-day roadmap, cited IBM/DBIR cost of inaction, 10-slide outline) |


---

## 3. Live Wazuh SIEM Screenshots (`evidence/Screenshots/`)

- **Active Endpoints (`Win10` & `ubuntu-01`)**: [`evidence/Screenshots/ActiveEndpoint-WAZUH.png`](evidence/Screenshots/ActiveEndpoint-WAZUH.png)
- **6-Panel Custom Tier-1 Dashboard**: [`evidence/Screenshots/Dashboard-WAZUH.png`](evidence/Screenshots/Dashboard-WAZUH.png)
- **Threat Hunting Overview**: [`evidence/Screenshots/ThreatHunt-WAZUH.png`](evidence/Screenshots/ThreatHunt-WAZUH.png)
- **Security Events Stream**: [`evidence/Screenshots/Events-WAZUH.png`](evidence/Screenshots/Events-WAZUH.png)
- **MITRE ATT&CK Overview**: [`evidence/Screenshots/MITRE ATT&CK-WAZUH.png`](evidence/Screenshots/MITRE%20ATT%26CK-WAZUH.png)
- **Discover Log Stream**: [`evidence/Screenshots/Discover-WAZUH.png`](evidence/Screenshots/Discover-WAZUH.png)
