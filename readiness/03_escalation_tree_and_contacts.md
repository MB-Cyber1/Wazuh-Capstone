# Sub-task 2.3 — Escalation Tree & 24/7 Contact Roster (4 pts)

## 1. Visual Incident Escalation Tree (Mermaid Flowchart)

```mermaid
flowchart TD
    A["Wazuh Alert Fires on SOC-Wazuh (192.168.99.10)<br/>Tier-1 SOC Analyst Initial Triage"] --> B{"Severity Classification<br/>(See 02_severity_classification_matrix.md)"}

    B -- "P4 (Lvl 3-6)<br/>False Positive / Baseline" --> C["Close Ticket as FP/BTP<br/>Log Tuning Proposal if Noisy<br/>(SLA: 4h Review)"]
    B -- "P3 (Lvl 7-9)<br/>100203, 100204, 100205, 100206" --> D["Tier-1 Investigates Host & User Context<br/>(Ack <= 30m | Contain <= 2h)"]
    D --> E{"Correlated with other alerts<br/>or Unauthorized Change?"}
    E -- "No (Approved Admin Activity)" --> C
    E -- "Yes (Unauthorized / Multi-Stage)" --> F["Elevate to P2 or P1<br/>Notify Tier-2 IR Lead"]

    B -- "P2 (Lvl 10-11)<br/>100005, 100007, 100013, 100202" --> G["Escalate to On-Call Tier-2 IR Lead<br/>Execute Playbook PB-01 / PB-02 / PB-03<br/>(Ack <= 15m | Contain <= 45m)"]
    B -- "P1 (Lvl 12-15 or Multi-Stage Chain)<br/>100200, 100201, 100207 (Incident A)" --> H["IMMEDIATE P1 WAR ROOM ACTIVATION<br/>6-Field Verbal Call to Tier-2 Lead + SOC Manager<br/>(Ack <= 5m | Host Isolation <= 15m)"]

    H --> I["CISO & Infrastructure Lead Notified (<= 15m)<br/>Authorize Domain/Account Reset & Segment Quarantine"]
    I --> J{"PHI / PII Exposure or<br/>Clinical Portal Outage?"}
    J -- "Yes" --> K["Legal Counsel, DPO & CEO Notified (<= 60m)<br/>Activate 72h PDPL / NCA / HIPAA Breach Notification"]
    J -- "No (Contained Pre-Exfiltration)" --> L["Complete Eradication, SHA-256 Evidence Lock<br/>& Post-Incident Review within 72h"]
```

---

## 2. 24/7 Incident Response Contact Roster

| Role | Primary Contact | Backup Contact | Primary Channel | Out-of-Band (OOB) Channel *(if Corp IT/Email Compromised)* | Notification Trigger & SLA |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier-1 SOC Analyst (24/7 Shift)** | Shift Analyst Alpha (`soc-t1@medira.health`) | Shift Analyst Bravo (`soc-t1-backup@medira.health`) | Wazuh Dashboard + Jira SOC Queue | Signal Group: `Medira-IR-Ops` (`+966-50-555-0101`) | All alerts (`P1 <= 5m`, `P2 <= 15m`, `P3 <= 30m`) |
| **Tier-2 Incident Response Lead** | Tariq Al-Harbi (`t.alharbi@medira.health`) | Sara Al-Qahtani (`s.alqahtani@medira.health`) | Voice Call + Slack `#soc-ir-warroom` | Personal Mobile / Signal (`+966-50-555-0102` / `0103`) | All **P1** (`<= 5m` voice call) and **P2** (`<= 15m`) |
| **SOC Manager** | Majed Al-Otaibi (`m.alotaibi@medira.health`) | Tariq Al-Harbi (Acting) | Voice Call + PagerDuty | Signal (`+966-50-555-0104`) | All **P1** (`<= 10m`) or any **P2** exceeding 45m containment SLA |
| **Chief Information Security Officer (CISO)** | Dr. Layla Al-Mansoor (`ciso@medira.health`) | Majed Al-Otaibi (Deputy) | Voice Call | Signal (`+966-50-555-0105`) | All **P1** (`<= 15m`), regulatory events, or clinical downtime |
| **Windows / AD Infrastructure Lead (`Win10`)** | Fahad Al-Dossary (`f.aldossary@medira.health`) | Omar Al-Zahrani (`o.alzahrani@medira.health`) | Slack `#infra-oncall` + Voice | Signal (`+966-50-555-0106`) | Host isolation / GPO / account lockout on `Win10` (`192.168.99.30`) |
| **Linux & Cloud Platform Owner (`ubuntu-01`)** | Nadia Siddiqui (`n.siddiqui@medira.health`) | Kareem Hassan (`k.hassan@medira.health`) | Slack `#platform-oncall` + Voice | Signal (`+966-50-555-0107`) | SSH / `cron` / `nginx` compromise on `ubuntu-01` (`192.168.99.40`) |
| **General Counsel & Data Protection Officer (DPO)** | Advisor Khalid Al-Sudairi (`dpo@medira.health`) | External Privacy Counsel (`ir-legal@lexhealth.sa`) | Encrypted Email / Voice | Signal (`+966-50-555-0108`) | Any confirmed/suspected PHI/PII access within **60 minutes** (72h PDPL clock) |
| **CEO & Medical Director (Executive Crisis)** | Dr. Nasser Al-Ghamdi (`ceo@medira.health`) | COO Office (`coo@medira.health`) | Direct CISO Phone Briefing | Signal (`+966-50-555-0109`) | Confirmed **P1** affecting clinical operations or public reputation (`<= 60m`) |

---

## 3. Business-Hours vs. Out-of-Hours Call Order & No-Answer Fallback Policy

| Time Window | Step 1 (T+00m) | Step 2 — 10-Min No-Answer Fallback (T+10m) | Step 3 — 20-Min Escalation (T+20m) |
| :--- | :--- | :--- | :--- |
| **Business Hours** (`Sun–Thu, 08:00–17:00 AST`) | On-Shift Tier-1 Analyst places **6-Field Call** to Primary Tier-2 IR Lead (`Tariq Al-Harbi`, `+966-50-555-0102`) + posts in Slack `#soc-ir-warroom`. | If no answer within **10 minutes**, call Backup Tier-2 Lead (`Sara Al-Qahtani`, `+966-50-555-0103`) AND SOC Manager (`Majed Al-Otaibi`, `+966-50-555-0104`). | If unacknowledged at **20 minutes**, page CISO (`Dr. Layla Al-Mansoor`, `+966-50-555-0105`) via Signal OOB channel and initiate host quarantine autonomously. |
| **Out of Hours / Weekends / Holidays** (`17:00–08:00 AST, Fri–Sat`) | On-Shift Tier-1 Analyst triggers PagerDuty High-Urgency Push + direct mobile voice call to On-Call Tier-2 Duty Officer (`+966-50-555-0102`). | If no answer within **10 minutes** (2 voice attempts, 5 minutes apart), call Backup Tier-2 Duty Officer (`+966-50-555-0103`) and SOC Manager (`+966-50-555-0104`). | At **15 minutes** for P1 incidents, call CISO directly (`+966-50-555-0105`) and execute pre-authorized firewall isolation (`Playbook PB-01`/`PB-02`). |

---

## 4. External Parties, Vendors & National Regulatory Reporting Requirements

| External Entity | Contact / Portal | Trigger Condition | Mandatory Reporting Deadline & Requirement |
| :--- | :--- | :--- | :--- |
| **Saudi Data & AI Authority (SDAIA — PDPL Regulator)** | National Data Governance Platform (`dgp.sdaia.gov.sa`) — Submitted by DPO (`Khalid Al-Sudairi`) | Any breach involving unauthorized access, disclosure, or destruction of Personal Data / Patient PHI. | **≤ 72 hours** of detection (Saudi PDPL Article 20 & Implementing Regulations); Affected data subjects notified "without undue delay" if high risk. |
| **National Cybersecurity Authority (NCA — Saudi CERT)** | NCA National Operations Portal (`nca.gov.sa` / `cert.gov.sa`) — Submitted by CISO | Critical cybersecurity incident (P1) affecting healthcare sector operations or critical infrastructure controls (ECC-1:2018). | **≤ 24 hours** initial flash notification for critical sector incidents; follow-up technical report within 72 hours. |
| **Ministry of Health (MOH) Healthcare Cyber Center** | `moh-cert@moh.gov.sa` | Any incident threatening clinical diagnostic availability or hospital EHR interconnectivity. | **≤ 24 hours** if clinical operations or external lab integrations are degraded. |
| **Law Enforcement (Presidency of State Security / Cybercrime Unit)** | Official Legal Filing via General Counsel | Confirmed criminal extortion, ransomware demand, or nation-state intrusion. | Filed upon CEO + General Counsel authorization after forensic hash preservation (`SHA256SUMS.txt`). |
| **External IR Retainer & SIEM Vendor Support** | Wazuh / Cloud Managed IR Retainer (`ir-emergency@cyberdefense.sa`) | P1 incident exceeding internal Tier-2 capacity or requiring full memory/disk malware reverse engineering. | **4-hour** contractual SLA response upon SOC Manager / CISO activation. |
