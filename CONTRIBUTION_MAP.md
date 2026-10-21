# Team Contribution & Peer-Review Map (3-Member Team)

> **Graduation Project Rule**: *Teams of 3–4. Every student writes 2+ rules and owns 1+ Part 2 task. Put this in a 1-page contribution map. Everything goes in the team Git repo.*

---

## Squad Roster & High-Level Roles
1. **Mohammad Bustami** — SIEM Architect, Lead Detection Engineer (4 Rules + Correlation) & Incident A Lead Blue-Team Investigator
2. **Saif Asender** — Linux/Windows Telemetry Engineer, Detection Engineer (3 Rules) & Incident A Red-Team Operator
3. **Mohammad Alodeh** — Detection Engineer (3 Rules), Tuning & False-Positive Lead (Incident B) & Incident Readiness Lead

---

## 1. Detection Rule Ownership & Peer Review Matrix (Sub-tasks 1.2, 1.3, 1.4)

*Requirement: Every student writes 2+ rules.*  
**Delivered: Mohammad Bustami = 4 Rules; Saif Asender = 3 Rules; Mohammad Alodeh = 3 Rules.**

| Rule ID | What It Detects (In Plain Text) | ATT&CK v19 | Primary Author (Owner) | Peer Reviewer (Approved) | Detection Card |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`100005`** | Suspicious PowerShell (encoded / cradle) | `T1059.001` (Execution) | **Mohammad Bustami** | **Saif Asender** | [`card_01_rule_100005.md`](detections/cards/card_01_rule_100005.md) |
| **`100007` + `100200`** | 5 failed logons -> Logon Success Correlation | `T1110 / T1078` (Cred Access) | **Mohammad Bustami** | **Mohammad Alodeh** | [`card_02_rule_100007.md`](detections/cards/card_02_rule_100007.md) |
| **`100201`** | LSASS Memory Access (Credential Dumping) | `T1003.001` (Cred Access) | **Mohammad Bustami** | **Saif Asender** | [`card_03_rule_100201.md`](detections/cards/card_03_rule_100201.md) |
| **`100013`** | LOLBin File Download (`certutil`/`bitsadmin`/`mshta`) | `T1105` (C2) | **Saif Asender** | **Mohammad Bustami** | [`card_04_rule_100013.md`](detections/cards/card_04_rule_100013.md) |
| **`100203`** | Linux Cron Job Modification (`/usr/bin/crontab`) | `T1053.003` (Persistence) | **Saif Asender** | **Mohammad Alodeh** | [`card_05_rule_100203.md`](detections/cards/card_05_rule_100203.md) |
| **`100202`** | Linux SSH `authorized_keys` Modification | `T1098.004` (Persistence) | **Saif Asender** | **Mohammad Bustami** | [`card_06_rule_100202.md`](detections/cards/card_06_rule_100202.md) |
| **`100204`** | Remote Desktop (RDP Logon Type 10) from Non-Local IP | `T1021.001` (Lateral Mvmt) | **Mohammad Alodeh** | **Mohammad Bustami** | [`card_07_rule_100204.md`](detections/cards/card_07_rule_100204.md) |
| **`100205`** | Suspicious `rundll32.exe` Proxy Execution | `T1218.011` (Stealth `TA0005`) | **Mohammad Alodeh** | **Saif Asender** | [`card_08_rule_100205.md`](detections/cards/card_08_rule_100205.md) |
| **`100206`** | Registry `Run` / `RunOnce` Value Set (`SetValue`) | `T1547.001` (Persistence) | **Mohammad Alodeh** | **Mohammad Bustami** | [`card_09_rule_100206.md`](detections/cards/card_09_rule_100206.md) |
| **`100207`** | Windows Security (`1102`) or System (`104`) Log Cleared | `T1685.005` (Defense Impair) | **Mohammad Bustami** | **Mohammad Alodeh** | [`card_10_rule_100207.md`](detections/cards/card_10_rule_100207.md) |

---

## 2. Part 2 Incident Readiness Pack Ownership (Sub-tasks 2.1 – 2.8)

*Requirement: Every student owns 1+ Part 2 task.*  
**Delivered: Every squad member owns dedicated Part 2 tasks as primary author:**

| Sub-task | Deliverable Description | Primary Author (Owner) | Reviewer / Contributor | File Link |
| :--- | :--- | :--- | :--- | :--- |
| **2.1** | **Organisation Profile & 12-Row Risk Register** (Medira Health Systems, MTD/RTO/RPO limits, Top 3 risk deep dive) | **Mohammad Bustami** | Saif Asender | [`01_org_profile_and_risk_register.md`](readiness/01_org_profile_and_risk_register.md) |
| **2.2** | **Severity Classification Matrix & Card Alignment** (P1–P4 org matrix, 12 concrete examples, SLAs, 5 updated cards) | **Mohammad Alodeh** | Mohammad Bustami | [`02_severity_classification_matrix.md`](readiness/02_severity_classification_matrix.md) |
| **2.3** | **Escalation Tree & National Reporting** (Call order, 10-min fallback policy, 24/7 roster, SDAIA <=72h & NCA <=24h) | **Saif Asender** | Mohammad Alodeh | [`03_escalation_tree_and_contacts.md`](readiness/03_escalation_tree_and_contacts.md) |
| **2.4** | **Playbook PB-01** (LSASS Memory Access, Ransomware Staging, Log Clearing) | **Mohammad Bustami** | Mohammad Alodeh | [`04_ir_playbooks.md`](readiness/04_ir_playbooks.md) |
| **2.4** | **Playbook PB-02** (Account Takeover, Brute Force & External RDP) | **Mohammad Alodeh** | Saif Asender | [`04_ir_playbooks.md`](readiness/04_ir_playbooks.md) |
| **2.4** | **Playbook PB-03** (Linux SSH Authorized Keys & Rogue Cron Persistence) | **Saif Asender** | Mohammad Bustami | [`04_ir_playbooks.md`](readiness/04_ir_playbooks.md) |
| **2.5** | **Playbook Testing & Cold Test Log** (Internal timed runs, 5 friction points fixed, External Student Cold Test) | **Mohammad Alodeh** | Saif Asender | [`05_playbook_testing_sheet.md`](readiness/05_playbook_testing_sheet.md) |
| **2.6** | **Crisis Communication Plan** (Spokesperson/approval matrix + 5 ready-to-send audience templates) | **Mohammad Alodeh** | Saif Asender | [`06_communication_plan.md`](readiness/06_communication_plan.md) |
| **2.7** | **Tabletop Exercise Package** ("Operation Silent Ward" 45-min TTX, 6 injects incl. pressure inject, Observer log) | **Saif Asender** | M. Bustami & M. Alodeh | [`07_tabletop_exercise_package.md`](readiness/07_tabletop_exercise_package.md) |
| **2.8** | **Board Executive Briefing** (1-page C-suite memo, top 3 risks, 10-slide outline, IBM $9.77M / DBIR cost of inaction) | **Mohammad Bustami** & **Mohammad Alodeh** | Saif Asender | [`08_executive_briefing.md`](readiness/08_executive_briefing.md) |

---

## 3. Separation of Duties in Incident Triage (Sub-tasks 1.5 & 1.6)

*Requirement: Incident A attacked by one member (who does not triage it); others triage, ticket, escalate, contain, and hash evidence. Incident B closed as FP with tuning suggestion. Queue of 4+ alerts; every member writes 1+ ticket.*

| Ticket ID | Incident Type | Assigned Blue-Team Analyst | Red-Team Attacker / Source | Peer Reviewer | File Link |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`SOC-2026-INC-A01`** | **Incident A** (P1 Critical True-Positive Chain) | **Mohammad Bustami** | **Saif Asender** *(Attacked; did not triage)* | Mohammad Alodeh | [`ticket_01_incident_a.md`](triage/ticket_01_incident_a.md) |
| **`SOC-2026-INC-B02`** | **Incident B** (P4 Informational False Positive) | **Mohammad Alodeh** | System Baseline (`0x1000` query on `lsass.exe`) | Mohammad Bustami | [`ticket_02_incident_b_fp.md`](triage/ticket_02_incident_b_fp.md) |
| **`SOC-2026-INC-C03`** | **Ticket #3** (P2 High Linux SSH & Cron TP) | **Mohammad Alodeh** | Saif Asender | Saif Asender | [`ticket_03_linux_ssh_persistence.md`](triage/ticket_03_linux_ssh_persistence.md) |
| **`SOC-2026-INC-D04`** | **Ticket #4** (P1 Critical Event Log Cleared TP) | **Saif Asender** | `wevtutil.exe cl Security` | Mohammad Bustami | [`ticket_04_defense_impairment.md`](triage/ticket_04_defense_impairment.md) |
