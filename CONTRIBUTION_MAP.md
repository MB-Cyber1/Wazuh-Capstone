# Team Contribution & Peer-Review Map (3-Member Team)

## Squad Roster
1. **Mohammad Bustami** — Lead Detection Engineer, SIEM Architect & Incident A Lead Blue-Team Investigator
2. **Saif Asender** — Detection Engineer, Linux/Windows Telemetry Engineer & Incident A Red-Team Operator
3. **Mohammad Alodeh** — Detection Engineer, False-Positive/Tuning Analyst (Incident B) & Incident Readiness Lead

---

## 1. Detection Rule Ownership & Peer Review Matrix (Sub-tasks 1.2, 1.3, 1.4)

Every team member authored at least 3 detection rules and peer-reviewed a teammate's Detection Cards as required by Sub-tasks 1.2 and 1.4:

| Rule ID | MITRE ATT&CK v19 | Rule Title | Primary Author | Peer Reviewer (Approved) | Detection Card |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`100005`** | `T1059.001` (Execution) | Suspicious PowerShell Execution (`-enc` / Download Cradle) | **Mohammad Bustami** | **Saif Asender** | [`card_01_rule_100005.md`](detections/cards/card_01_rule_100005.md) |
| **`100007` + `100200`** | `T1110` / `T1078` (Credential Access) | Brute Force (5x `4625` in 2m) -> Logon Success (`4624` in 5m) Correlation | **Mohammad Bustami** | **Mohammad Alodeh** | [`card_02_rule_100007.md`](detections/cards/card_02_rule_100007.md) |
| **`100201`** | `T1003.001` (Credential Access) | LSASS Process Memory Access (`Sysmon Event 10`) | **Mohammad Bustami** | **Saif Asender** | [`card_03_rule_100201.md`](detections/cards/card_03_rule_100201.md) |
| **`100013`** | `T1105` (Command & Control) | LOLBin File Download (`certutil` / `bitsadmin` / `mshta`) | **Saif Asender** | **Mohammad Bustami** | [`card_04_rule_100013.md`](detections/cards/card_04_rule_100013.md) |
| **`100203`** | `T1053.003` (Persistence) | Linux Cron Job Modification (`/usr/bin/crontab`) | **Saif Asender** | **Mohammad Alodeh** | [`card_05_rule_100203.md`](detections/cards/card_05_rule_100203.md) |
| **`100202`** | `T1098.004` (Persistence) | Linux SSH `authorized_keys` Modification | **Saif Asender** | **Mohammad Bustami** | [`card_06_rule_100202.md`](detections/cards/card_06_rule_100202.md) |
| **`100204`** | `T1021.001` (Lateral Movement) | Remote Desktop (`LogonType 10`) from Non-Local IP | **Mohammad Alodeh** | **Mohammad Bustami** | [`card_07_rule_100204.md`](detections/cards/card_07_rule_100204.md) |
| **`100205`** | `T1218.011` (Stealth `TA0005`) | Suspicious `rundll32.exe` Proxy Execution | **Mohammad Alodeh** | **Saif Asender** | [`card_08_rule_100205.md`](detections/cards/card_08_rule_100205.md) |
| **`100206`** | `T1547.001` (Persistence) | Registry `Run` / `RunOnce` Value Set (`Sysmon Event 13`) | **Mohammad Alodeh** | **Mohammad Bustami** | [`card_09_rule_100206.md`](detections/cards/card_09_rule_100206.md) |
| **`100207`** | `T1685.005` (Defense Impairment `TA0112`) | Windows Security (`1102`) or System (`104`) Audit Log Cleared | **Mohammad Bustami** | **Mohammad Alodeh** | [`card_10_rule_100207.md`](detections/cards/card_10_rule_100207.md) |

---

## 2. Triage, Incident Simulation & Part 2 Ownership (Sub-tasks 1.5, 1.6 & Part 2)

Strictly enforces the Sub-task 1.5 separation of duties (Incident A Red-Team Attacker, Incident A Lead Blue-Team Analyst, and Incident B False-Positive Lead Analyst are three distinct team members, and every member triaged at least one ticket):

| Deliverable / Role | Lead Owner | Supporting / Peer Reviewer | File Path |
| :--- | :--- | :--- | :--- |
| **3-VM Lab Build & Log Pipeline (1.1)** | **Mohammad Bustami** & **Saif Asender** | **Mohammad Alodeh** | [`evidence/PIPELINE_PROOF.md`](evidence/PIPELINE_PROOF.md) |
| **Incident A Red-Team Attacker (1.5)** | **Saif Asender** | — | Executed multi-stage chain on `Win10` (`192.168.99.30`) |
| **Incident A Lead Blue-Team Triage & Report (1.5 & 1.6)** | **Mohammad Bustami** | **Mohammad Alodeh** | [`triage/ticket_01_incident_a.md`](triage/ticket_01_incident_a.md) & [`triage/INCIDENT_A_REPORT.md`](triage/INCIDENT_A_REPORT.md) |
| **Incident B False-Positive Triage & Rule Tuning (1.3 & 1.5)** | **Mohammad Alodeh** | **Mohammad Bustami** | [`triage/ticket_02_incident_b_fp.md`](triage/ticket_02_incident_b_fp.md) & [`detections/tuning/TUNING_REPORT.md`](detections/tuning/TUNING_REPORT.md) |
| **Ticket #3 (Linux SSH & Cron Persistence)** | **Mohammad Alodeh** | **Saif Asender** | [`triage/ticket_03_linux_ssh_persistence.md`](triage/ticket_03_linux_ssh_persistence.md) |
| **Ticket #4 (Defense Impairment — Event Log Cleared)** | **Saif Asender** | **Mohammad Bustami** | [`triage/ticket_04_defense_impairment.md`](triage/ticket_04_defense_impairment.md) |
| **Part 2 Readiness Pack (`2.1`–`2.4`)** | **Mohammad Bustami** & **Saif Asender** | **Mohammad Alodeh** | `readiness/01_*` .. `04_*` |
| **Part 2 Readiness Pack (`2.5`–`2.8`)** | **Mohammad Alodeh** & **Mohammad Bustami** | **Saif Asender** | `readiness/05_*` .. `08_*` |
