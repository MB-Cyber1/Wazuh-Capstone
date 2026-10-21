# Sub-task 1.6 — 8-Minute Live Demo & Viva Script

> **Goal**: Walk the instructor/evaluators through the live 3-VM SOC lab, fire real detections on `Win10` and `ubuntu-01`, show the custom 6-panel Wazuh Dashboard updating in real time, and walk through Incident A triage in **8 minutes sharp**.

---

## Pre-Demo Checklist (30 Seconds Before Starting)
1. Open browser tab to **`https://192.168.99.10/app/dashboards#/view/soc-capstone-tier1-dashboard`** (`admin` / `SecretPassword`) and set the time picker to **Last 24 hours** (or **Last 15 minutes**).
2. Open a terminal in `C:\Users\moh-b\Downloads\soc-capstone`.
3. Verify all 3 VMs and both agents are `Active`:
   ```powershell
   ssh -i C:\Users\moh-b\.ssh\soclab_ed25519 soc@192.168.99.10 "sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
   ```

---

## Minute-by-Minute Live Demo Runbook (8:00 Total)

### Minute 0:00 – 1:30 | Lab Architecture & 3 Log Sources Proof (Sub-task 1.1)
- **Show**: Terminal output of `agent_control -l` (`000 wazuh.manager`, `001 ubuntu-01 Active`, `002 Win10 Active`) and [`PIPELINE_PROOF.md`](../evidence/PIPELINE_PROOF.md).
- **Say**: *"Our lab runs on an isolated `192.168.99.0/24` Host-Only network (`VMnet1`) with three VMs: `SOC-Wazuh` (`192.168.99.10`) running the Wazuh v4.14.9 Docker stack, `ubuntu-01` (`192.168.99.40`) forwarding `auditd` (with Neo23x0 + custom rules) and `nginx` web logs, and `Win10` (`192.168.99.30`) forwarding Windows Security, System, PowerShell 4104, and Sysmon v15.15 (`SwiftOnSecurity` + LSASS Event 10). Measured ingestion latency across all three sources is **0.45 to 0.83 seconds**."*

### Minute 1:30 – 3:30 | Rule Pack, Sigma Validation & ATT&CK v19 Mapping (Sub-tasks 1.2 & 1.3)
- **Show**:
  1. Run Sigma CLI validation live:
     ```powershell
     C:\Users\moh-b\AppData\Local\Python\pythoncore-3.14-64\Scripts\sigma.exe check detections\sigma\
     ```
  2. Open [`local_rules.xml`](../detections/wazuh/local_rules.xml) and [`attack_navigator_v19.json`](../detections/navigator/attack_navigator_v19.json).
- **Say**: *"All 10 rules from our Detection Rule Pack (`100005` through `100207`, plus correlation rule `100200`) are authored in Sigma v2 (0 validation errors) and hand-translated to Wazuh XML (`wazuh-analysisd -t` returns 0 errors). Note that in **MITRE ATT&CK Enterprise v19**, legacy Defense Evasion split into **Stealth (`TA0005`, Rule `100205` `rundll32`)** and **Defense Impairment (`TA0112`, Rule `100207` `Event 1102`)**. During tuning, we resolved a real false positive on Rule `100201` where `windows_eventchannel` doubled backslashes caused `svchost.exe` and Windows Defender (`MsMpEng.exe`) `0x1000` queries on `lsass.exe` to fire."*

### Minute 3:30 – 5:30 | Live Attack Execution & Real-Time SIEM Detection
- **Run Live**: Trigger Linux SSH `authorized_keys` modification (`100202`) + Windows encoded PowerShell (`100005`) + Registry Run Key (`100206`) live:
  ```powershell
  ssh -i C:\Users\moh-b\.ssh\soclab_ed25519 soc@192.168.99.40 "sudo sh -c 'echo ssh-rsa AAAA demo >> /home/kali/.ssh/authorized_keys && truncate -s 0 /home/kali/.ssh/authorized_keys'"
  ```
- **Switch to Browser**: Click **Refresh** on **`SOC Capstone — Tier-1 Analyst Triage Dashboard`**.
- **Point Out All 6 Panels (Sub-task 1.4)**:
  1. **Panel 1**: Alert count over time stacked by `rule.level` (`8`, `9`, `10`, `12`, `13`, `14`).
  2. **Panel 2**: Top Detection Rules Fired table showing all 11 rule IDs (`100005`–`100207`).
  3. **Panel 3**: Top Targeted Hosts (`Win10`, `ubuntu-01`) and Users (`soc`, `kali`).
  4. **Panel 4**: Failed (`4625`) vs. Successful (`4624`) logons over time showing the brute-force spike followed by login success.
  5. **Panel 5**: High-Severity Triage Stream (`rule.level >= 8`) with `commandLine` and `targetUserName`.
  6. **Panel 6**: MITRE ATT&CK v19 Technique Donut Chart.

### Minute 5:30 – 7:00 | Triage Tickets, Incident A Chain & False Positive Tuning (Sub-task 1.5 & 1.6)
- **Show**: [`ticket_01_incident_a.md`](../triage/ticket_01_incident_a.md), [`ticket_02_incident_b_fp.md`](../triage/ticket_02_incident_b_fp.md), and [`INCIDENT_A_REPORT.md`](../triage/INCIDENT_A_REPORT.md).
- **Say**: *"In Incident A (`SOC-2026-INC-A01`), we correlated 8 alerts into a single P1 kill chain: 5 failed logons (`100007`) -> successful login (`100200`) & RDP (`100204`) -> encoded PowerShell (`100005`) -> LOLBin staging from `192.168.99.40` (`100013`) -> `rundll32` proxy (`100205`) -> Registry Run persistence (`100206`) -> LSASS access (`100201`) -> clearing the Security log (`100207`). Even though the attacker wiped `Security.evtx` locally, Wazuh had already ingested the entire chain in `< 0.6s`. We contained `Win10`, removed persistence, escalated via our 6-field call script, and preserved SHA-256 hashes in `evidence/SHA256SUMS.txt`."*

### Minute 7:00 – 8:00 | Part 2 Incident Readiness Pack Tie-In (Sub-tasks 2.1 – 2.8)
- **Show**: `readiness/` directory (`01_org_profile_and_risk_register.md` through `08_executive_briefing.md`).
- **Say**: *"Finally, in Part 2 we built a complete Incident Readiness Pack for **Medira Health Systems** mapped directly to these exact lab hosts (`Win10`, `ubuntu-01`, `SOC-Wazuh`) and rule IDs (`100005`–`100207`), including our 3 IR Playbooks (Ransomware/LSASS, Brute-Force/Account Compromise, and Linux Web Server Persistence), Playbook Dry-Run Test Sheet, Escalation Tree, Communication Plan, 6-Inject Tabletop Exercise, and Board Executive Briefing."*
