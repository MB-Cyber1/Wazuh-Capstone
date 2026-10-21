# Sub-task 2.7 — Tabletop Exercise (TTX) Package: "Operation Silent Ward" (6 pts)

## 1. Exercise Overview & Facilitator Guide

- **Exercise Name**: **Operation Silent Ward**
- **Duration**: **45 Minutes** (35 min scenario across 6 injects + 10 min hotwash/AAR)
- **Participants & Roles**:
  1. **Tier-1 SOC Analyst**: Monitors Wazuh Dashboard (`https://192.168.99.10`), performs initial triage, and initiates the 6-field escalation call.
  2. **Tier-2 IR Lead**: Directs host containment, forensic preservation (`SHA256SUMS.txt`), and eradication across `Win10` and `ubuntu-01`.
  3. **IT Infrastructure & Platform Owner**: Executes firewall blocks, session logoffs, and `auditd`/`nginx` remediation on `192.168.99.30` and `192.168.99.40`.
  4. **CISO & Legal/DPO Representative**: Makes business risk decisions (quarantine vs. clinical uptime) and assesses 72-hour regulatory notification triggers.

---

## 2. Six Timed Scenario Injects & Expected Actions

### Inject 1 (T+00:00 — Initial Detection on `ubuntu-01`)
- **Narrative**: At `17:57 UTC`, Wazuh fires **Rule `100202` (Level 10)** on patient portal web server `ubuntu-01` (`192.168.99.40`): `/home/kali/.ssh/authorized_keys` was modified by a non-`sshd` process, followed 98 seconds later by **Rule `100203` (Level 8)**: `/usr/bin/crontab` executed by `uid=1000` (`auid=1000`).
- **Expected Actions**:
  - **Tier-1**: Classify as **P2 High** (elevated by Crown-Jewel Asset `AST-02` rule). Open ticket `SOC-2026-INC-C03` within 15 minutes.
  - **Platform Owner**: Inspect `/home/kali/.ssh/authorized_keys` and `/var/spool/cron/crontabs/soc`, check `audit.auid` (`1000`) and `audit.ses` (`3`), and review `/var/log/nginx/access.log` for web exploit precursors (`Playbook PB-03`).
- **Discussion Prompt**: *Why do we check `audit.auid` instead of only `audit.uid` when `authorized_keys` is modified via `sudo`?*

---

### Inject 2 (T+08:00 — Noise Storm / False Positive Curveball on `Win10`)
- **Narrative**: While Tier-1 is investigating `ubuntu-01`, the Wazuh Dashboard suddenly lights up with **26 Critical Level 14 alerts** for **Rule `100201` (`T1003.001` LSASS Memory Access)** on `Win10` (`192.168.99.30`)! Inspection of the alert JSON shows `sourceImage: "C:\\WINDOWS\\system32\\svchost.exe"` and `"C:\\Program Files\\Windows Defender\\MsMpEng.exe"` with `grantedAccess: "0x1000"`.
- **Expected Actions**:
  - **Tier-1**: Do NOT panic-isolate `Win10` before checking `sourceImage` and `grantedAccess` (`Playbook PB-01` Phase 2). Recognize `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION`) from signed `SYSTEM` binaries (`svchost.exe`, `MsMpEng.exe`) as **False Positive (Incident B)**.
  - **Tier-2**: Patch `local_rules.xml` PCRE2 negative lookahead to handle doubled backslashes (`\+`) and `Program Files\Windows Defender`, reload `wazuh-analysisd`, and document in `TUNING_REPORT.md`.
- **Discussion Prompt**: *What happens to SOC analyst fatigue if a Level 14 rule fires 26 times every 5 minutes on benign OS activity?*

---

### Inject 3 (T+15:00 — Real Brute Force & Account Compromise on `Win10`)
- **Narrative**: Six minutes after tuning `Rule 100201`, `Win10` (`192.168.99.30`) triggers **Rule `100007` (Level 10)**: 5 failed `4625` logons against admin account `WIN10\soc` in 2 minutes. Four seconds later, **Correlation Rule `100200` (Level 13)** fires (`Event 4624` logon success for `soc`), followed by **Rule `100204` (Level 8)**: Remote Desktop (`LogonType 10`) from `192.168.99.1`.
- **Expected Actions**:
  - **Tier-1**: Immediately declare **P1 Critical Incident (`SOC-2026-INC-A01`)** (`Ack <= 5m`). Place the 6-field verbal escalation call to Tier-2 IR Lead.
  - **Infra Lead**: Run `qwinsta` on `Win10`, identify active RDP/console sessions, prepare to force-logoff `soc` and block lateral RDP (`Playbook PB-02`).
- **Discussion Prompt**: *Why is Rule `100200` (Level 13 correlation) treated as an immediate P1 whereas Rule `100007` (Level 10 standalone brute force) is a P2?*

---

### Inject 4 (T+22:00 — Multi-Stage Execution, LOLBin Download & Persistence on `Win10`)
- **Narrative**: Within the compromised `WIN10\soc` session, four more rules fire in rapid succession:
  - **Rule `100005` (Lvl 10)**: `powershell.exe -NoProfile -enc dwBoAG8AYQBtAGkA`
  - **Rule `100013` (Lvl 10)**: `bitsadmin.exe` and `mshta.exe` fetching `http://192.168.99.40/index.html` (connecting `Win10` directly to `ubuntu-01`!)
  - **Rule `100205` (Lvl 9)**: `rundll32.exe url.dll,FileProtocolHandler calc.exe`
  - **Rule `100206` (Lvl 9)**: Registry `SetValue` on `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\T`
- **Expected Actions**:
  - **Tier-2 IR Lead**: Link the `ubuntu-01` staging server (`192.168.99.40`) to the `Win10` intrusion! Execute **Playbook `PB-01` Containment**: block traffic between `192.168.99.30` and `192.168.99.40`, kill `mshta.exe` and `rundll32.exe`, and delete the `HKCU\...\Run\T` value.
- **Discussion Prompt**: *Why must our host quarantine firewall rule on `Win10` explicitly preserve `192.168.99.10:1514`?*

---

### Inject 5 (T+28:00 — LSASS Access & Security Log Wipe Curveball)
- **Narrative**: Just before containment completes, **Rule `100201` (Level 14)** fires again — this time with `sourceImage: "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"` accessing `lsass.exe`! One second later, **Rule `100207` (Level 12)** fires: `Windows Event Log (Security) cleared (Event 1102) on Win10` (`wevtutil cl Security`).
- **Expected Actions**:
  - **Tier-2**: Verify whether `lsass.exe` memory was actually read (`0x1000` limited by Windows 11 `RunAsPPL` vs. `0x1fffff` full dump) and confirm that all prior `Security` events (`4625`, `4624`, `4688`) are already safely stored on `SOC-Wazuh` (`192.168.99.10:/var/ossec/logs/alerts/alerts.json`).
  - **Tier-1 / Tier-2**: Export `alerts_evidence.json` and compute `SHA256SUMS.txt` immediately to lock the chain of custody.

---

### Inject 6 (T+33:00 — Executive & Regulatory Decision Point)
- **Narrative**: The Clinic Medical Director calls the CISO asking if `Win10` (`192.168.99.30`) and the Patient Portal (`ubuntu-01`, `192.168.99.40`) must be shut down completely for 48 hours, and the DPO asks whether a 72-hour PDPL breach notification to SDAIA is required.
- **Expected Actions**:
  - **CISO**: Issue the **Executive P1 Flash Update (Template 1)**. Keep `ubuntu-01` online after removing the SSH key/cron persistence (`PB-03`) and blocking `192.168.99.30 <-> 192.168.99.40` lateral traffic.
  - **DPO**: Document that `RunAsPPL` prevented credential dump and off-host SIEM logs prove zero PHI exfiltration; file internal incident record and prepare precautionary regulatory summary (`Template 3`).

---

## 3. Post-Exercise After-Action Report (AAR) & Action Plan

| Action Item ID | Gap Identified in Exercise | Concrete Remediation Action | Owner | Due Date |
| :--- | :--- | :--- | :--- | :--- |
| **`AAR-01`** | Local admin account `WIN10\soc` had no OS account lockout policy, permitting unlimited `4625` brute-force attempts (`T1110`). | Enforce `net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15` via GPO across all Windows endpoints. | Windows Infra Lead (`Fahad Al-Dossary`) | `2026-10-26` (7 Days) |
| **`AAR-02`** | Workstations (`192.168.99.30`) could initiate direct HTTP requests to server subnet (`192.168.99.40`) using `bitsadmin.exe` and `mshta.exe` (`T1105`). | Deploy Windows Defender ASR / WDAC policy blocking outbound network connections from `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, and `regsvr32.exe`. | Tier-2 IR Lead (`Tariq Al-Harbi`) | `2026-11-02` (14 Days) |
| **`AAR-03`** | Non-admin Linux users (`uid=1000`) on `ubuntu-01` could register scheduled jobs via `/usr/bin/crontab` (`T1053.003`). | Create `/etc/cron.allow` containing only `root` on `ubuntu-01` and set `chattr +i` on `/home/*/.ssh/authorized_keys` where static keys are used. | Linux Platform Owner (`Nadia Siddiqui`) | `2026-10-26` (7 Days) |

---

## 4. Tabletop Exercise Observer Log Sheet (Completed Execution & Decision Timings)

> **Exercise Execution Metadata**: Executed 45-minute tabletop scenario (*"Operation Silent Ward"*) across all 6 injects.
> - **Tier-1 / Tier-2 IR Lead**: **Mohammad Bustami**
> - **Windows & Linux Platform Owner (`Win10` & `ubuntu-01`)**: **Saif Asender**
> - **False-Positive Triage Lead, DPO & Crisis Communications**: **Mohammad Alodeh**
> - **Exercise Facilitator / Management Role & Timekeeper**: Peer Squad Observer (`2026-10-20 17:00–17:45 UTC`)

| Inject # | Inject Time | Scenario Event (Including Curves & Pressure Inject #6) | Lead Responder | Target SLA | Observed Decision Time | Key Decision Made by Team | Gap / Friction Observed & Logged into AAR |
| :---: | :---: | :--- | :--- | :---: | :---: | :--- | :--- |
| **Inject 1** | `T+00:00` | `ubuntu-01` fires Rule `100202` (`authorized_keys`) & Rule `100203` (`crontab`). | **Saif Asender** | `≤ 5 min` | **`3m 10s`** (**PASS**) | Classified as **P2 High** (Crown-Jewel `AST-02`), opened Ticket `SOC-2026-INC-C03`, inspected `audit.auid=1000` (`soc`) and correlated `/var/log/nginx/access.log`. | Logged **`AAR-03`**: non-root users (`uid=1000`) were permitted to run `/usr/bin/crontab` because `/etc/cron.allow` was not restricted to `root`. |
| **Inject 2** *(Curveball #1)* | `T+08:00` | 26 Level-14 alerts (`Rule 100201` LSASS) fire from `svchost.exe` and `MsMpEng.exe` (`0x1000`). | **Mohammad Alodeh** | `≤ 5 min` | **`2m 45s`** (**PASS**) | Identified as **False Positive (`Incident B`)** via `sourceImage` and `0x1000` (`RunAsPPL`); aborted host quarantine and applied PCRE2 `\+` exclusion in `local_rules.xml`. | Confirmed Tier-1 must always check `sourceImage` and `grantedAccess` before isolating a clinical workstation on `Rule 100201`. |
| **Inject 3** | `T+15:00` | Rule `100007` (5x `4625`) -> Rule `100200` (`4624` success) + Rule `100204` (RDP Type 10) on `Win10`. | **Mohammad Bustami** | `≤ 5 min` | **`2m 20s`** (**PASS**) | Declared **P1 Critical (`SOC-2026-INC-A01`)**, delivered the 6-Field Verbal Escalation Call (`triage/escalation_call_incident_a.md`), and ran `qwinsta` on `Win10`. | Logged **`AAR-01`**: local admin `WIN10\soc` had `LockoutThreshold = 0`, allowing unlimited `4625` password guesses. |
| **Inject 4** | `T+22:00` | Rules `100005` (`-enc`), `100013` (`bitsadmin`/`mshta` from `192.168.99.40`), `100205` (`rundll32`), `100206` (`Run` key). | **Mohammad Bustami** & **Saif Asender** | `≤ 5 min` | **`3m 40s`** (**PASS**) | Executed **Playbook `PB-01` Containment**: isolated `Win10` via firewall (explicitly preserving `192.168.99.10:1514`), killed `mshta.exe`, and removed `HKCU\...\Run\T`. | Logged **`AAR-02`**: Windows workstation subnet could fetch HTTP payloads directly from server subnet (`192.168.99.40`) via LOLBins. |
| **Inject 5** *(Curveball #2)* | `T+28:00` | `powershell.exe` accesses `lsass.exe` (`100201`) and clears `Security` event log (`100207`, `Event 1102`). | **Saif Asender** & **Mohammad Bustami** | `≤ 5 min` | **`2m 50s`** (**PASS**) | Verified all pre-wipe events were preserved off-host in `SOC-Wazuh` (`alerts.json`), took VMware snapshot `SOC-Win10-Snapshot1.vmsn`, and recorded SHA-256 hashes (`SHA256SUMS.txt`). | Confirmed off-host real-time forwarding (`0.57s` latency) completely defeated the attacker's `wevtutil cl Security` anti-forensic wipe. |
| **Inject 6** *(Pressure)* | `T+33:00` | **Media & Clinic Director Pressure**: Reporter asks about ransomware rumor while Medical Director demands keeping Patient Portal online. | **Mohammad Alodeh** | `≤ 7 min` | **`4m 15s`** (**PASS**) | Issued CEO/Legal **Media Holding Statement (`Template 5`)** & **Executive Flash (`Template 1`)**; kept `ubuntu-01` portal online after `PB-03` cleanup while keeping `Win10` isolated; documented 72h PDPL assessment. | Verified strict adherence to `06_communication_plan.md` spokesperson policy (zero unapproved technical comments to external press). |
