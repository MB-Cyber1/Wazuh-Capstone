# Sub-task 2.5 — Playbook Dry-Run & External Cold-Test Sheet (6 pts)

## 1. Internal Team Dry-Run Execution Summary

Our squad (**Mohammad Bustami**, **Saif Asender**, and **Mohammad Alodeh**) executed a live timed dry-run of **Playbook `PB-01` (Credential Access & Defense Impairment)**, **Playbook `PB-02` (Brute Force & Lateral Movement)**, and **Playbook `PB-03` (Linux Persistence)** against our live 3-VM lab (`Win10` `192.168.99.30`, `ubuntu-01` `192.168.99.40`, and `SOC-Wazuh` `192.168.99.10`).

| Test Metadata | Details |
| :--- | :--- |
| **Internal Dry-Run Window (UTC)** | `2026-10-19 17:57 UTC – 18:57 UTC` |
| **External Cold-Test Window (UTC)** | `2026-10-20 16:30 UTC – 16:45 UTC` |
| **Playbooks Tested** | `PB-01`, `PB-02`, and `PB-03` |
| **Target Lab Systems** | `Win10` (`192.168.99.30`, Agent `002`) & `ubuntu-01` (`192.168.99.40`, Agent `001`) |
| **Squad Evaluators** | **Mohammad Bustami** (`PB-01`), **Saif Asender** (`PB-03`), **Mohammad Alodeh** (`PB-02`) |

---

## 2. Step-by-Step Playbook Timing & Friction Log (Internal Lab Execution)

| Playbook & Phase | Step Tested | Lead Tester | Target SLA | Actual Time | Verdict | Friction / Gap Discovered During Live Test | Playbook & Rule Improvement Applied |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| **`PB-01` — Identification** (`Rule 100201` LSASS) | Triage Sysmon Event 10 alert on `lsass.exe` and distinguish OS background queries from attack tools. | **Mohammad Bustami** | ≤ 5m | **2m 10s** | **PASS (after fix)** | **Gap #1**: On Windows 11 24H2 (`Build 26100`), `lsass.exe` runs as Protected Process Light (`RunAsPPL`), so non-PPL processes open `lsass.exe` with `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION`). Additionally, `windows_eventchannel` doubles backslashes (`C:\\WINDOWS\\system32\\svchost.exe`), causing `svchost.exe`, `CompatTelRunner.exe`, and `C:\Program Files\Windows Defender\MsMpEng.exe` to trigger 26 false positives. | Updated `Rule 100201` in `local_rules.xml` to use `\+` in PCRE2 and exclude `svchost`, `CompatTelRunner`, and `Program Files\Windows Defender\MsMpEng.exe`. False positives dropped to **0**. |
| **`PB-01` — Identification** (`Rule 100013` LOLBin) | Detect LOLBin HTTP download from `http://192.168.99.40/index.html`. | **Mohammad Bustami** | ≤ 15m | **1m 15s** | **PASS** | **Gap #2**: Windows Defender on Windows 11 24H2 blocks `certutil.exe -urlcache -f http://...` at `CreateProcess` before the binary starts, so adversaries pivot to `bitsadmin.exe /transfer` or `mshta.exe http://...`. | Verified `Rule 100013` covers `certutil`, `bitsadmin`, `mshta`, and `regsvr32`, and updated `PB-01` eradication steps to terminate `mshta.exe` and clear BITS jobs (`bitsadmin /reset /allusers`). |
| **`PB-02` — Detection & Correlation** (`Rules 100007`, `100200`, `100204`) | Detect 5 failed logons (`4625`) -> successful logon (`4624`) and RDP `LogonType 10` (`100204`). | **Mohammad Alodeh** | ≤ 5m | **1m 45s** | **PASS (after fix)** | **Gap #3**: Built-in Wazuh WEF rule `67022` (`0955-WEF-baseline_rules.xml`) and `92651`–`92657` (`0840-win_event_channel.xml`) match `Event 4624` before custom rules if `<if_sid>` only lists `60106`. Also, RDP into an already-active console session reattaches (`LogonType 3` + `Event 4778`) unless the console session is logged off first. | Added `67022,92651,92652,92653,92656,92657` to `<if_sid>` in Rules `100204` and `100200`, and added `Event 4778` + `qwinsta` checks to `PB-02`. |
| **`PB-01` / `PB-02` — Containment** | Isolate `Win10` (`192.168.99.30`) via `New-NetFirewallRule` without severing Wazuh Agent port `1514`. | **Mohammad Bustami** & **Mohammad Alodeh** | ≤ 15m | **3m 20s** | **PASS** | **Gap #4**: A blanket `Set-NetFirewallProfile -DefaultOutboundAction Block` drops Wazuh Agent heartbeats (`192.168.99.10:1514`) and SSH triage (`22`). | Updated `PB-01` containment script to explicitly allow `192.168.99.10` (`TCP 1514` & `22`) before blocking lateral movement (`192.168.99.40`) and RDP (`3389`). |
| **`PB-03` — Identification & Eradication** (`Rules 100202`, `100203`) | Detect and eradicate `authorized_keys` write and rogue `crontab` on `ubuntu-01` (`192.168.99.40`). | **Saif Asender** | ≤ 15m | **2m 05s** | **PASS (after fix)** | **Gap #5**: Neo23x0's default `-w /var/log/audit/ -p rwa` rule caused an infinite feedback loop when `wazuh-logcollector` read `audit.log`, and catch-all `execve` rules masked `/usr/bin/crontab`. | Changed `/var/log/audit/` watch to `-p wa` and placed capstone rules in `/etc/audit/rules.d/10-soc-capstone.rules` ahead of `50-neo23x0.rules`. |

---

## 3. External Student Cold-Test Log Sheet (Sub-task 2.5 — Completed)

> **Graduation Brief Criteria (Sub-task 2.5 — 3 pts)**: A student from another team follows one playbook (`PB-02`) without help from its authors. **Pass criteria**: (1) Correct first containment/triage action reached within **≤ 2× the team's own timed run** (Target: `≤ 3m 30s` for `PB-02`), and (2) Tester asks **at most 2 questions** that the playbook should have answered.

| Cold-Test Field | Recorded Value / Observation |
| :--- | :--- |
| **Playbook Selected for Cold Test** | `PB-02: Brute-Force Attack, Account Takeover & RDP Lateral Movement` (`readiness/04_ir_playbooks.md`) |
| **External Tester Role & Squad** | Peer Bootcamp Analyst — External Squad #2 (Unassisted Cold Run) |
| **Author Team Observers** | **Mohammad Alodeh** (Timekeeper) & **Saif Asender** (Observer) |
| **Author Team Baseline Time to First Action** | **`1m 45s`** (`105 seconds`) |
| **Maximum Allowed Cold-Test Time (2× Baseline)** | **`3m 30s`** (`210 seconds`) |
| **Actual Cold-Tester Time to Correct First Action** | **`2m 38s`** (`158 seconds` — **1.50× baseline**, well under the `3m 30s` limit) |
| **First Action Executed by Cold Tester** | Filtered Wazuh Dashboard for `rule.id:(100007 OR 100200 OR 100204)`, verified `targetUserName: soc` and `ipAddress: 192.168.99.1`, and ran `qwinsta` + `New-NetFirewallRule -DisplayName "SOC-PB02-Block-Source-IP"` on `Win10`. |
| **Question #1 Asked by Cold Tester** | *"When running `logoff <SessionID>` after `qwinsta`, which column in `qwinsta` output is the numeric Session ID?"* |
| **Question #2 Asked by Cold Tester** | *None (Only 1 question asked out of maximum 2 allowed).* |
| **Cold Test Verdict (`PASS` / `FAIL`)** | **PASS** (`2m 38s ≤ 3m 30s` max time, and `1 ≤ 2` max questions) |
| **Playbook Revision Made After Cold Test** | Updated `PB-02` Phase 3 in `readiness/04_ir_playbooks.md` to include sample `qwinsta` output highlighting the numeric `ID` column (`rdp-tcp#0  soc  2  Active`) before `logoff 2`. |
