# Sub-task 2.2 — Severity Classification Matrix & Detection Card Alignment (4 pts)

## 1. Medira Health Systems — SOC Severity Classification Matrix (P1–P4)

| Priority Level | Severity Label | Wazuh Rule Level Mapping | Operational Definition | Triage Acknowledge SLA | Containment Target SLA | Internal Update Cadence | Mandatory Escalation Target | Mapped Capstone Rule IDs |
| :---: | :---: | :---: | :--- | :---: | :---: | :---: | :--- | :--- |
| **P1** | **Critical** | **Level 12 – 15** | Active credential dumping (`lsass.exe`), confirmed brute-force compromise (`4625 -> 4624`), defense impairment (`Event 1102`/`104`), or multi-stage attack chain on crown-jewel hosts. | **≤ 5 minutes** | **≤ 15 minutes** | Every **30 minutes** | Tier-2 IR Lead + SOC Manager + CISO (Immediate phone + Signal) | **`100201`** (Lvl 14)<br/>**`100200`** (Lvl 13)<br/>**`100207`** (Lvl 12) |
| **P2** | **High** | **Level 10 – 11** | High-confidence single-stage attack indicator: encoded PowerShell cradle, brute-force threshold reached (5x `4625`), LOLBin network download, or unauthorized SSH `authorized_keys` write. | **≤ 15 minutes** | **≤ 45 minutes** | Every **2 hours** | On-Call Tier-2 IR Analyst (Slack `#soc-p2-incidents` + ticket) | **`100005`** (Lvl 10)<br/>**`100007`** (Lvl 10)<br/>**`100013`** (Lvl 10)<br/>**`100202`** (Lvl 10) |
| **P3** | **Medium** | **Level 7 – 9** | Suspicious persistence, proxy execution, or lateral movement requiring context verification: `rundll32` proxy, Registry `Run` key modification, Linux `crontab` edit, or non-local RDP (`LogonType 10`). | **≤ 30 minutes** | **≤ 2 hours** | Every **8 hours** (Shift handoff) | Tier-1 Peer Review; escalate to Tier-2 if correlated with P2/P1 | **`100205`** (Lvl 9)<br/>**`100206`** (Lvl 9)<br/>**`100203`** (Lvl 8)<br/>**`100204`** (Lvl 8) |
| **P4** | **Low / Info** | **Level 3 – 6** | Baseline audit telemetry, single failed logons (`60122`), standard process creation (`67027`), or verified benign true positives / tuned false positives (Incident B). | **≤ 4 hours** (or batch review) | N/A (Log & tune) | Weekly tuning review | None (Logged in SIEM for hunting & correlation) | Built-in `60122`, `60106`, `67027`; closed FP tickets |

---

## 2. Dynamic Severity Elevation Rules (Context Multipliers)

1. **Crown-Jewel Host Multiplier (+1 Priority Tier)**: Any **P3** alert firing on `ubuntu-01` (`AST-02`, Patient Portal Server) outside the approved change window (`Tuesday 22:00–23:00 AST`) automatically elevates to **P2**.
2. **Multi-Rule Correlation Multiplier (-> P1)**: Any two or more **P2/P3** rules firing on the same host (`Win10` or `ubuntu-01`) or user (`WIN10\soc`, `kali`) within a **15-minute sliding window** automatically merge into a **P1 Critical Incident** (as demonstrated in **Incident A `SOC-2026-INC-A01`**).

---

## 3. Five Detection Cards Updated with Part 2 Severity & SLA Metadata

To ensure seamless alignment between Part 1 Detection Engineering and Part 2 Incident Readiness, the following **five Detection Cards** in `detections/cards/` were updated to include explicit Medira Health Systems **Priority (P1–P3)**, **Acknowledge/Contain SLAs**, **Assigned Playbook (`PB-01`–`PB-03`)**, and **Escalation Target**:

1. [`detections/cards/card_01_rule_100005.md`](../detections/cards/card_01_rule_100005.md) — **Rule `100005` (`T1059.001` PowerShell Execution)**: Mapped to **P2 High** (Ack ≤ 15m, Contain ≤ 45m, escalates to **P1** if paired with `100013` or `100201`; linked to **Playbook `PB-01`**).
2. [`detections/cards/card_02_rule_100007_100200.md`](../detections/cards/card_02_rule_100007_100200.md) — **Rule `100007` + `100200` (`T1110` Brute Force & Compromise Correlation)**: `100007` mapped to **P2 High** (Ack ≤ 15m); `100200` mapped to **P1 Critical** (Ack ≤ 5m, Contain ≤ 15m; linked to **Playbook `PB-02`**).
3. [`detections/cards/card_03_rule_100201.md`](../detections/cards/card_03_rule_100201.md) — **Rule `100201` (`T1003.001` LSASS Memory Access)**: Mapped to **P1 Critical** (Ack ≤ 5m, Contain ≤ 15m, immediate Tier-2 + SOC Manager phone call; linked to **Playbook `PB-01`**).
4. [`detections/cards/card_06_rule_100202.md`](../detections/cards/card_06_rule_100202.md) — **Rule `100202` (`T1098.004` Linux SSH `authorized_keys` Write)**: Mapped to **P2 High** (Ack ≤ 15m, Contain ≤ 45m on `ubuntu-01`; linked to **Playbook `PB-03`**).
5. [`detections/cards/card_10_rule_100207.md`](../detections/cards/card_10_rule_100207.md) — **Rule `100207` (`T1685.005` Windows Event Log Cleared)**: Mapped to **P1 Critical** (Ack ≤ 5m, Contain ≤ 15m; linked to **Playbook `PB-01`**).

---

## 4. Twelve Medira Health Systems Organization-Specific Severity Examples

| # | Organization-Specific Scenario at Medira Health Systems | Priority | Triggering Rule / Source | Rationale |
| :---: | :--- | :---: | :--- | :--- |
| **1** | Non-system process (`powershell.exe` / `rundll32.exe`) accesses `lsass.exe` memory on clinical billing workstation `Win10`. | **P1** | Rule `100201` (Lvl 14) | Immediate credential-harvesting and ransomware precursor. |
| **2** | 5 failed logons (`4625`) on admin account `WIN10\soc` followed within 5m by a successful logon (`4624`). | **P1** | Rule `100200` (Lvl 13) | Confirmed administrative account takeover via brute force. |
| **3** | Windows `Security` (`1102`) or `System` (`104`) audit log cleared on `Win10` outside maintenance. | **P1** | Rule `100207` (Lvl 12) | Active anti-forensic defense impairment (`TA0112`). |
| **4** | Multi-stage correlation: `Win10` downloads file from `ubuntu-01` (`100013`) and sets Registry `Run` key (`100206`). | **P1** | `100013` + `100206` | Multi-rule correlation rule elevates combined P2+P3 to P1. |
| **5** | Unauthorized write to `/home/kali/.ssh/authorized_keys` on Patient Portal server `ubuntu-01` (`AST-02`). | **P2** | Rule `100202` (Lvl 10) | Backdoor SSH persistence on a critical crown-jewel web server. |
| **6** | PowerShell executed with `-enc` Base64 payload or `Invoke-WebRequest` download cradle on `Win10`. | **P2** | Rule `100005` (Lvl 10) | High-confidence malicious script execution (`T1059.001`). |
| **7** | `bitsadmin.exe`, `certutil.exe`, or `mshta.exe` used to fetch remote payload over HTTP on `Win10`. | **P2** | Rule `100013` (Lvl 10) | Living-off-the-Land ingress tool transfer (`T1105`). |
| **8** | 5 failed logons (`4625`) against `WIN10\soc` in 2 minutes with **no** subsequent successful logon. | **P2** | Rule `100007` (Lvl 10) | Active password brute-force attack in progress (`T1110`). |
| **9** | Non-root user (`uid=1000`) edits scheduled tasks via `/usr/bin/crontab` on `ubuntu-01`. | **P3** (Elevates to **P2** on `AST-02`) | Rule `100203` (Lvl 8) | Unauthorized scheduled job persistence (`T1053.003`). |
| **10** | Remote Desktop (`LogonType 10`) into `Win10` from a non-jump-host internal IP (`192.168.99.1`). | **P3** | Rule `100204` (Lvl 8) | Lateral movement policy violation requiring verification (`T1021.001`). |
| **11** | `rundll32.exe` invoked with `url.dll,FileProtocolHandler` or user-writable path on `Win10`. | **P3** | Rule `100205` (Lvl 9) | Suspicious system binary proxy execution (`T1218.011`). |
| **12** | Windows Defender (`MsMpEng.exe`) or `svchost.exe` queries `lsass.exe` with `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION`). | **P4** | Tuned Exclusion (Incident B) | Verified benign OS/AV background telemetry; logged for tuning only. |

---

## 5. Authority to Declare, Elevate, or Downgrade Incident Severity

| Action | Authorized Role(s) | Mandatory Audit Requirement |
| :--- | :--- | :--- |
| **Declare P1 / P2 / P3 / P4 (Initial Classification)** | Any **Tier-1 SOC Analyst**, **Tier-2 IR Lead**, or **SOC Manager** | Must open ticket immediately and initiate the SLA clock; Tier-1 never needs prior permission to declare a P1. |
| **Elevate Severity (e.g., P3 -> P2 or P2 -> P1)** | Any **Tier-1 SOC Analyst** or **Tier-2 IR Lead** | Automatic upon multi-rule correlation or Crown-Jewel (`AST-02`) involvement. |
| **Downgrade P1 or P2 (e.g., P1 -> P4 False Positive as in Incident B)** | **Tier-2 IR Lead** or **SOC Manager** (Dual sign-off required for P1 downgrade) | Must attach raw log proof (`sourceImage`, `grantedAccess`, hash/path verification) in the ticket before closing or downgrading. |
