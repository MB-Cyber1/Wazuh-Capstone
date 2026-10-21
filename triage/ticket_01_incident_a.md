# Triage Ticket #1 — Incident A (True Positive Multi-Stage Attack Chain on `Win10`)

> **10-Item Triage Checklist Compliance**: All 10 mandatory rubric fields are explicitly populated below using live telemetry from `SOC-Wazuh` (`192.168.99.10`).

---

## 1. Ticket ID, Open Time & Analyst Name
- **Ticket ID**: `SOC-2026-INC-A01`
- **Open Time (UTC)**: `2026-10-19T18:43:45Z` (Updated through `18:55:00Z`)
- **Assigned Analyst**: Mohammad Bustami (Lead Blue-Team Analyst — Incident A) | Peer Reviewed by: Mohammad Alodeh

## 2. Rule ID & Name That Fired
- **Primary Correlation Trigger**: **Rule `100200`** — `SOC-100200 [T1110 CORRELATION]: Successful logon (Event 4624) for soc within 5 minutes of brute-force alert (100007)`
- **Correlated Attack-Chain Rules on `Win10`**:
  - `100007` (Level 10): 5 failed logons (`Event 4625`) for `soc` within 2 minutes (`18:43:36.474Z`)
  - `100200` (Level 13): Successful logon (`Event 4624`) after brute force (`18:43:40.196Z` / `18:47:04.854Z`)
  - `100204` (Level 8): Remote Desktop (`LogonType 10`) lateral movement into `Win10` from `192.168.99.1` (`18:54:54.754Z`)
  - `100005` (Level 10): Suspicious PowerShell execution with `-enc dwBoAG8AYQBtAGkA` (`18:43:30.754Z`)
  - `100013` (Level 10): LOLBin ingress tool transfer via `mshta.exe` and `bitsadmin.exe` from `http://192.168.99.40/index.html` (`18:49:42.921Z`)
  - `100205` (Level 9): Suspicious `rundll32.exe url.dll,FileProtocolHandler calc.exe` proxy execution (`18:43:33.350Z`)
  - `100206` (Level 9): Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\T` persistence set to `calc.exe` (`18:43:34.422Z`)
  - `100201` (Level 14): `powershell.exe` accessed `lsass.exe` process memory with rights `0x1000` (`18:52:15.234Z`)

## 3. Severity (P1–P4) with One-Line Reason
- **Severity**: **P1 — Critical**
- **One-Line Reason**: Confirmed multi-stage compromise of an administrative account (`Win10\soc`) combining successful password brute force (`100200`), encoded payload execution (`100005`), registry persistence (`100206`), and direct LSASS process access (`100201`, Wazuh Level 14).

## 4. Affected Host(s) & User(s)
- **Target Host**: `Win10` (`192.168.99.30`, Wazuh Agent ID `002`, Windows 11 Enterprise Eval Build 26100)
- **Staging / C2 Host**: `ubuntu-01` (`192.168.99.40`, serving HTTP payload at `http://192.168.99.40/index.html`) and lateral source `192.168.99.1`
- **Compromised User Account**: `WIN10\soc` (`SID: S-1-5-21-2093812193-1135278953-2291312261-1000`, Local Administrator, `IntegrityLevel: High`)

## 5. Raw Log Snippet (12 Lines — Live Wazuh `alerts.json`)
```json
{
  "timestamp": "2026-10-19T18:47:04.854+0000",
  "rule": {
    "level": 13,
    "description": "SOC-100200 [T1110 CORRELATION]: Successful logon (Event 4624) for soc within 5 minutes of brute-force alert (100007)",
    "id": "100200",
    "mitre": {
      "id": [
        "T1110",
        "T1078"
      ],
      "tactic": [
        "Credential Access",
        "Defense Evasion",
        "Persistence",
        "Privilege Escalation",
        "Initial Access"
      ],
      "technique": [
        "Brute Force",
        "Valid Accounts"
      ]
    },
    "frequency": 2,
    "firedtimes": 7,
    "mail": true,
    "groups": [
      "local",
      "soc_capstone",
      "credential_access",
      "correlation",
      "compromised_account"
    ]
  },
  "agent": {
    "id": "002",
    "name": "Win10",
    "ip": "192.168.99.30"
  },
  "eventID": "4624",
  "targetUserName": "soc",
  "logonType": "3",
  "followup_lsass_alert": {
    "timestamp": "2026-10-19T18:52:15.234+0000",
    "rule_id": "100201",
    "sourceImage": "C:\\\\WINDOWS\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "targetImage": "C:\\\\WINDOWS\\\\system32\\\\lsass.exe",
    "grantedAccess": "0x1000"
  }
}
```

## 6. IOCs Extracted
| IOC Type | Value | Context |
| :--- | :--- | :--- |
| **Source IP (Lateral / RDP)** | `192.168.99.1` | Source IP for RDP Logon Type 10 (`Rule 100204`) |
| **Staging URL / IP** | `http://192.168.99.40/index.html` (`192.168.99.40`) | Remote payload server contacted by `bitsadmin.exe` and `mshta.exe` (`Rule 100013`) |
| **Command Line (Base64)** | `"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -enc dwBoAG8AYQBtAGkA` | Decodes (UTF-16LE) to `whoami` discovery (`Rule 100005`) |
| **Process SHA-256 (`powershell.exe`)** | `D3B4B97C2BF97D70E5655FF4C4CA1D8CEF9DED51685CFD764247CFDA98EE68DF` | Sysmon Event 1 `Hashes` field on `Win10` |
| **Process SHA-256 (`mshta.exe`)** | `MD5=38966EA123D42A1BC11369032D11ECC1,SHA256=57C402A06BCC5E8756F80C5719A179A5CD229706703D613DA5A5224939BA29E8,IMPHASH=71A59821E6458156CA7792C7A1D58E33` | Sysmon Event 1 `Hashes` field for LOLBin download |
| **Registry Persistence Key** | `HKU\S-1-5-21-2093812193-1135278953-2291312261-1000\Software\Microsoft\Windows\CurrentVersion\Run\T` | Value set to `calc.exe` via `reg.exe` (`Rule 100206`) |
| **Dropped File Path** | `C:\Temp\out2.txt` / `C:\Temp\a.txt` | Target path of `bitsadmin.exe /transfer` |

## 7. MITRE ATT&CK v19 Tactic + Technique ID
- **Credential Access (`TA0006`)**: `T1110` (Brute Force), `T1003.001` (OS Credential Dumping: LSASS Memory)
- **Lateral Movement (`TA0008`)**: `T1021.001` (Remote Services: Remote Desktop Protocol)
- **Execution (`TA0002`)**: `T1059.001` (Command and Scripting Interpreter: PowerShell)
- **Command and Control (`TA0011`)**: `T1105` (Ingress Tool Transfer)
- **Stealth (`TA0005`, ATT&CK v19)**: `T1218.011` (System Binary Proxy Execution: Rundll32)
- **Persistence (`TA0003`)**: `T1547.001` (Boot or Logon Autostart Execution: Registry Run Keys)

## 8. Investigation Notes (What Was Checked & Found)
1. **Authentication Pivot**: Queried `wazuh-alerts-*` for `agent.name:Win10 AND (data.win.system.eventID:4625 OR data.win.system.eventID:4624)` around `18:43:36Z`. Verified 6 consecutive `4625` failures (`SubStatus: 0xc000006a` wrong password) against `WIN10\soc`, triggering `100007`, followed 3.7 seconds later by a successful `4624` logon (`100200`).
2. **Process Lineage (`ProcessGuid`)**: Pivoted on `Win10` Sysmon Event 1 logs. Confirmed the session spawned `powershell.exe -NoProfile -enc dwBoAG8AYQBtAGkA` (`100005`), fetched content from `http://192.168.99.40/index.html` using `bitsadmin.exe` and `mshta.exe` (`100013`), executed `rundll32.exe url.dll,FileProtocolHandler calc.exe` (`100205`), and wrote `HKCU\...\CurrentVersion\Run\T` (`100206`).
3. **Credential Access & Anti-Forensics**: At `18:52:15.234Z`, `powershell.exe` (`PID 8248`) opened a handle (`0x1000`) to `C:\WINDOWS\system32\lsass.exe` (`PID 872`, `Rule 100201`), and 1.2 seconds later executed `wevtutil.exe cl Security`, clearing the Windows Security Event Log (`Event 1102`, `Rule 100207`).

## 9. Verdict + Reason
- **Verdict**: **True Positive (TP)**
- **Reason**: Deterministic correlation across 8 distinct detection rules spanning Brute Force, Lateral Movement, Execution, C2 Tool Transfer, Persistence, Credential Access, and Defense Impairment within a single user session (`WIN10\soc`).

## 10. Action Taken
1. **Immediate Escalation**: Escalated to Tier-2 / Incident Response Lead via the 6-field Escalation Call (`triage/escalation_call_incident_a.md`) within 5 minutes of P1 classification.
2. **Host Containment**: Isolated `Win10` (`192.168.99.30`) using Windows Firewall outbound/inbound containment policy (`triage/containment_and_evidence_preservation.md`), terminated active `mstsc` / suspicious `powershell` and `mshta` processes, removed the `HKCU\...\Run\T` persistence value, and rotated credentials for `WIN10\soc`.
3. **Forensic Preservation**: Exported full Wazuh alert JSONs and calculated SHA-256 cryptographic hashes in `evidence/SHA256SUMS.txt`.
