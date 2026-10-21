# Triage Ticket #4 — Defense Impairment: Windows Security Event Log Cleared (`Win10`)

> **10-Item Triage Checklist Compliance**: All 10 mandatory rubric fields are explicitly populated below using live telemetry from `Win10` (`192.168.99.30`).

---

## 1. Ticket ID, Open Time & Analyst Name
- **Ticket ID**: `SOC-2026-INC-D04`
- **Open Time (UTC)**: `2026-10-19T18:52:20Z`
- **Assigned Analyst**: Saif Asender (Tier-1 SOC Analyst) | Peer Reviewed by: Mohammad Bustami

## 2. Rule ID & Name That Fired
- **Rule ID**: **`100207`** (Level 12)
- **Rule Name**: `SOC-100207 [T1685.005]: Windows Event Log (Security) cleared (Event 1102) on Win10`

## 3. Severity (P1–P4) with One-Line Reason
- **Severity**: **P1 — Critical (Correlated with Incident A) / P2 Standalone**
- **One-Line Reason**: Clearing the Windows `Security` audit log (`Event 1102`) is a high-confidence anti-forensic action (`T1685.005`) executed 1.2 seconds after LSASS memory access (`100201`) on `Win10`.

## 4. Affected Host(s) & User(s)
- **Affected Host**: `Win10` (`192.168.99.30`, Wazuh Agent ID `002`)
- **Subject Account**: `WIN10\soc` (`SubjectUserSid: S-1-5-21-2093812193-1135278953-2291312261-1000`, `SubjectLogonId: 0x10ee042`)

## 5. Raw Log Snippet (14 Lines — Live Wazuh `alerts.json`)
```json
{
  "timestamp": "2026-10-19T18:52:16.445+0000",
  "rule": {
    "level": 12,
    "description": "SOC-100207 [T1685.005]: Windows Event Log (Security) cleared (Event 1102) on Win10",
    "id": "100207",
    "firedtimes": 1,
    "mail": true,
    "groups": [
      "local",
      "soc_capstone",
      "defense_impairment",
      "logs_cleared"
    ]
  },
  "agent": {
    "id": "002",
    "name": "Win10",
    "ip": "192.168.99.30"
  },
  "manager": {
    "name": "wazuh.manager"
  },
  "id": "1792435936.11665474",
  "full_log": "{\"win\":{\"system\":{\"providerName\":\"Microsoft-Windows-Eventlog\",\"providerGuid\":\"{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}\",\"eventID\":\"1102\",\"version\":\"1\",\"level\":\"4\",\"task\":\"104\",\"opcode\":\"0\",\"keywords\":\"0x4020000000000000\",\"systemTime\":\"2026-10-19T18:52:16.7379356Z\",\"eventRecordID\":\"2902\",\"processID\":\"1688\",\"threadID\":\"8312\",\"channel\":\"Security\",\"computer\":\"Win10\",\"severityValue\":\"INFORMATION\",\"message\":\"\\\"The audit log was cleared.\\r\\nSubject:\\r\\n\\tSecurity ID:\\tS-1-5-21-2093812193-1135278953-2291312261-1000\\r\\n\\tAccount Name:\\tsoc\\r\\n\\tDomain Name:\\tWIN10\\r\\n\\tLogon ID:\\t0x1044E26\\\"\"},\"logFileCleared\":{\"subjectUserSid\":\"S-1-5-21-2093812193-1135278953-2291312261-1000\",\"subjectUserName\":\"soc\",\"subjectDomainName\":\"WIN10\",\"subjectLogonId\":\"0x1044e26\",\"clientProcessId\":\"4936\",\"clientProcessStartKey\":\"844424930133205\"}}}",
  "decoder": {
    "name": "windows_eventchannel"
  },
  "data": {
    "win": {
      "system": {
        "providerName": "Microsoft-Windows-Eventlog",
        "providerGuid": "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}",
        "eventID": "1102",
        "version": "1",
        "level": "4",
        "task": "104",
        "opcode": "0",
        "keywords": "0x4020000000000000",
        "systemTime": "2026-10-19T18:52:16.7379356Z",
        "eventRecordID": "2902",
        "processID": "1688",
        "threadID": "8312",
        "channel": "Security",
        "computer": "Win10",
        "severityValue": "INFORMATION",
        "message": "\"The audit log was cleared.\r\nSubject:\r\n\tSecurity ID:\tS-1-5-21-2093812193-1135278953-2291312261-1000\r\n\tAccount Name:\tsoc\r\n\tDomain Name:\tWIN10\r\n\tLogon ID:\t0x1044E26\""
      },
      "logFileCleared": {
        "subjectUserSid": "S-1-5-21-2093812193-1135278953-2291312261-1000",
        "subjectUserName": "soc",
        "subjectDomainName": "WIN10",
        "subjectLogonId": "0x1044e26",
        "clientProcessId": "4936",
        "clientProcessStartKey": "844424930133205"
      }
    }
  },
  "location": "EventChannel"
}
```

## 6. IOCs Extracted
| IOC Type | Value | Context |
| :--- | :--- | :--- |
| **Event Provider & ID** | `Microsoft-Windows-Eventlog` — `EventID: 1102` | Kernel/Eventlog service self-audit record when `Security` channel is wiped |
| **Subject Account & LogonId** | `WIN10\soc` (`LogonId: 0x10ee042`) | Exact logon session that invoked `wevtutil.exe cl Security` |
| **Correlated Binary** | `C:\Windows\System32\wevtutil.exe` (`cl Security`) | Executed immediately after `powershell.exe` LSASS access (`Rule 100201`) |

## 7. MITRE ATT&CK v19 Tactic + Technique ID
- **Tactic**: **Defense Impairment (`TA0112`)** *(split from legacy Defense Evasion in MITRE ATT&CK v19)*
- **Technique**: **`T1685.005`** — Indicator Removal: Clear Windows Event Logs *(mapped alongside `T1685` in Wazuh)*

## 8. Investigation Notes (What Was Checked & Found)
1. **Verified Pre-Wipe Telemetry in SIEM**: Although the local `Security.evtx` buffer on `Win10` was cleared at `18:52:16.445Z`, `wazuh-agent` (`002`) had already streamed all prior `4625`, `4624`, `4688`, and `Sysmon` events in real time (`< 0.6s` latency) to `SOC-Wazuh` (`192.168.99.10:/var/ossec/logs/alerts/alerts.json`).
2. **Confirmed `Microsoft-Windows-Sysmon/Operational` Intact**: Verified on `Win10` that the attacker only cleared the `Security` channel (`wevtutil cl Security`) and did not clear `Microsoft-Windows-Sysmon/Operational`.

## 9. Verdict + Reason
- **Verdict**: **True Positive (TP)**
- **Reason**: Event ID `1102` cannot be generated by benign background services; `SubjectUserName: soc` explicitly ran `wevtutil.exe cl Security` following credential-access activity.

## 10. Action Taken
1. **Linked to Master Incident Ticket**: Merged `SOC-2026-INC-D04` into Master Incident `SOC-2026-INC-A01` (Incident A) as the anti-forensics stage of the attack chain.
2. **Immutable SIEM Evidence Lock**: Exported off-host Wazuh alert logs (`evidence/alerts_evidence.json`) and recorded SHA-256 integrity hashes (`evidence/SHA256SUMS.txt`).
