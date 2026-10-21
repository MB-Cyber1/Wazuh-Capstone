# MITRE ATT&CK v19 Coverage & Telemetry Gap Note (Sub-task 1.3)

## 1. Current Coverage Summary (10 Rules, 7 Tactics in ATT&CK Enterprise v19)

| Rule ID | Technique ID (v19) | Tactic (v19) | Platform | Log Source |
|---|---|---|---|---|
| 100005 | T1059.001 PowerShell | Execution (TA0002) | Windows | Sysmon Event 1 |
| 100007 + 100200 | T1110 Brute Force (Correlation) | Credential Access (TA0006) | Windows | Security 4625 -> 4624 |
| 100201 | T1003.001 LSASS Memory | Credential Access (TA0006) | Windows | Sysmon Event 10 |
| 100013 | T1105 Ingress Tool Transfer | Command & Control (TA0011) | Windows | Sysmon Event 1 |
| 100203 | T1053.003 Cron | Persistence (TA0003) | Linux | auditd SYSCALL/EXECVE |
| 100202 | T1098.004 SSH Authorized Keys | Persistence (TA0003) | Linux | auditd file watch |
| 100204 | T1021.001 Remote Desktop Protocol | Lateral Movement (TA0008) | Windows | Security 4624 (Type 10) |
| 100205 | T1218.011 Rundll32 | Stealth (TA0005) | Windows | Sysmon Event 1 |
| 100206 | T1547.001 Registry Run Keys | Persistence (TA0003) | Windows | Sysmon Event 13 |
| 100207 | T1685.005 Clear Windows Event Logs | Defense Impairment (TA0112) | Windows | Security 1102 / System 104 |

> **Note on ATT&CK Enterprise v19 (April 2026):** MITRE retired and split *Defense Evasion* into **Stealth (TA0005)** (blending into normal activity while leaving controls intact, e.g., `T1218.011`) and **Defense Impairment (TA0112)** (actively breaking or clearing security controls/logs, e.g., `T1685.005`). Our layer reflects this v19 taxonomy.

---

## 2. Three Techniques We Cannot Yet Detect and Why (Gap Analysis)

1. **T1558.003 — Steal or Forged Kerberos Tickets: Kerberoasting (Credential Access)**
   - **Why we cannot detect it yet:** Detecting Kerberoasting requires Windows Active Directory Domain Controller Kerberos Service Ticket Operations auditing (**Security Event ID 4769** with `TicketEncryptionType = 0x17` RC4-HMAC and non-machine `ServiceName`). In our baseline Part 1 lab, `Win10` operates as a standalone workstation without Kerberos KDC telemetry enabled or forwarded from a Domain Controller.
   - **Remediation plan:** Promote `DC01`, enable Advanced Audit Policy `Audit Kerberos Service Ticket Operations (Success/Failure)`, and deploy a Wazuh rule matching Event 4769 where `ticketEncryptionType = 0x17`.

2. **T1071.004 — Application Layer Protocol: DNS Tunneling / C2 (Command and Control)**
   - **Why we cannot detect it yet:** While Sysmon Event ID 22 logs local process DNS queries on `Win10`, our Linux server (`ubuntu-01`) and network perimeter do not yet forward full DNS resolver query/response telemetry (query length, subdomain entropy, TXT/NULL record volume) to Wazuh.
   - **Remediation plan:** Enable `Sysmon Event 22 (DnsQuery)` rules on Windows and deploy `zeek` or `dnsmasq`/`bind9` query logging on the lab gateway.

3. **T1055.001 / T1055.012 — Process Hollowing & In-Memory Reflective DLL Injection (Stealth)**
   - **Why we cannot detect it yet:** Sysmon Event ID 8 (`CreateRemoteThread`) only catches classic remote-thread injection. Process hollowing (`NtUnmapViewOfSection`) and direct syscalls bypass user-mode hooks and do not emit standard Sysmon Event 1 or Event 8 records unless kernel ETW (`Microsoft-Windows-Threat-Intelligence`) is consumed by an EDR agent.
   - **Remediation plan:** Enable Sysmon Event ID 25 (`ProcessTampering`) in `sysmonconfig.xml` and add a Wazuh child rule under `sysmon_event_25`.
