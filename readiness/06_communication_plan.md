# Sub-task 2.6 — Crisis & Incident Communication Plan (4 pts)

## 1. Stakeholder Communication Matrix

| Audience / Stakeholder | Trigger Condition | Timing / SLA | Primary Channel | Out-of-Band (OOB) Channel | Sender / Owner | Approval Authority |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| **SOC & IR Technical Team (`Tier-1`, `Tier-2`, `Infra`)** | Any **P1** or **P2** incident opened | **≤ 5 min** (P1)<br/>**≤ 15 min** (P2) | Voice Call + Slack `#soc-ir-warroom` | Signal Group `Medira-IR-Ops` | Tier-1 SOC Analyst | Tier-2 IR Lead |
| **CISO & Executive Leadership (`CEO`, `COO`, `Medical Director`)** | Any confirmed **P1** incident (`SOC-2026-INC-A01`) or clinical portal outage | **≤ 15 min** (CISO)<br/>**≤ 60 min** (Execs) | Direct Phone Briefing + Written Flash Update | Signal Direct + Printed Brief | CISO (`Dr. Layla Al-Mansoor`) | CISO |
| **Internal Employees & Clinical Staff** | Password reset mandate, workstation quarantine, or portal maintenance window | **≤ 2 hours** from containment | Internal Email (`security-alerts@medira.health`) + Intranet Banner | SMS Broadcast (`Medira-Staff-Notify`) | IT Service Desk + SOC Manager | CISO + HR/Ops |
| **Regulators (`SDAIA / PDPL`, `NCA`, `MOH`) & Affected Patients** | Confirmed unauthorized access/exfiltration of PHI/PII | **≤ 72 hours** (PDPL statutory deadline; **≤ 24h** NCA critical notice) | Official Regulatory Portal + Registered Notice | Legal Counsel Direct Filing | General Counsel & DPO (`Khalid Al-Sudairi`) | CEO + General Counsel + CISO |

---

## 2. Five Ready-to-Send Crisis Communication Templates

### Template 1: Executive / Board P1 Flash Update (Internal — Confidential)
```text
SUBJECT: [P1 SECURITY FLASH - CONTAINED] Incident SOC-2026-INC-A01 on Workstation Win10 (192.168.99.30)
TO: Chief Executive Officer, Chief Operating Officer, General Counsel/DPO
FROM: Dr. Layla Al-Mansoor (CISO) & Majed Al-Otaibi (SOC Manager)
TIME: 2026-10-19 19:10 UTC (Classification: CONFIDENTIAL - INTERNAL)

1. WHAT HAPPENED:
Between 18:43 UTC and 18:54 UTC today, our Wazuh SIEM detected a multi-stage intrusion on clinical administrative workstation Win10 (192.168.99.30). An attacker guessed the password of local admin account WIN10\soc (Rules 100007/100200), connected via Remote Desktop (Rule 100204), executed encoded PowerShell and staging commands (Rules 100005/100013/100205), added a Registry startup entry (Rule 100206), attempted to read LSASS credential memory (Rule 100201), and cleared the local Windows Security log (Rule 100207).

2. CURRENT STATUS & CLINICAL IMPACT:
- CONTAINED: Host Win10 (192.168.99.30) was isolated within 12 minutes of initial detection.
- ZERO DATA LOSS CONFIRMED: Windows 11 Protected Process Light (RunAsPPL) blocked full LSASS memory extraction, and 100% of endpoint logs were already streamed to SOC-Wazuh (192.168.99.10) before the local log was cleared.
- CLINICAL OPERATIONS: Patient diagnostic imaging and the Patient Portal remain 100% operational.

3. NEXT STEPS (NEXT 4 HOURS):
- Complete mandatory credential rotation and enforce 5-attempt account lockout policy across all workstations.
- Next Executive Update scheduled for 21:00 UTC.
```

---

### Template 2: Internal Staff & IT Security Advisory
```text
SUBJECT: [ACTION REQUIRED] Mandatory Admin Credential Rotation & RDP Hardening Notice
TO: Medira Health Systems IT & Clinical Administration Staff
FROM: Medira SOC & IT Security Team
DATE: 2026-10-19

Team,

Our Security Operations Center (SOC) detected and contained unauthorized sign-in activity targeting administrative workstation Win10 (192.168.99.30). As a precautionary measure:
1. Workstation Win10 (192.168.99.30) has been temporarily isolated for security maintenance.
2. All administrative accounts in the 192.168.99.0/24 segment must rotate passwords immediately and enable Multi-Factor Authentication (MFA).
3. Direct Remote Desktop (RDP port 3389) from non-jump-host workstations is now blocked by policy.

If you observe any unexpected login prompts or lockouts, contact the 24/7 SOC Desk immediately at ext. 4100 or soc-t1@medira.health.
```

---

### Template 3: External Regulatory / Data Protection Authority Notification (PDPL / HIPAA 72-Hour Notice)
```text
OFFICIAL NOTIFICATION OF CYBERSECURITY INCIDENT (SAUDI PDPL ART. 20 / NCA ECC)
Reporting Entity: Medira Health Systems (CR #1010998877)
Incident Reference: SOC-2026-INC-A01
Date/Time of Detection: 19 October 2026, 18:43:30 UTC
Date/Time of Containment: 19 October 2026, 18:55:30 UTC
Point of Contact: Khalid Al-Sudairi, Data Protection Officer (dpo@medira.health | +966-50-555-0108)

1. Summary of Incident:
On 19 October 2026 at 18:43 UTC, Medira Health Systems' Security Operations Center detected unauthorized administrative access to workstation Win10 (192.168.99.30) following a password brute-force attack (MITRE ATT&CK T1110), followed by persistence and credential-access attempts (T1003.001, T1685.005).

2. Personal Data & Systems Assessment:
Forensic analysis of off-host SIEM telemetry (preserved with SHA-256 chain of custody) confirms the host was isolated within 12 minutes. OS-level credential protection (RunAsPPL) prevented credential harvesting, and no patient health records (PHI/PII) were exfiltrated.

3. Corrective & Preventive Actions Taken:
- Immediate network quarantine of affected endpoint and eradication of persistence artifacts.
- Credential rotation, enforcement of 5-attempt account lockout policies, and restriction of internal RDP/HTTP LOLBin utilities.
```

---

### Template 4: Customer / Patient Notification Template (If Patient Portal or PHI Affected)
```text
SUBJECT: Important Security Notice From Medira Health Systems
FROM: Medira Health Systems Patient Privacy Office (privacy@medira.health)

Dear Valued Patient,

We are writing to inform you of a recent cybersecurity event identified by our Security Operations Center on 19 October 2026 involving an internal administrative workstation. Our security team detected and isolated the affected system within 12 minutes.

What Information Was Involved:
Our forensic investigation confirmed that no medical imaging records, diagnostic results, or personal identification numbers were accessed or downloaded.

What We Are Doing & What You Can Do:
We have rotated administrative credentials, strengthened multi-factor authentication across our clinic network, and notified the relevant authorities in accordance with the Saudi Personal Data Protection Law (PDPL). As a best practice, we encourage you to use a unique password for your Medira Patient Portal account. For questions, please call our dedicated toll-free line at 800-555-0199.
```

---

### Template 5: External Media / Press Holding Statement (Approved by CEO & General Counsel)
```text
FOR IMMEDIATE RELEASE — MEDIRA HEALTH SYSTEMS MEDIA STATEMENT
Spokesperson: Office of the Chief Executive Officer & Corporate Communications (media@medira.health)

"On 19 October 2026, Medira Health Systems' 24/7 Security Operations Center detected unauthorized activity on a single administrative workstation and contained the system within 12 minutes using our automated incident response protocols. All clinical imaging services and the Medira Patient Portal remain fully operational. Forensic verification confirms no patient medical records were exfiltrated. No further technical details will be shared while our post-incident review concludes."
```
