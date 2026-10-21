# Sub-task 1.5 — Host Containment & Forensic Evidence Preservation

## 1. Host Containment Procedure Executed on `Win10` (`192.168.99.30`)

During Incident A (`SOC-2026-INC-A01`), Tier-1 contained `Win10` (`192.168.99.30`) while keeping the Wazuh Agent (`192.168.99.10:1514/tcp`) and SOC management SSH (`192.168.99.10 -> 192.168.99.30:22`) alive for forensic collection:

```powershell
# 1. Remove Registry Run key persistence artifact (Rule 100206)
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "T" -ErrorAction SilentlyContinue

# 2. Terminate suspicious LOLBin / proxy children (Rules 100013, 100205)
Get-Process mshta,CalculatorApp,calc -ErrorAction SilentlyContinue | Stop-Process -Force

# 3. Remove staged payload files in C:\Temp (Rule 100013)
Remove-Item -Path "C:\Temp\a.txt","C:\Temp\out.txt","C:\Temp\out2.txt" -Force -ErrorAction SilentlyContinue

# 4. Quarantine host network (allow Wazuh Manager 192.168.99.10, block lateral movement to/from 192.168.99.40)
New-NetFirewallRule -DisplayName "SOC-Quarantine-Block-Lateral-Out" -Direction Outbound -RemoteAddress 192.168.99.40 -Action Block
New-NetFirewallRule -DisplayName "SOC-Quarantine-Block-RDP-In" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
```

---

## 2. Evidence Preservation, VM Snapshot & Chain-of-Custody Hashing (`SHA-256`)

All SIEM alert evidence, rule files, pipeline proofs, and the live VMware forensic snapshot + memory image of `SOC-Win10` (`Incident_A_Forensic_Snapshot`) were preserved and hashed with SHA-256 in [`evidence/SHA256SUMS.txt`](../evidence/SHA256SUMS.txt):

| Preserved Forensic Artifact | File Path / Location | Size | SHA-256 Hash |
| :--- | :--- | :--- | :--- |
| **VMware Forensic State Snapshot (`.vmsn`)** | `SOC-Win10\SOC-Win10-Snapshot1.vmsn` | `135,744,786 B` | `e7174f020f1aeb92b7006b8a9cbe52b61dc57bef2530f69202ae1701bc5e7838` |
| **VMware Snapshot Descriptor (`.vmsd`)** | `SOC-Win10\SOC-Win10.vmsd` | `457 B` | `a25632686bc6c471830a04b2bea83544dd9526633418517295837adc8d42c73a` |
| **VMware Full Memory Image (`.vmem`)** | `SOC-Win10\SOC-Win10-Snapshot1.vmem` | `4,294,967,296 B (4.0 GB)` | Preserved on host storage alongside `.vmsn` |
| **Raw Fired SIEM Alerts JSON** | [`evidence/alerts_evidence.json`](../evidence/alerts_evidence.json) | `55,021 B` | `8d9bc9fd66c5182cb28056db43c414677b16a43e1278941e74be550bb70d88b5` |
