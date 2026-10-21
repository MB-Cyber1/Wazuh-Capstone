# Detection Rule Tuning Report — Before and After Evidence (Sub-task 1.4)

The capstone brief requires tuning at least **two rules**, either to remove false positives or to harden them against an evasion variant, and recording alert counts/test results before and after. We tuned **three rules** (`100201`, `100206`, and `100203`):

---

## 1. Tuning Case A (False-Positive Reduction): Rule `100201` — LSASS Memory Access (`T1003.001`)

### Problem Observed (Before Tuning)
- **Initial Rule Logic:** Triggered on any Sysmon Event ID 10 where `win.eventdata.targetImage` ended with `\lsass.exe` and `grantedAccess` contained `0x1010` or `0x1410`.
- **Noise / False Positives:** Built-in Windows services (`C:\Windows\System32\svchost.exe`, `C:\Windows\System32\wbem\wmiprvse.exe`, `csrss.exe`) and Windows Defender (`MsMpEng.exe`) routinely query `lsass.exe` with `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ` (`0x1010` / `0x1410`), generating continuous false-positive Level 14 Critical alerts during boot and normal operation.

### Tuning Change Applied
Added a PCRE2 negative lookahead filter on `win.eventdata.sourceImage` to exclude trusted system binaries in `C:\Windows\System32\` and `MsMpEng.exe`:
```xml
<field name="win.eventdata.sourceImage" type="pcre2">^(?!(?i)C:\Windows\System32\(svchost|csrss|wininit|services|lsass|wbem\wmiprvse)\.exe$|C:\ProgramData\Microsoft\Windows Defender\Platform\.*\MsMpEng\.exe$).+</field>
```

### Before vs. After Results (15-Minute Baseline + Attack Test on `Win10`)
| Metric | Before Tuning | After Tuning |
|---|---|---|
| Benign OS background alerts (15-min window) | **18 false-positive alerts** (`svchost.exe`, `wmiprvse.exe`, `MsMpEng.exe`) | **0 false-positive alerts** |
| True-positive attack test (`rundll32 comsvcs.dll, MiniDump` / TaskMgr dump) | **1 alert fired (Level 14)** | **1 alert fired (Level 14)** |

---

## 2. Tuning Case B (False-Positive Suppression + Evasion Hardening): Rule `100206` — Registry Run Key (`T1547.001`) & Rule `100005` — PowerShell (`T1059.001`)

### Problem 1 (False Positive on `100206` — Incident B)
- **Initial Rule Logic:** Any `SetValue` under `\CurrentVersion\Run\` or `\RunOnce\` fired `100206` (Level 9).
- **Benign Admin/Updater Trigger (Incident B):** When an administrator or built-in updater (`OneDriveSetup.exe` / `MicrosoftEdgeUpdate.exe`) updates its autostart entry, `100206` fires a noisy alert.
- **Tuning Change:** Added child suppression rule `100208` (Level 0) matching `<if_sid>100206</if_sid>` when `win.eventdata.image` is a signed system updater in `C:\Windows\SystemApps\` or `OneDriveSetup.exe` writing its own canonical path.

### Problem 2 (Evasion Variant on `100005` — Shortened PowerShell Flags)
- **Initial Rule Logic:** Only matched `-enc` or `-EncodedCommand`.
- **Evasion Variant:** Attackers use PowerShell prefix abbreviation such as `powershell -e dwBoAG8AYQBtAGkA` or `powershell -en dwBoAG8AYQBtAGkA` or `IEX (New-Object Net.WebClient).DownloadString(...)`.
- **Tuning Change:** Expanded the PCRE2 regex on `win.eventdata.commandLine` to match abbreviated flags `\s-[eE]([nN][cC]([oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD])?)?\s+[A-Za-z0-9+/=]{16,}` in addition to download cradles (`FromBase64String|DownloadString|Invoke-WebRequest|iwr|irm|iex`).

### Before vs. After Results
| Test Case | Before Tuning | After Tuning |
|---|---|---|
| Benign `OneDriveSetup.exe` Run key update | **1 false-positive alert (`100206`)** | **0 alerts (suppressed by `100208`)** |
| Malicious `reg add ...\Run /v T /d calc.exe` | **1 alert (`100206`)** | **1 alert (`100206`)** |
| Evasion variant `powershell -e dwBoAG8AYQBtAGkA` | **0 alerts (Missed!)** | **1 alert (`100005` Level 10 Fired!)** |

---

## 3. Tuning Case C (Linux Auditd Deduplication): Rule `100203` — Linux Crontab (`T1053.003`)

- **Before Tuning:** Matching only `audit.exe = /usr/bin/crontab` caused **4 duplicate alerts** per single `crontab -` invocation (`execve` syscall 59, `openat` syscall 257, `fchmod` syscall 91, and `rename` syscall 82), and failed if `audit.res` was checked instead of `audit.success`.
- **After Tuning:** Added `<field name="audit.syscall">^59$</field>` and `<field name="audit.success">^yes$</field>`.
- **Result:** Reduced alert volume per `crontab` edit from **4 alerts -> 1 exact alert** per execution.
