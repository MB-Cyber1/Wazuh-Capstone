# Sub-task 1.4 — Custom SOC Tier-1 Analyst Dashboard (6 pts)

## 1. Live Dashboard Access

- **Direct Dashboard URL**: `https://192.168.99.10/app/dashboards#/view/soc-capstone-tier1-dashboard`
- **Credentials**: `admin` / `SecretPassword`
- **Exported Saved Objects Bundle**: [`soc_capstone_tier1_dashboard.ndjson`](../../detections/dashboard/soc_capstone_tier1_dashboard.ndjson)

---

## 2. Dashboard Panels Specification (6 Panels)

| Panel # | Panel Title | Visualization Type | Index / Filter Query (KQL) | Tier-1 Analyst Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **1** | `1. Alert Volume Over Time by Severity Level (rule.level)` | Stacked Bar Histogram | `wazuh-alerts-*` (`timestamp` x `rule.level`) | Detects alert spikes and separates Level 12–14 critical incidents (`100200`, `100201`, `100207`) from baseline Level 3–5 telemetry. |
| **2** | `2. Top Detection Rules Fired (Rule ID, MITRE, Description)` | Data Table | `rule.groups:soc_capstone or rule.level >= 8` | Ranks firing rules by volume alongside `rule.id`, `rule.level`, `rule.mitre.id`, and `rule.description` to spot noisy rules vs. high-priority detections. |
| **3** | `3. Top Targeted Hosts (agent.name) & Users` | Data Table | `wazuh-alerts-*` (`agent.name` x `data.win.eventdata.targetUserName`) | Identifies which endpoints (`Win10`, `ubuntu-01`) and user accounts (`soc`, `kali`) are under active attack. |
| **4** | `4. Failed vs. Successful Logons Over Time (4625 / 4624 / PAM)` | Stacked Bar Histogram | Filter 1: `rule.groups:authentication_failed or data.win.system.eventID:4625`<br/>Filter 2: `rule.groups:authentication_success or data.win.system.eventID:4624` | Visually correlates brute-force bursts (`100007`) against subsequent logon successes (`100200` / `100204`). |
| **5** | `5. Recent High-Severity & Capstone Alerts (Key Triage Fields)` | Saved Search Stream | `rule.groups:soc_capstone or rule.level >= 8` | Provides immediate one-screen triage context: `timestamp`, `agent.name`, `rule.id`, `rule.level`, `rule.mitre.id`, `rule.description`, `data.win.eventdata.targetUserName`, and `data.win.eventdata.commandLine`. |
| **6** | `6. MITRE ATT&CK v19 Techniques Detected (Capstone Rule Pack)` | Donut Chart | `rule.groups:soc_capstone` (`rule.mitre.id`) | Maps active alerts directly to MITRE ATT&CK v19 techniques (`T1059.001`, `T1110`, `T1003.001`, `T1105`, `T1053.003`, `T1098.004`, `T1021.001`, `T1218.011`, `T1547.001`, `T1685`). |

---

## 3. Re-Importing the Dashboard (`_import` API)

If rebuilding the stack, import `soc_capstone_tier1_dashboard.ndjson` with a single command:

```bash
curl -sk -u admin:SecretPassword \
  -X POST "https://192.168.99.10:443/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" \
  --form file=@detections/dashboard/soc_capstone_tier1_dashboard.ndjson
```
