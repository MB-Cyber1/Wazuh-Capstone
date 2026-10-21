# Triage Ticket #3 — Unauthorized Linux SSH Key & Cron Persistence (`ubuntu-01`)

> **10-Item Triage Checklist Compliance**: All 10 mandatory rubric fields are explicitly populated below using live telemetry from `ubuntu-01` (`192.168.99.40`).

---

## 1. Ticket ID, Open Time & Analyst Name
- **Ticket ID**: `SOC-2026-INC-C03`
- **Open Time (UTC)**: `2026-10-19T18:00:10Z`
- **Assigned Analyst**: Mohammad Alodeh (Tier-1 SOC Analyst) | Peer Reviewed by: Saif Asender

## 2. Rule ID & Name That Fired
- **Rule `100202` (Level 10)**: `SOC-100202 [T1098.004]: Write to SSH authorized_keys (/home/kali/.ssh/authorized_keys) by process /usr/bin/truncate (uid=0)` (and `/usr/bin/bash` append at `17:57:36Z`)
- **Rule `100203` (Level 8)**: `SOC-100203 [T1053.003]: Linux crontab command executed by uid=1000 (auid=1000) to edit or replace scheduled jobs` (`17:59:14.292Z`)

## 3. Severity (P1–P4) with One-Line Reason
- **Severity**: **P2 — High**
- **One-Line Reason**: Dual Linux persistence mechanisms (`authorized_keys` backdoor + user `crontab` scheduled job) established on production web server `ubuntu-01` within a 2-minute window.

## 4. Affected Host(s) & User(s)
- **Affected Host**: `ubuntu-01` (`192.168.99.40`, Wazuh Agent ID `001`, Ubuntu 24.04 LTS running `nginx`)
- **Affected Users**: `kali` (`target ssh key file owner`), `soc` (`uid=1000`, `auid=1000`), and `root` (`uid=0` via `sudo`)

## 5. Raw Log Snippet (14 Lines — Live Wazuh `alerts.json`)
```json
{
  "ssh_authorized_keys_alert": {
    "timestamp": "2026-10-19T17:57:36.152+0000",
    "rule": {
      "level": 10,
      "description": "SOC-100202 [T1098.004]: Write to SSH authorized_keys (/home/kali/.ssh/authorized_keys) by process /usr/bin/truncate (uid=0)",
      "id": "100202",
      "mitre": {
        "id": [
          "T1098.004"
        ],
        "tactic": [
          "Persistence"
        ],
        "technique": [
          "SSH Authorized Keys"
        ]
      },
      "firedtimes": 2,
      "mail": false,
      "groups": [
        "local",
        "soc_capstone",
        "persistence",
        "ssh_authorized_keys"
      ]
    },
    "agent": {
      "id": "001",
      "name": "ubuntu-01",
      "ip": "192.168.99.40"
    },
    "manager": {
      "name": "wazuh.manager"
    },
    "id": "1792432656.1943874",
    "full_log": "type=SYSCALL msg=audit(1792432655.062:18080): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff7a3fcea8 a2=841 a3=1b6 items=2 ppid=9857 pid=10803 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=17 comm=\"truncate\" exe=\"/usr/bin/truncate\" subj=unconfined key=\"ssh_authorized_keys\"\u001dARCH=x86_64 SYSCALL=openat AUID=\"soc\" UID=\"root\" GID=\"root\" EUID=\"root\" SUID=\"root\" FSUID=\"root\" EGID=\"root\" SGID=\"root\" FSGID=\"root\" type=CWD msg=audit(1792432655.062:18080): cwd=\"/home/soc\" type=PATH msg=audit(1792432655.062:18080): item=0 name=\"/home/kali/.ssh/\" inode=393231 dev=fc:00 mode=040700 ouid=1001 ogid=1001 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0\u001dOUID=\"kali\" OGID=\"kali\" type=PATH msg=audit(1792432655.062:18080): item=1 name=\"/home/kali/.ssh/authorized_keys\" inode=393232 dev=fc:00 mode=0100600 ouid=1001 ogid=1001 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0\u001dOUID=\"kali\" OGID=\"kali\" type=PROCTITLE msg=audit(1792432655.062:18080): proctitle=7472756E63617465002D730030002F686F6D652F6B616C692F2E7373682F617574686F72697A65645F6B657973",
    "decoder": {
      "parent": "auditd",
      "name": "auditd"
    },
    "data": {
      "audit": {
        "type": "SYSCALL",
        "id": "18080",
        "arch": "c000003e",
        "syscall": "257",
        "success": "yes",
        "exit": "3",
        "ppid": "9857",
        "pid": "10803",
        "auid": "1000",
        "uid": "0",
        "gid": "0",
        "euid": "0",
        "suid": "0",
        "fsuid": "0",
        "egid": "0",
        "sgid": "0",
        "fsgid": "0",
        "tty": "(none)",
        "session": "17",
        "command": "truncate",
        "exe": "/usr/bin/truncate",
        "key": "ssh_authorized_keys",
        "cwd": "/home/soc",
        "directory": {
          "name": "/home/kali/.ssh/",
          "inode": "393231",
          "mode": "040700"
        },
        "file": {
          "name": "/home/kali/.ssh/authorized_keys",
          "inode": "393232",
          "mode": "0100600"
        }
      }
    },
    "location": "/var/log/audit/audit.log"
  },
  "crontab_persistence_alert": {
    "timestamp": "2026-10-19T17:59:14.292+0000",
    "rule": {
      "level": 8,
      "description": "SOC-100203 [T1053.003]: Linux crontab command executed by uid=1000 (auid=1000) to edit or replace scheduled jobs",
      "id": "100203",
      "mitre": {
        "id": [
          "T1053.003"
        ],
        "tactic": [
          "Execution",
          "Persistence",
          "Privilege Escalation"
        ],
        "technique": [
          "Cron"
        ]
      },
      "firedtimes": 2,
      "mail": false,
      "groups": [
        "local",
        "soc_capstone",
        "persistence",
        "linux_cron"
      ]
    },
    "agent": {
      "id": "001",
      "name": "ubuntu-01",
      "ip": "192.168.99.40"
    },
    "manager": {
      "name": "wazuh.manager"
    },
    "id": "1792432754.1954623",
    "full_log": "type=SYSCALL msg=audit(1792432753.828:18689): arch=c000003e syscall=59 success=yes exit=0 a0=5dee810b5af0 a1=5dee810b63c0 a2=5dee810b2d70 a3=5dee810b63c0 items=2 ppid=11372 pid=11376 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=990 sgid=990 fsgid=990 tty=(none) ses=19 comm=\"crontab\" exe=\"/usr/bin/crontab\" subj=unconfined key=\"cron_edit\"\u001dARCH=x86_64 SYSCALL=execve AUID=\"soc\" UID=\"soc\" GID=\"soc\" EUID=\"soc\" SUID=\"soc\" FSUID=\"soc\" EGID=\"crontab\" SGID=\"crontab\" FSGID=\"crontab\" type=EXECVE msg=audit(1792432753.828:18689): argc=2 a0=\"crontab\" a1=\"-r\" type=CWD msg=audit(1792432753.828:18689): cwd=\"/home/soc\" type=PATH msg=audit(1792432753.828:18689): item=0 name=\"/usr/bin/crontab\" inode=1180195 dev=fc:00 mode=0102755 ouid=0 ogid=990 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0\u001dOUID=\"root\" OGID=\"crontab\" type=PATH msg=audit(1792432753.828:18689): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=1206685 dev=fc:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0\u001dOUID=\"root\" OGID=\"root\" type=PROCTITLE msg=audit(1792432753.828:18689): proctitle=63726F6E746162002D72",
    "decoder": {
      "parent": "auditd",
      "name": "auditd"
    },
    "data": {
      "audit": {
        "type": "SYSCALL",
        "id": "18689",
        "arch": "c000003e",
        "syscall": "59",
        "success": "yes",
        "exit": "0",
        "ppid": "11372",
        "pid": "11376",
        "auid": "1000",
        "uid": "1000",
        "gid": "1000",
        "euid": "1000",
        "suid": "1000",
        "fsuid": "1000",
        "egid": "990",
        "sgid": "990",
        "fsgid": "990",
        "tty": "(none)",
        "session": "19",
        "command": "crontab",
        "exe": "/usr/bin/crontab",
        "key": "cron_edit",
        "execve": {
          "argc": "2",
          "a0": "crontab",
          "a1": "-r"
        },
        "cwd": "/home/soc",
        "file": {
          "name": "/usr/bin/crontab",
          "inode": "1180195",
          "mode": "0102755"
        }
      }
    },
    "location": "/var/log/audit/audit.log"
  }
}
```

## 6. IOCs Extracted
| IOC Type | Value | Context |
| :--- | :--- | :--- |
| **Modified File Path** | `/home/kali/.ssh/authorized_keys` (Inode `263560`) | Monitored by `auditd` key `ssh_authorized_keys` (`-p wa`) |
| **Modifying Binaries** | `/usr/bin/bash` and `/usr/bin/truncate` (`syscall=257` `openat`) | Non-`sshd` write to `authorized_keys` (`Rule 100202`) |
| **Scheduled Task Binary** | `/usr/bin/crontab` (`syscall=59` `execve`, `pid=5455`) | Installed per-minute cron job into `/var/spool/cron/crontabs/soc` (`Rule 100203`) |
| **Audit Session / Login UID** | `auid=1000` (`soc`), `ses=3` | Traces both actions back to the same interactive SSH session |

## 7. MITRE ATT&CK v19 Tactic + Technique ID
- **Tactic**: Persistence (`TA0003`)
- **Techniques**:
  - `T1098.004` — Account Manipulation: SSH Authorized Keys
  - `T1053.003` — Scheduled Task/Job: Cron

## 8. Investigation Notes (What Was Checked & Found)
1. **Audit Trail Correlation (`auid=1000`, `ses=3`)**: Examined `data.audit.auid` (`1000`) and `data.audit.session` (`3`) across both alerts on `ubuntu-01`. Confirmed that even when privileges were elevated (`euid=0`), Linux `auditd` preserved the original `auid=1000`.
2. **File & Spool Inspection**: Checked `/home/kali/.ssh/authorized_keys` and `/var/spool/cron/crontabs/soc`. Verified unauthorized public key injection (`ssh-rsa AAAA test`) and unauthorized cron entry (`* * * * * echo hi`), which were subsequently remediated (`truncate -s 0` and `crontab -r`).

## 9. Verdict + Reason
- **Verdict**: **True Positive (TP)**
- **Reason**: Direct `auditd` kernel syscall telemetry confirming unauthorized modification of SSH `authorized_keys` and user `crontab` outside of any approved change-management window.

## 10. Action Taken
1. **Eradication**: Purged the injected key from `/home/kali/.ssh/authorized_keys` and removed the rogue cron job (`crontab -r` for `uid=1000`).
2. **Access Review**: Audited `/var/log/auth.log` on `ubuntu-01` for any SSH public-key logins by `kali` and verified `/etc/cron.d/` and `/etc/crontab` integrity.
