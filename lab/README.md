# SOC Capstone Lab – Build Notes

## Network plan (VMnet1 host-only = lab, VMnet8 NAT = internet for setup only)

| Host | Role | Lab IP (VMnet1) | OS | RAM / vCPU |
|---|---|---|---|---|
| Your PC | Analyst workstation / browser | 192.168.99.1 | Windows | – |
| SOC-Wazuh | Wazuh 4.14.9 on Docker (manager, indexer, dashboard) | 192.168.99.10 | Ubuntu 24.04 | 8 GB / 4 |
| DC01 | Domain controller (`soc.lab`) | 192.168.99.20 | Windows Server 2022 eval | 4 GB / 2 |
| WIN10 | Victim workstation (Sysmon) | 192.168.99.30 | Windows 11 Enterprise eval | 6 GB / 4 |
| ubuntu-01 | Linux victim (auditd + nginx = 3rd log source) | 192.168.99.40 | Ubuntu 24.04 | 2 GB / 2 |
| attacker | Attacker box (optional, Kali) | 192.168.99.50 | Kali | 4 GB / 2 |

> Isolation: before running any attack, disconnect **Network Adapter 2 (NAT)** on every VM.
> The lab keeps working on VMnet1; nothing leaves the lab network.

## Lab-only credentials

| Where | User | Password |
|---|---|---|
| Ubuntu VMs (SSH, sudo) | `soc` | `SocLab!2026` (or key `~/.ssh/soclab_ed25519`) |
| Wazuh dashboard | `admin` | `SecretPassword` (wazuh-docker default – change it) |

## Build steps (status)

1. `isos/` – Ubuntu 24.04.3 (checksum verified), Windows 11 Ent eval, Server 2022 eval
2. `vm-builder/build_vms.py` – unattended Ubuntu VMs (cloud-init autoinstall)
3. `wazuh/deploy_wazuh.sh` – Wazuh single-node on Docker
4. Agents + Sysmon (Windows), auditd + nginx (ubuntu-01)
5. Pipeline proof per host (test action → searchable event, delay + fields recorded)
