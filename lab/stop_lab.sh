#!/usr/bin/env bash
# Shut the lab down cleanly (better than letting VMware suspend the VMs).
#
#   lab/stop_lab.sh
set -uo pipefail

KEY=${KEY:-$HOME/.ssh/soclab_ed25519}
ssh_() { ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=5 "$@"; }

ssh_ soc@192.168.99.30 "shutdown /s /t 0" && echo "Win10 shutting down"
ssh_ soc@192.168.99.40 "sudo systemctl poweroff" && echo "ubuntu-01 shutting down"
# Wazuh last, so the agents' final events still get indexed
sleep 20
ssh_ soc@192.168.99.10 "sudo systemctl poweroff" && echo "SOC-Wazuh shutting down"
