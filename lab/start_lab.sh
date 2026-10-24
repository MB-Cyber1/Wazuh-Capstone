#!/usr/bin/env bash
# Start (or resume) the three lab VMs headless, fix Win10's clock and Docker's
# bridge, and show agent status. Run from Git Bash on the analyst PC:
#
#   lab/start_lab.sh
#
# Setting Win10's clock logs in over SSH as soc, so don't run this within
# 5 minutes of a card 02 brute-force test (any soc logon then fires 100200).
set -euo pipefail

VMRUN="/c/Program Files (x86)/VMware/VMware Workstation/vmrun.exe"
BASE="$(cygpath -w "$HOME")\\Documents\\Virtual Machines\\SOC-Lab"
KEY=${KEY:-$HOME/.ssh/soclab_ed25519}

ssh_() { ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=5 "$@"; }

running=$("$VMRUN" -T ws list)
for vm in SOC-Wazuh SOC-ubuntu-01 SOC-Win10; do
  vmx="$BASE\\$vm\\$vm.vmx"
  if grep -qF "$vm.vmx" <<<"$running"; then
    echo "$vm already running"
  else
    echo "starting $vm"
    "$VMRUN" -T ws start "$vmx" nogui
  fi
done

echo "waiting for SSH ..."
for ip in 10 40 30; do
  for i in $(seq 1 60); do ssh_ soc@192.168.99.$ip exit 2>/dev/null && break; sleep 5; done
done

# Win10 has no VMware Tools, so after a suspend its clock stays where it stopped
# (and w32tm refuses big corrections). Set it from this PC's clock.
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ssh_ soc@192.168.99.30 "powershell -NoProfile -c \"Set-Date -Date ([datetime]::Parse('$now')) | Out-Null\""
echo "Win10 clock set to $now"

# containers restart on their own (restart: always); wait for both agents
ssh_ soc@192.168.99.10 bash -s <<'EOF'
# After a suspend/resume, VMware Tools restarts the VM's networking, which can
# strip the IPv4 address off Docker's bridge: the containers keep running, but
# the agents (1514), the indexer API and the dashboard become unreachable.
NET=single-node_default
BR=br-$(sudo docker network inspect $NET -f '{{.Id}}' | cut -c1-12)
GW=$(sudo docker network inspect $NET -f '{{(index .IPAM.Config 0).Gateway}}')
PFX=$(sudo docker network inspect $NET -f '{{(index .IPAM.Config 0).Subnet}}' | cut -d/ -f2)
if ! ip -4 addr show "$BR" | grep -q "inet $GW/"; then
  sudo ip addr add "$GW/$PFX" dev "$BR" && echo "repaired docker bridge $BR ($GW/$PFX)"
fi

for i in $(seq 1 60); do
  n=$(sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l 2>/dev/null | grep -cE 'ID: 00[12].*Active' || true)
  [ "$n" = 2 ] && break
  sleep 5
done
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l | grep -E 'ID: 00'
curl -sk -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health | jq -r '"indexer: " + .status'
EOF
echo "Dashboard: https://192.168.99.10  (admin / SecretPassword)"
