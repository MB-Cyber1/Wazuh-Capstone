#!/usr/bin/env bash
# Push detections/wazuh/local_rules.xml and lab/wazuh/agent.conf from this repo
# to the manager container, check both, then restart the manager.
# If the ruleset doesn't load, the previous local_rules.xml is put back.
#
#   lab/wazuh/push_rules.sh          (from the repo root or anywhere, Git Bash is fine)
set -euo pipefail
cd "$(dirname "$0")/../.."

WAZUH=${WAZUH:-soc@192.168.99.10}
KEY=${KEY:-$HOME/.ssh/soclab_ed25519}

ssh_() { ssh -i "$KEY" -o BatchMode=yes "$WAZUH" "$@"; }

ssh_ "cat > /tmp/local_rules.xml" < detections/wazuh/local_rules.xml
ssh_ "cat > /tmp/agent.conf" < lab/wazuh/agent.conf

ssh_ bash -s <<'EOF'
set -euo pipefail
C=single-node-wazuh.manager-1
R=/var/ossec/etc/rules/local_rules.xml
A=/var/ossec/etc/shared/default/agent.conf

sudo docker exec $C cp $R $R.bak
sudo docker cp /tmp/local_rules.xml $C:$R
sudo docker cp /tmp/agent.conf $C:$A
sudo docker exec $C chown wazuh:wazuh $R $A
sudo docker exec $C /var/ossec/bin/verify-agent-conf -f $A

if ! sudo docker exec $C /var/ossec/bin/wazuh-analysisd -t; then
  echo "[!] ruleset didn't load - restoring the previous local_rules.xml"
  sudo docker exec $C cp $R.bak $R
  exit 1
fi

sudo docker exec $C /var/ossec/bin/wazuh-control restart >/dev/null
echo "[ok] rules + agent.conf deployed, manager restarted"
sudo docker exec $C /var/ossec/bin/agent_control -l | grep -E 'ID: 00[12]'
EOF
