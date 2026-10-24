#!/usr/bin/env bash
# Print the full_log of a stored alert as one line, ready to paste into a
# cases/*.ini file as "log N pass = <line>".
#
#   tests/logtest/export_alert.sh 1792435410.10265946
#   tests/logtest/export_alert.sh 1792435410.10265946 location   # where it came from
set -euo pipefail
WAZUH=${WAZUH:-soc@192.168.99.10}
KEY=${KEY:-$HOME/.ssh/soclab_ed25519}
ID=$1 FIELD=${2:-full_log}

ssh -i "$KEY" -o BatchMode=yes "$WAZUH" bash -s -- "$ID" "$FIELD" <<'EOF'
curl -sk -u admin:SecretPassword -H 'Content-Type: application/json' \
  "https://127.0.0.1:9200/wazuh-alerts-*/_search" \
  -d "{\"size\":1,\"query\":{\"term\":{\"id\":\"$1\"}}}" |
  jq -r --arg f "$2" '.hits.hits[0]._source[$f] // empty' | tr -d '\n'
echo
EOF
