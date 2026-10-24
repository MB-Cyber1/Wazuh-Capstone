#!/usr/bin/env bash
# Create (or update) the OpenSearch Alerting monitor for the custom rules and
# import the Tier-1 dashboard + saved searches. Safe to re-run.
#
#   lab/wazuh/apply_alerting.sh
#
# The dashboard import needs the wazuh-alerts-* index pattern, which the Wazuh
# app creates the first time someone opens the dashboard after a fresh install.
set -euo pipefail
cd "$(dirname "$0")/../.."

WAZUH=${WAZUH:-soc@192.168.99.10}
KEY=${KEY:-$HOME/.ssh/soclab_ed25519}

ssh_() { ssh -i "$KEY" -o BatchMode=yes "$WAZUH" "$@"; }

ssh_ "cat > /tmp/soc_monitor.json" < detections/alerting/soc_capstone_custom_rules_monitor.json
ssh_ "cat > /tmp/soc_dashboard.ndjson" < detections/dashboard/soc_capstone_tier1_dashboard.ndjson

ssh_ bash -s <<'EOF'
set -euo pipefail
IDX=https://127.0.0.1:9200
OSD=https://127.0.0.1
AUTH=admin:SecretPassword
name=$(jq -r .name /tmp/soc_monitor.json)

# update in place if a monitor with this name already exists
id=$(curl -sk -u $AUTH -H 'Content-Type: application/json' "$IDX/_plugins/_alerting/monitors/_search" \
       -d "{\"query\":{\"match_phrase\":{\"monitor.name\":\"$name\"}}}" | jq -r '.hits.hits[0]._id // empty')
if [ -n "$id" ]; then
  curl -sk -u $AUTH -H 'Content-Type: application/json' -X PUT "$IDX/_plugins/_alerting/monitors/$id" \
    -d @/tmp/soc_monitor.json | jq -c '{monitor: ._id, result: "updated"}'
else
  curl -sk -u $AUTH -H 'Content-Type: application/json' -X POST "$IDX/_plugins/_alerting/monitors" \
    -d @/tmp/soc_monitor.json | jq -c '{monitor: ._id, result: "created"}'
fi

curl -sk -u $AUTH -H 'osd-xsrf: true' "$OSD/api/saved_objects/_import?overwrite=true" \
  --form file=@/tmp/soc_dashboard.ndjson | jq -c '{success, successCount, errors}'
EOF
