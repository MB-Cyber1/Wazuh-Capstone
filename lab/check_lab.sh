#!/usr/bin/env bash
# Pre-demo health check: VMs, Wazuh stack, agents, deployed rules vs repo,
# indexer, log flow, the Alerting monitor and Win10's clock. Read-only.
#
# It never logs into Win10 or ubuntu-01 (only a TCP check on port 22): an SSH
# logon as soc within 5 minutes of a card 02 test would fire rule 100200.
# Win10's clock is read from its latest event in the indexer instead.
#
#   lab/check_lab.sh          (Git Bash on the analyst PC; exit code 1 if anything FAILs)
set -uo pipefail
cd "$(dirname "$0")/.."

VMRUN="/c/Program Files (x86)/VMware/VMware Workstation/vmrun.exe"
WAZUH=${WAZUH:-soc@192.168.99.10}
KEY=${KEY:-$HOME/.ssh/soclab_ed25519}
RULES=${RULES:-detections/wazuh/local_rules.xml}
AGENT_CONF=lab/wazuh/agent.conf
MONITOR_JSON=detections/alerting/soc_capstone_custom_rules_monitor.json

fails=0 warns=0
report() {  # STATUS name detail
  case $1 in FAIL) fails=$((fails + 1)) ;; WARN) warns=$((warns + 1)) ;; esac
  printf '%-4s  %-20s %s\n' "$1" "$2" "$3"
}

# --- VMs and reachability --------------------------------------------------
running=$("$VMRUN" -T ws list 2>/dev/null)
for vm in SOC-Wazuh SOC-ubuntu-01 SOC-Win10; do
  if grep -qF "$vm.vmx" <<<"$running"; then
    report PASS "vm $vm" running
  else
    report FAIL "vm $vm" "not running - run lab/start_lab.sh"
  fi
done

for host in 192.168.99.10:SOC-Wazuh 192.168.99.40:ubuntu-01 192.168.99.30:Win10; do
  ip=${host%%:*} name=${host#*:}
  if timeout 4 bash -c "</dev/tcp/$ip/22" 2>/dev/null; then
    report PASS "network $name" "$ip:22 reachable"
  else
    report FAIL "network $name" "$ip:22 unreachable"
  fi
done

# --- everything else is checked from the Wazuh VM ---------------------------
rules_sha=$(tr -d '\r' < "$RULES" | sha256sum | cut -d' ' -f1)
conf_sha=$(tr -d '\r' < "$AGENT_CONF" | sha256sum | cut -d' ' -f1)
monitor=$(grep -m1 '"name"' "$MONITOR_JSON" | sed 's/.*"name": *"\(.*\)".*/\1/')

remote=$(ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=5 "$WAZUH" \
  "bash -s -- $rules_sha $conf_sha '$monitor'" 2>/dev/null <<'EOF'
R=$1 C=$2 MON=$3
M=single-node-wazuh.manager-1
AUTH=admin:SecretPassword
IDX=https://127.0.0.1:9200
out() { echo "$1|$2|$3"; }
q() { curl -sk -u $AUTH -H 'Content-Type: application/json' "$IDX/wazuh-alerts-*/_search" -d "$1"; }
count() { q "{\"size\":0,\"query\":{\"bool\":{\"filter\":[$1,{\"range\":{\"timestamp\":{\"gte\":\"$2\"}}}]}}}" | jq -r '.hits.total.value // 0'; }

for c in manager indexer dashboard; do
  s=$(sudo docker inspect -f '{{.State.Status}}' single-node-wazuh.$c-1 2>/dev/null)
  if [ "$s" = running ]; then out PASS "container $c" running; else out FAIL "container $c" "${s:-missing}"; fi
done

NET=single-node_default
BR=br-$(sudo docker network inspect $NET -f '{{.Id}}' 2>/dev/null | cut -c1-12)
GW=$(sudo docker network inspect $NET -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)
if ip -4 addr show "$BR" 2>/dev/null | grep -q "inet $GW/"; then
  out PASS "docker bridge" "$BR has $GW"
else
  out FAIL "docker bridge" "$BR lost its address after a resume - run lab/start_lab.sh"
fi

if sudo docker exec $M /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q 'wazuh-analysisd is running'; then
  out PASS analysisd running
else
  out FAIL analysisd "not running - check /var/ossec/logs/ossec.log in the manager"
fi

agents=$(sudo docker exec $M /var/ossec/bin/agent_control -l 2>/dev/null)
for a in 001:ubuntu-01 002:Win10; do
  line=$(grep "ID: ${a%%:*}," <<<"$agents")
  case "$line" in
    *Active*) out PASS "agent ${a#*:}" Active ;;
    *) out FAIL "agent ${a#*:}" "${line##*, }" ;;
  esac
done

d=$(sudo docker exec $M cat /var/ossec/etc/rules/local_rules.xml | tr -d '\r' | sha256sum | cut -d' ' -f1)
if [ "$d" = "$R" ]; then out PASS "deployed rules" "match the repo"; else out FAIL "deployed rules" "differ from the repo - run lab/wazuh/push_rules.sh"; fi
d=$(sudo docker exec $M cat /var/ossec/etc/shared/default/agent.conf | tr -d '\r' | sha256sum | cut -d' ' -f1)
if [ "$d" = "$C" ]; then out PASS "agent.conf" "matches the repo"; else out FAIL "agent.conf" "differs from the repo - run lab/wazuh/push_rules.sh"; fi

h=$(curl -sk -u $AUTH $IDX/_cluster/health | jq -r '.status // empty')
up=$(( $(date +%s) - $(date -d "$(sudo docker inspect -f '{{.State.StartedAt}}' single-node-wazuh.indexer-1)" +%s) ))
case $h in
  green) out PASS indexer green ;;
  yellow) out WARN indexer "yellow (unassigned replicas)" ;;
  *) if [ $up -lt 300 ]; then out FAIL indexer "no answer - it started ${up}s ago, give it a minute and re-run"
     else out FAIL indexer "${h:-no answer}"; fi ;;
esac

code=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/)
case $code in 200|302) out PASS dashboard "HTTP $code" ;; *) out FAIL dashboard "HTTP $code" ;; esac

n=$(count '{"term":{"agent.name":"Win10"}}' now-15m)
if [ "$n" -gt 0 ]; then out PASS "Win10 logs" "$n events in last 15 min"; else out FAIL "Win10 logs" "nothing in last 15 min"; fi
n=$(count '{"term":{"data.win.system.channel":"Microsoft-Windows-Sysmon/Operational"}}' now-60m)
if [ "$n" -gt 0 ]; then out PASS "Win10 Sysmon" "$n events in last 60 min"; else out WARN "Win10 Sysmon" "none in last 60 min - quiet host, or channel missing from agent.conf"; fi
n=$(count '{"term":{"agent.name":"ubuntu-01"}}' now-60m)
if [ "$n" -gt 0 ]; then out PASS "ubuntu-01 logs" "$n events in last 60 min"; else out WARN "ubuntu-01 logs" "nothing in last 60 min"; fi

# Win10 clock: its own event time vs when the manager received it
last=$(q '{"size":1,"sort":[{"timestamp":"desc"}],"_source":["timestamp","data.win.system.systemTime"],"query":{"bool":{"filter":[{"term":{"agent.name":"Win10"}},{"exists":{"field":"data.win.system.systemTime"}},{"range":{"timestamp":{"gte":"now-30m"}}}]}}}' |
  jq -r '.hits.hits[0]._source | "\(.timestamp) \(.data.win.system.systemTime)"' 2>/dev/null)
if [ -n "$last" ] && [ "$last" != "null null" ]; then
  skew=$(( $(date -d "${last%% *}" +%s) - $(date -d "${last##* }" +%s) ))
  if [ ${skew#-} -le 60 ]; then out PASS "Win10 clock" "${skew}s off the manager"; else out FAIL "Win10 clock" "${skew}s off the manager - run lab/start_lab.sh"; fi
else
  out WARN "Win10 clock" "no recent Win10 event to compare"
fi

mid=$(curl -sk -u $AUTH -H 'Content-Type: application/json' "$IDX/_plugins/_alerting/monitors/_search" \
        -d "{\"query\":{\"match_phrase\":{\"monitor.name\":\"$MON\"}}}" | jq -r '.hits.hits[0]._id // empty')
if [ -z "$mid" ]; then
  out FAIL "alerting monitor" "not found - run lab/wazuh/apply_alerting.sh"
else
  enabled=$(curl -sk -u $AUTH "$IDX/_plugins/_alerting/monitors/$mid" | jq -r '.monitor.enabled')
  err=$(curl -sk -u $AUTH -X POST "$IDX/_plugins/_alerting/monitors/$mid/_execute?dryrun=true" | jq -r '.input_results.error // empty')
  active=$(curl -sk -u $AUTH "$IDX/_plugins/_alerting/monitors/alerts?alertState=ACTIVE&size=100" | jq -r '.totalAlerts // 0')
  if [ "$enabled" != true ]; then out FAIL "alerting monitor" "disabled"
  elif [ -n "$err" ]; then out FAIL "alerting monitor" "query error: $err"
  else out PASS "alerting monitor" "enabled, runs clean, $active active alert(s)"; fi
fi
EOF
)
if [ $? -ne 0 ] && [ -z "$remote" ]; then
  report FAIL "wazuh vm" "can't SSH to $WAZUH - remaining checks skipped"
fi
while IFS='|' read -r status name detail; do
  [ -n "$status" ] && report "$status" "$name" "$detail"
done <<<"$remote"

echo
if [ $fails -eq 0 ] && [ $warns -eq 0 ]; then
  echo "All checks passed."
elif [ $fails -eq 0 ]; then
  echo "All checks passed, $warns warning(s)."
else
  echo "$fails check(s) FAILED, $warns warning(s)."
fi
[ $fails -eq 0 ]
