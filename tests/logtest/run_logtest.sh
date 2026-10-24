#!/usr/bin/env bash
# Replay tests/logtest/cases/*.ini through wazuh-logtest on SOC-Wazuh.
#
# Uses a throwaway manager container (wazuh-ruletest) so the real manager's
# ruleset is never touched. Runs from the analyst PC (Git Bash is fine).
#
#   tests/logtest/run_logtest.sh               # every case file
#   tests/logtest/run_logtest.sh 100201        # only case files with 100201 in the name
#   RULES=/tmp/candidate.xml tests/logtest/run_logtest.sh 100201   # try a rule change first
set -euo pipefail
cd "$(dirname "$0")/../.."

WAZUH=${WAZUH:-soc@192.168.99.10}
KEY=${KEY:-$HOME/.ssh/soclab_ed25519}
RULES=${RULES:-detections/wazuh/local_rules.xml}
CASES=${CASES:-tests/logtest/cases}
FILTER=${1:-}

ssh_() { ssh -i "$KEY" -o BatchMode=yes "$WAZUH" "$@"; }

STAGE=$(ssh_ mktemp -d /tmp/logtest.XXXXXX)
ssh_ "cat > $STAGE/local_rules.xml" < "$RULES"
tar -cf - -C tests/logtest runner.py logtest_windows_decoder.xml | ssh_ "tar -xf - -C $STAGE"
tar -cf - -C "$CASES" . | ssh_ "mkdir $STAGE/cases && tar -xf - -C $STAGE/cases"

ssh_ "bash -s -- $STAGE '$FILTER'" <<'EOF'
set -euo pipefail
STAGE=$1 FILTER=${2:-} C=wazuh-ruletest
trap 'rm -rf "$STAGE"' EXIT

# one run at a time - the container has a single rules dir
exec 9>/tmp/logtest.lock
flock 9

if ! sudo docker ps --format '{{.Names}}' | grep -qx "$C"; then
  sudo docker rm -f "$C" >/dev/null 2>&1 || true
  # default bridge network: its filebeat can't resolve wazuh.indexer, nothing gets indexed
  sudo docker run -d --name "$C" --memory 1200m wazuh/wazuh-manager:4.14.9 >/dev/null
  until sudo docker exec "$C" /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q 'analysisd is running'; do sleep 3; done
fi

sudo docker cp "$STAGE/local_rules.xml" "$C:/var/ossec/etc/rules/local_rules.xml"
sudo docker cp "$STAGE/logtest_windows_decoder.xml" "$C:/var/ossec/ruleset/decoders/0004-logtest_windows_eventchannel.xml"
sudo docker exec "$C" sh -c 'chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml; rm -rf /tmp/cases'
sudo docker cp "$STAGE/cases" "$C:/tmp/cases"
sudo docker cp "$STAGE/runner.py" "$C:/tmp/runner.py"

# logtest sessions load the ruleset when they're created, so no restart needed
sudo docker exec "$C" /var/ossec/framework/python/bin/python3 /tmp/runner.py /tmp/cases "$FILTER"
EOF
