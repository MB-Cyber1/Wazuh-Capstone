#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[*] Installing auditd, nginx, curl, gnupg, apt-transport-https"
sudo apt-get update -qq
sudo apt-get install -y -qq auditd audispd-plugins nginx curl gnupg apt-transport-https

echo "[*] Creating user kali and .ssh directories for rule 100202 compatibility"
id kali >/dev/null 2>&1 || sudo useradd -m -s /bin/bash kali
for u in soc kali root; do
  home_dir=$(eval echo "~$u")
  sudo mkdir -p "$home_dir/.ssh"
  sudo touch "$home_dir/.ssh/authorized_keys"
  sudo chown -R "$u:$u" "$home_dir/.ssh" 2>/dev/null || true
  sudo chmod 700 "$home_dir/.ssh"
  sudo chmod 600 "$home_dir/.ssh/authorized_keys"
done

echo "[*] Installing published Neo23x0 auditd rules + capstone rules (100202, 100203)"
sudo cp /tmp/audit.rules /etc/audit/rules.d/50-neo23x0.rules
cat <<'EOF' | sudo tee /etc/audit/rules.d/99-soc-capstone.rules >/dev/null
# Rule 100203: T1053.003 Cron job execution and crontab modification
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/crontab -k cron_edit
-w /etc/crontab -p wa -k cron_edit
-w /etc/cron.d -p wa -k cron_edit
-w /etc/cron.daily -p wa -k cron_edit
-w /etc/cron.hourly -p wa -k cron_edit
-w /var/spool/cron/crontabs -p wa -k cron_edit

# Rule 100202: T1098.004 SSH authorized_keys modification
-w /home/kali/.ssh/authorized_keys -p wa -k ssh_authorized_keys
-w /home/soc/.ssh/authorized_keys -p wa -k ssh_authorized_keys
-w /root/.ssh/authorized_keys -p wa -k ssh_authorized_keys
-w /home/kali/.ssh -p wa -k ssh_authorized_keys
-w /home/soc/.ssh -p wa -k ssh_authorized_keys
EOF
sudo augenrules --load || sudo auditctl -R /etc/audit/rules.d/99-soc-capstone.rules
sudo systemctl enable --now auditd
sudo systemctl enable --now nginx

echo "[*] Installing Wazuh Agent 4.14.9"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list >/dev/null
sudo apt-get update -qq
sudo WAZUH_MANAGER="192.168.99.10" WAZUH_AGENT_NAME="ubuntu-01" apt-get install -y -qq wazuh-agent=4.14.9-1

if ! sudo grep -q "/var/log/nginx/access.log" /var/ossec/etc/ossec.conf; then
  sudo sed -i '/<\/ossec_config>/i \
  <localfile>\n    <log_format>audit</log_format>\n    <location>/var/log/audit/audit.log</location>\n  </localfile>\n  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/nginx/access.log</location>\n  </localfile>\n  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/nginx/error.log</location>\n  </localfile>' /var/ossec/etc/ossec.conf
fi
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl restart wazuh-agent || true
echo "[OK] ubuntu-01 provisioned: auditd + nginx + wazuh-agent"
sudo auditctl -l | tail -n 12