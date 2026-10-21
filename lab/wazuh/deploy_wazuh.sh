#!/usr/bin/env bash
set -euo pipefail
sudo rm -f /etc/machine-id
sudo systemd-machine-id-setup
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf >/dev/null
sudo sysctl -w vm.max_map_count=262144
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq docker.io docker-compose-v2 jq
sudo usermod -aG docker soc || true
sudo systemctl enable --now docker

WAZUH_VERSION="v4.14.9"
DIR="$HOME/wazuh-docker"
if [ ! -d "$DIR" ]; then
  git clone --depth 1 -b "$WAZUH_VERSION" https://github.com/wazuh/wazuh-docker.git "$DIR"
fi
cd "$DIR/single-node"
if [ ! -f config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
  sudo docker compose -f generate-indexer-certs.yml run --rm generator
fi
sudo docker compose pull -q
sudo docker compose up -d
echo "[*] Waiting for Wazuh dashboard on https://127.0.0.1 ..."
for i in $(seq 1 60); do
  code=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1 || true)
  if [ "$code" = "200" ] || [ "$code" = "302" ]; then
    echo "[OK] Wazuh Dashboard is READY (HTTP $code)"
    sudo docker compose ps
    exit 0
  fi
  sleep 5
done
echo "[!] Timeout waiting for dashboard"
sudo docker compose ps