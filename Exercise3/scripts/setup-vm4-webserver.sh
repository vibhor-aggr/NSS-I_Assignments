#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source ./topology.env

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root on VM4" >&2
  exit 1
fi

ip addr add "$VM4_IP" dev "${VM4_IF:-eth0}" 2>/dev/null || true
ip route replace default via "$VM4_GW"

mkdir -p /var/www/html/nss-ex3
printf 'NSS Exercise 3 web selector test\n' > /var/www/html/nss-ex3/index.txt

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y apache2
  systemctl enable --now apache2
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y httpd
  systemctl enable --now httpd
else
  python3 -m http.server 80 --directory /var/www/html &
fi

echo "VM4 webserver ready. Test from VM1 with: wget http://30.0.0.10/nss-ex3/index.txt"
