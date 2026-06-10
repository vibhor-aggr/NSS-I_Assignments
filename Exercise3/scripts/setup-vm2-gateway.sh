#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source ./topology.env

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root on VM2" >&2
  exit 1
fi

ip addr add "$VM2_LEFT_IP" dev "$VM2_LEFT_IF" 2>/dev/null || true
ip addr add "$VM2_RIGHT_IP" dev "$VM2_RIGHT_IF" 2>/dev/null || true
ip link set "$VM2_LEFT_IF" up
ip link set "$VM2_RIGHT_IF" up
sysctl -w net.ipv4.ip_forward=1

iptables -P FORWARD DROP
iptables -A FORWARD -s "$LEFT_SUBNET" -d "$RIGHT_SUBNET" -j ACCEPT
iptables -A FORWARD -s "$RIGHT_SUBNET" -d "$LEFT_SUBNET" -j ACCEPT

install -m 0644 configs/vm2-ipsec.conf /etc/ipsec.conf
systemctl enable --now ipsec
ipsec restart
ipsec auto --add nss-tunnel
ipsec auto --up nss-tunnel

echo "VM2 gateway configured. Validate with: ipsec status; ip xfrm state"
