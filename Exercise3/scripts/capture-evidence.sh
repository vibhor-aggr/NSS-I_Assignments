#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source ./topology.env

out_dir="${1:-captures}"
mkdir -p "$out_dir"

cat <<EOF
Run the following commands on the indicated VMs.

On VM2 or VM3 gateway, capture IKE and ESP:
  sudo tcpdump -i ${CAPTURE_IF} -w ${out_dir}/gateway-ike-esp.pcap 'udp port 500 or udp port 4500 or esp'

On VM1, prove tunnel ICMP:
  ping -c 4 ${VM4_WEB_IP}
  traceroute ${VM4_WEB_IP}

On VM1, prove traffic selector for web traffic:
  wget -O - http://${VM4_WEB_IP}/nss-ex3/index.txt

On VM1, prove non-web traffic is denied after nss-web-selector is active:
  nc -vz ${VM4_WEB_IP} 22 || true

On gateways, collect LibreSwan/IPsec state:
  sudo ipsec status
  sudo ip xfrm state
  sudo ip xfrm policy
EOF
