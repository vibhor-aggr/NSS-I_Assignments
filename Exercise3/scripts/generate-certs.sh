#!/usr/bin/env bash
set -euo pipefail

out_dir="${1:-certs}"
mkdir -p "$out_dir"

openssl genrsa -out "$out_dir/ca.key" 4096
openssl req -x509 -new -nodes -key "$out_dir/ca.key" -sha256 -days 3650 \
  -subj "/CN=NSS Exercise3 CA" -out "$out_dir/ca.crt"

for vm in vm2 vm3; do
  openssl genrsa -out "$out_dir/$vm.key" 2048
  openssl req -new -key "$out_dir/$vm.key" -subj "/CN=$vm.nss.local" -out "$out_dir/$vm.csr"
  openssl x509 -req -in "$out_dir/$vm.csr" -CA "$out_dir/ca.crt" -CAkey "$out_dir/ca.key" \
    -CAcreateserial -out "$out_dir/$vm.crt" -days 825 -sha256
done

cat <<EOF
Generated CA and gateway certificates in $out_dir.

Copy to VM2:
  ca.crt, vm2.crt, vm2.key
Copy to VM3:
  ca.crt, vm3.crt, vm3.key

On each gateway, import with:
  sudo ipsec initnss
  sudo certutil -A -n "NSS Exercise3 CA" -t "CT,," -d sql:/etc/ipsec.d -i ca.crt
  sudo pk12util -i <vm>.p12 -d sql:/etc/ipsec.d

If pk12util is required:
  openssl pkcs12 -export -inkey <vm>.key -in <vm>.crt -certfile ca.crt -out <vm>.p12 -name <vm>.crt
EOF
