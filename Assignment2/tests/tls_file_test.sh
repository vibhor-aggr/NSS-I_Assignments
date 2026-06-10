#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

make >/dev/null
mkdir -p "$tmp/files/alice" "$tmp/files/bob" "$tmp/downloads" "$tmp/certs"
printf 'alice:alicepass:%s/files/alice\nbob:bobpass:%s/files/bob\n' "$tmp" "$tmp" > "$tmp/users.db"
printf 'tls file payload\n' > "$tmp/files/bob/secret.txt"
printf 'user:alice:r--\n' > "$tmp/files/bob/.secret.txt.acl"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=nss-test-requester" \
  -keyout "$tmp/certs/requester.key" -out "$tmp/certs/requester.crt" >/dev/null 2>&1

./server_real --bind 127.0.0.1 --kdc-port 19400 --chat-port 19401 \
  --users "$tmp/users.db" --root "$tmp/files" > "$tmp/server.out" 2> "$tmp/server.err" &
server_pid=$!
sleep 1

{ sleep 6; } | timeout 10 ./client_real --user bob --password bobpass --host 127.0.0.1 \
  --kdc-port 19400 --chat-port 19401 --file-root "$tmp/files/bob" \
  > "$tmp/bob.out" 2> "$tmp/bob.err" &
bob_pid=$!

{
  printf '/request file bob secret.txt 127.0.0.1 19450\n'
  sleep 5
} | timeout 10 ./client_real --user alice --password alicepass --host 127.0.0.1 \
  --kdc-port 19400 --chat-port 19401 --file-root "$tmp/files/alice" \
  --download-dir "$tmp/downloads" --cert "$tmp/certs/requester.crt" --key "$tmp/certs/requester.key" \
  > "$tmp/alice.out" 2> "$tmp/alice.err"

wait "$bob_pid" 2>/dev/null || true
cmp "$tmp/files/bob/secret.txt" "$tmp/downloads/secret.txt"

echo "tls_file_test: ok"
