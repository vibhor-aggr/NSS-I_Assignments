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
mkdir -p "$tmp/files/alice" "$tmp/files/bob"
printf 'alice:alicepass:%s/files/alice\nbob:bobpass:%s/files/bob\n' "$tmp" "$tmp" > "$tmp/users.db"
printf 'hello from alice\n' > "$tmp/files/alice/readme.txt"

./server_real --bind 127.0.0.1 --kdc-port 19100 --chat-port 19101 \
  --users "$tmp/users.db" --root "$tmp/files" > "$tmp/server.out" 2> "$tmp/server.err" &
server_pid=$!
sleep 1

{ printf '/who\n'; sleep 1; } | timeout 5 \
  ./client_real --user alice --password alicepass --host 127.0.0.1 \
  --kdc-port 19100 --chat-port 19101 --file-root "$tmp/files/alice" \
  > "$tmp/alice.out" 2> "$tmp/alice.err"

grep -q 'OK authenticated alice' "$tmp/alice.out"
grep -q 'USERS' "$tmp/alice.out"

if { printf '/who\n'; sleep 1; } | timeout 5 \
  ./client_real --user alice --password wrong --host 127.0.0.1 \
  --kdc-port 19100 --chat-port 19101 --file-root "$tmp/files/alice" \
  > "$tmp/bad.out" 2> "$tmp/bad.err"; then
  echo "bad password unexpectedly authenticated" >&2
  exit 1
fi

echo "chat_smoke_test: ok"
