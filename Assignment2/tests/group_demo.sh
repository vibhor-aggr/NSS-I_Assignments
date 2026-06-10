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

./server_real --bind 127.0.0.1 --kdc-port 19200 --chat-port 19201 \
  --users "$tmp/users.db" --root "$tmp/files" > "$tmp/server.out" 2> "$tmp/server.err" &
server_pid=$!
sleep 1

{
  sleep 2
  printf '/group invite accept 1\n'
  sleep 2
} | timeout 8 ./client_real --user bob --password bobpass --host 127.0.0.1 \
  --kdc-port 19200 --chat-port 19201 --file-root "$tmp/files/bob" \
  > "$tmp/bob.out" 2> "$tmp/bob.err" &
bob_pid=$!

{
  printf '/create group demo\n'
  sleep 1
  printf '/group invite 1 bob\n'
  sleep 1
  printf '/init group dhxchg 1\n'
  sleep 1
  printf '/write group 1 encrypted hello\n'
  sleep 1
} | timeout 8 ./client_real --user alice --password alicepass --host 127.0.0.1 \
  --kdc-port 19200 --chat-port 19201 --file-root "$tmp/files/alice" \
  > "$tmp/alice.out" 2> "$tmp/alice.err"

wait "$bob_pid" 2>/dev/null || true

grep -q 'GROUP_CREATED 1 demo' "$tmp/alice.out"
grep -q 'GROUP_KEY 1' "$tmp/alice.out"
grep -q 'MSG group 1 alice encrypted hello' "$tmp/bob.out"

echo "group_demo: ok"
