#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make >/dev/null
openssl rand -out "$tmp/secure.key" 32
printf 'secure copy regression\nline two\n' > "$tmp/input.txt"
mkdir -p "$tmp/out" "$tmp/corrupt"

./secure_client "$tmp/input.txt" received.txt "$tmp/secure.key" | \
  ./secure_server "$tmp/secure.key" "$tmp/out" >/dev/null

cmp "$tmp/input.txt" "$tmp/out/received.txt"

if ./secure_client "$tmp/input.txt" received.txt "$tmp/secure.key" -corrupt_data | \
   ./secure_server "$tmp/secure.key" "$tmp/corrupt" >/dev/null 2>&1; then
  echo "corrupt transfer unexpectedly succeeded" >&2
  exit 1
fi

if [ -e "$tmp/corrupt/received.txt" ]; then
  echo "corrupt transfer wrote output file" >&2
  exit 1
fi

echo "secure_copy_test: ok"
