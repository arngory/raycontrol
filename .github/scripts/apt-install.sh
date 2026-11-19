#!/usr/bin/env bash
# Installs packages on an Ubuntu runner, and again after a pause when the
# archive fails: its mirrors answer 503 for minutes at times, and a release
# or a check must not stop on that. Six tries over about five minutes.
set -euo pipefail
for try in 1 2 3 4 5 6; do
  if sudo apt-get install -y -q "$@"; then
    exit 0
  fi
  if [ "$try" -lt 6 ]; then
    echo "apt-get install $*: try $try failed, again in $((try * 20)) s" >&2
    sleep $((try * 20))
    sudo apt-get update -q || true
  fi
done
echo "apt-get install $*: failed six times" >&2
exit 1
