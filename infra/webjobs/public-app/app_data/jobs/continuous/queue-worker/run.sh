#!/usr/bin/env bash
set -euo pipefail

echo "ho-azure-lab queue-worker webjob started"
while true; do
  echo "ho-azure-lab queue-worker heartbeat"
  sleep 300
done
