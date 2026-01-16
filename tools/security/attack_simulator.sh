#!/usr/bin/env bash
set -euo pipefail
TARGET=${1:-http://localhost:8080/login}
USERS=(analyst investigator admin)
PASSWORD=WrongPassword123
for user in "${USERS[@]}"; do
  for attempt in {1..5}; do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST "$TARGET" -d "username=$user&password=$PASSWORD"
    sleep 1
  done
done
echo "Completed simulated brute force"
