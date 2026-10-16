#!/usr/bin/env bash
set -euo pipefail
# P0 gate: prove a backup actually restores.
# 1. In the SN app: Preferences > Backups > download an ENCRYPTED and a DECRYPTED export.
# 2. Import the ENCRYPTED backup into a fresh account on the Docker server via the
#    desktop app (Account > Advanced > Sync Server = http://localhost:3000; supply
#    the backup's ORIGINAL password when importing).
# 3. Run this against the DECRYPTED export to confirm the restore is complete and faithful.
#
# Usage: SN_EMAIL=.. SN_PASSWORD=.. ./ops/backup/verify_restore.sh path/to/decrypted-export.txt
export SN_SERVER="${SN_SERVER:-http://localhost:3000}"
go run ./cmd/sn-verify "$1"
