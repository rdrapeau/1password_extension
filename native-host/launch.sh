#!/bin/bash
# Launcher script for the OPVault native messaging host.
# Firefox calls this executable, which starts the Node.js host process.

DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="/tmp/opvault-host.log"

echo "$(date): launch.sh started" >> "$LOG"
echo "$(date): DIR=$DIR" >> "$LOG"
echo "$(date): node=$(/opt/homebrew/bin/node --version 2>&1)" >> "$LOG"
echo "$(date): argv=$@" >> "$LOG"

# Run node and capture ALL output (stdout goes to Firefox, stderr to log)
/opt/homebrew/bin/node "$DIR/host.mjs" 2>> "$LOG"
EXIT_CODE=$?
echo "$(date): node exited with code $EXIT_CODE" >> "$LOG"
