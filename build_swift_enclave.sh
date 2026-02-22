#!/bin/bash
set -e

CERT_NAME="Apple Development"
PROJECT_DIR="$(pwd)"
DIST_DIR="$PROJECT_DIR/dist"
SWIFT_BIN="$DIST_DIR/swift_enclave"

echo "=== Swift Touch ID Prompt Builder ==="

# 1. Prepare distribution directory
mkdir -p "$DIST_DIR"

# 2. Compile the Swift binary
echo "[1] Compiling swift_enclave.swift..."
swiftc swift_enclave.swift -o "$SWIFT_BIN"

# 3. Sign it
echo "[2] Signing binary..."
codesign -f -s "$CERT_NAME" --timestamp --options runtime "$SWIFT_BIN"

echo "[3] Verifying signature..."
codesign -dv "$SWIFT_BIN"

echo "=== SUCCESS ==="
echo "Test with: ./dist/swift_enclave prompt 'Authenticate to test'"
