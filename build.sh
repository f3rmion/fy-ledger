#!/bin/bash
# Build script for FROST Ledger App

set -e

CURVE="${1:-BJJ}"
IMAGE="ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest"

echo "Building FROST app for curve: ${CURVE}"
echo "Using image: ${IMAGE}"
echo ""

docker run --rm \
    -v "$(pwd):/app" \
    -w /app \
    "${IMAGE}" \
    make CURVE="${CURVE}"

echo ""
echo "Build complete!"
echo "Binary located in: bin/"
