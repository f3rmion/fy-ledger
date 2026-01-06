#!/bin/bash
# Run Speculos emulator for testing the FROST Ledger app
#
# Usage:
#   ./simulate.sh          # Run with default binary
#   ./simulate.sh path/to/app.elf  # Run with specific binary

set -e

# Default to built binary
APP_ELF="${1:-bin/app.elf}"
MODEL="${2:-nanos2}"  # nanos2 = Nano S Plus

if [ ! -f "$APP_ELF" ]; then
    echo "Error: App binary not found: $APP_ELF"
    echo ""
    echo "Build the app first:"
    echo "  ./build.sh"
    echo ""
    echo "Or specify the path to your .elf file:"
    echo "  ./simulate.sh path/to/app.elf"
    exit 1
fi

echo "Starting Speculos emulator..."
echo "  App: $APP_ELF"
echo "  Model: $MODEL"
echo ""
echo "The emulator will:"
echo "  - Display UI at http://localhost:5000"
echo "  - Accept APDU via TCP on port 9999"
echo ""
echo "Press Ctrl+C to stop."
echo ""

# Run Speculos in Docker
docker run --rm -it \
    -v "$(pwd):/app" \
    -p 5000:5000 \
    -p 9999:9999 \
    ghcr.io/ledgerhq/speculos:latest \
    --model "$MODEL" \
    --display headless \
    --apdu-port 9999 \
    "/app/$APP_ELF"
