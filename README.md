# FROSTGUARD Ledger App

FROST threshold signatures for Baby Jubjub curve on Ledger hardware wallets.

## Overview

This Ledger app enables secure storage of FROST key shares and performs threshold signing operations. The private key share never leaves the secure element.

## Features

- Secure storage of FROST key shares in NVRAM
- Hardware RNG for nonce generation (critical for FROST security)
- User confirmation for key injection and signing
- Automatic nonce clearing after signing

## APDU Commands

| INS | Command | Description |
|-----|---------|-------------|
| 0x00 | GET_VERSION | Get app version |
| 0x01 | GET_PUBLIC_KEY | Get group public key |
| 0x19 | INJECT_KEYS | Store FROST key share |
| 0x1A | COMMIT | Generate nonces, return commitments |
| 0x1B | INJECT_MESSAGE | Set message hash to sign |
| 0x1C | INJECT_COMMITMENTS_P1 | Send commitment list (part 1) |
| 0x1D | INJECT_COMMITMENTS_P2 | Send commitment list (part 2) |
| 0x1E | PARTIAL_SIGN | Compute partial signature |
| 0x1F | RESET | Clear signing state |

## Building

### Prerequisites

- Docker (recommended)
- Or: Ledger SDK and ARM toolchain

### Using Docker (recommended)

```bash
# Pull the dev tools image
docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest

# Build for Nano S+
docker run --rm -v $(pwd):/app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest \
  bash -c "cd /app && make"

# Build for specific target
docker run --rm -v $(pwd):/app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest \
  bash -c "cd /app && make TARGET=nanox"
```

### Targets

- `nanos2` - Nano S+ (default)
- `nanox` - Nano X
- `stax` - Stax
- `flex` - Flex

## Testing with Speculos

Speculos is Ledger's official emulator - test without physical hardware.

### Quick Start

```bash
# 1. Build the app
docker run --rm -v $(pwd):/app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest \
  bash -c "cd /app && make"

# 2. Run in Speculos emulator
docker run --rm -it -v $(pwd):/app -p 5000:5000 -p 9999:9999 \
  ghcr.io/ledgerhq/speculos \
  --model nanosp /app/bin/app.elf

# 3. Open http://localhost:5000 in browser to see virtual Ledger screen
# 4. Send APDUs to localhost:9999
```

### Speculos Ports

| Port | Purpose |
|------|---------|
| 5000 | Web UI - virtual device screen with buttons |
| 9999 | APDU TCP - send commands programmatically |

### Send Test APDUs

```bash
# Get version (INS=0x00)
echo "E000000000" | nc localhost 9999 | xxd

# Using Python
python3 -c "
import socket
s = socket.socket()
s.connect(('localhost', 9999))
s.send(bytes.fromhex('E000000000'))
print(s.recv(100).hex())
"
```

### Debug Output

Build with `DEBUG=1` to see printf statements:

```bash
docker run --rm -v $(pwd):/app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest \
  bash -c "cd /app && make DEBUG=1"
```

## Loading to Device

```bash
# Linux (requires udev rules)
make load

# Or use Ledger Live developer mode
```

## Security Model

### Key Injection

After distributed key generation (DKG), the host sends the key share to the Ledger via `INJECT_KEYS`. This is the only time the secret touches the host.

**Important:** The Ledger requires user confirmation before storing keys.

### Nonce Security

FROST security depends on fresh, random nonces for each signing session. This app:

1. Generates nonces using the secure element's hardware RNG
2. Never exposes nonces - only commitments are returned
3. Clears nonces immediately after `PARTIAL_SIGN` or on error
4. Rejects signing if state machine is violated

### State Machine

```
IDLE -> [COMMIT] -> COMMITTED -> [INJECT_MESSAGE] -> MESSAGE_SET
     -> [INJECT_COMMITMENTS] -> COMMITMENTS_SET -> [PARTIAL_SIGN] -> IDLE
```

Any error or `RESET` command returns to IDLE and clears nonces.

## Project Structure

```
ledger-app-frost/
├── Makefile              # Build configuration
├── ledger_app.toml       # App manifest
├── src/
│   ├── main.c            # Entry point, APDU dispatcher
│   ├── globals.h         # Global declarations
│   ├── handler.h/c       # APDU command handlers
│   ├── frost_storage.h/c # NVRAM storage
│   ├── bjj.h/c           # Baby Jubjub crypto
│   ├── ui.h/c            # User interface
│   └── glyphs.h          # Icon declarations
├── glyphs/               # App icons (GIF format)
└── tests/                # Functional tests
```

## License

MIT
