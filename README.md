# fy-ledger

FROST threshold signatures for Baby Jubjub curve on Ledger hardware wallets. Compatible with [gnark-crypto](https://github.com/consensys/gnark-crypto) and the [fy](https://github.com/f3rmion/fy) FROST library.

## Overview

This Ledger app enables secure storage of FROST key shares and performs threshold signing operations. The private key share never leaves the secure element.

## Features

- Secure storage of FROST key shares in NVRAM
- Hardware RNG for nonce generation (critical for FROST security)
- User confirmation for key injection and signing
- Automatic nonce clearing after signing
- Compatible with gnark-crypto's Baby Jubjub twisted Edwards curve
- Blake2b-512 hashing with fy-compatible domain separation

## Curve Support

Currently supports Baby Jubjub (BJJ) curve using gnark-crypto's twisted Edwards form:
- Base field: BN254 Fr (prime ~254 bits)
- Curve equation: `a*x² + y² = 1 + d*x²*y²` where `a = -1 mod p`
- Point compression: Little-endian Y with sign bit in MSB of last byte

## FROST Protocol

This implementation follows the FROST protocol with fy-compatible hashing:

| Hash Function | Domain Tag | Purpose |
|---------------|------------|---------|
| H1 (rho) | `FROST-EDBABYJUJUB-BLAKE512-v1` + `rho` | Binding factor |
| H2 (chal) | `FROST-EDBABYJUJUB-BLAKE512-v1` + `chal` | Challenge |

All hashes use Blake2b-512, interpreted as little-endian and reduced mod curve order.

## APDU Commands

| INS | Command | Description |
|-----|---------|-------------|
| 0x00 | GET_VERSION | Get app version |
| 0x01 | GET_PUBLIC_KEY | Get group public key (32 bytes compressed) |
| 0x19 | INJECT_KEYS | Store FROST key share |
| 0x1A | COMMIT | Generate nonces, return commitments |
| 0x1B | INJECT_MESSAGE | Set message hash to sign |
| 0x1C | INJECT_COMMITMENTS | Send commitment list |
| 0x1E | PARTIAL_SIGN | Compute partial signature |
| 0x1F | RESET | Clear signing state |

### Data Formats

**INJECT_KEYS (0x19):**
- P1: Curve ID (0x00 = BJJ)
- Data: `group_pubkey[32] || participant_id[32] || secret_share[32]`

**COMMIT (0x1A):**
- Returns: `hiding_commitment[32] || binding_commitment[32]`

**INJECT_COMMITMENTS (0x1C):**
- P1: Number of participants
- Data: For each participant: `id[32] || hiding[32] || binding[32]`

**PARTIAL_SIGN (0x1E):**
- Returns: `partial_signature[32]`

## Building

### Prerequisites

- Docker

### Build Script

```bash
# Build for Baby Jubjub (default)
./build.sh BJJ

# Output: bin/app.elf
```

### Manual Build

```bash
docker run --rm -v $(pwd):/app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest \
  bash -c "cd /app && make CURVE=BJJ"
```

## Testing with Speculos

Speculos is Ledger's official emulator.

### Quick Start

```bash
# 1. Build the app
./build.sh BJJ

# 2. Run in Speculos emulator
docker run --rm -d \
  -v $(pwd)/bin:/app \
  -p 5001:5001 -p 9999:9999 \
  ghcr.io/ledgerhq/speculos:latest \
  /app/app.elf --model nanosp \
  --seed "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --display headless --apdu-port 9999 --api-port 5001

# 3. Run the 2-of-3 FROST test
cd scripts && python3 test-2of3.py
```

### Expected Output

```
======================================================================
FROST 2-of-3 Signing: Ledger + Software Participant
======================================================================
...
[11] Verifying aggregated signature...
    SIGNATURE VALID!
======================================================================
2-of-3 FROST signing completed successfully!
======================================================================
```

## Integration with fy Library

Generate FROST key shares using the fy library's DKG, then inject into Ledger:

```go
package main

import (
    "github.com/f3rmion/fy/bjj"
    "github.com/f3rmion/fy/frost"
)

func main() {
    g := &bjj.BJJ{}

    // Run DKG for 2-of-3
    shares, groupPubKey := frost.KeyGen(g, 2, 3)

    // Share 1 goes to Ledger via INJECT_KEYS APDU
    // Shares 2,3 can be software participants or other Ledgers
}
```

See `scripts/keygen/` for the full Go helper and `scripts/test-2of3.py` for the Python test harness.

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
fy-ledger/
├── build.sh              # Build script
├── Makefile              # Build configuration
├── ledger_app.toml       # App manifest
├── src/
│   ├── main.c            # Entry point, APDU dispatcher
│   ├── globals.h         # Global declarations
│   ├── handler.h/c       # APDU command handlers
│   ├── frost_storage.h/c # NVRAM storage
│   ├── frost.h/c         # FROST protocol operations
│   ├── curve.h           # Curve abstraction
│   └── ui.h/c            # User interface
├── curves/
│   └── bjj/
│       ├── curve_bjj.h   # BJJ curve interface
│       └── curve_bjj.c   # BJJ implementation (gnark-crypto compatible)
├── scripts/
│   ├── test-2of3.py      # FROST 2-of-3 integration test
│   └── keygen/           # Go helper for key generation
└── glyphs/               # App icons
```

## License

MIT
