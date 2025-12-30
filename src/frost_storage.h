#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "os.h"
#include "curve.h"

// Identifier size (padded for commitment list)
#define IDENTIFIER_SIZE   32

// Maximum participants in FROST signing
#define MAX_PARTICIPANTS  15

// Commitment entry size: identifier (32) + hiding (32) + binding (32) = 96 bytes
#define COMMITMENT_ENTRY_SIZE  (IDENTIFIER_SIZE + CURVE_POINT_SIZE * 2)

// ============================================================================
// Persistent Storage (NVRAM)
// ============================================================================

// FROST key share stored in NVRAM
// Aligned to 64-byte page boundary for flash efficiency
typedef struct __attribute__((aligned(64))) {
    uint8_t  initialized;                         // 0x01 if keys are set
    uint8_t  curve_id;                            // Curve identifier
    uint16_t identifier;                          // FROST participant ID
    uint8_t  threshold;                           // Signing threshold (t)
    uint8_t  max_signers;                         // Total participants (n)
    uint8_t  _padding[26];                        // Alignment padding to 32 bytes
    uint8_t  group_public_key[CURVE_POINT_SIZE];  // 32 bytes (compressed)
    uint8_t  secret_share[CURVE_SCALAR_SIZE];     // 32 bytes - NEVER expose this!
} frost_storage_t;                                // Total: 96 bytes

// NVRAM storage declaration (N_ prefix required by Ledger SDK)
extern const frost_storage_t N_frost_real;
#define N_frost (*(volatile frost_storage_t *) PIC(&N_frost_real))

// ============================================================================
// Ephemeral Signing Context (RAM only)
// ============================================================================

// Signing state machine
typedef enum {
    FROST_STATE_IDLE = 0,
    FROST_STATE_COMMITTED,       // Nonces generated, commitments ready
    FROST_STATE_MESSAGE_SET,     // Message hash injected
    FROST_STATE_COMMITMENTS_SET, // All participant commitments received
    FROST_STATE_READY_TO_SIGN    // Ready for partial signature
} frost_state_t;

// Ephemeral signing context - cleared after each signing session
typedef struct {
    frost_state_t state;

    // Nonces - CRITICAL: must NEVER leave the device
    uint8_t hiding_nonce[CURVE_SCALAR_SIZE];
    uint8_t binding_nonce[CURVE_SCALAR_SIZE];

    // Our commitments (public values, safe to export)
    uint8_t hiding_commit[CURVE_POINT_SIZE];
    uint8_t binding_commit[CURVE_POINT_SIZE];

    // Message hash to sign
    uint8_t message_hash[CURVE_SCALAR_SIZE];

    // Commitment list from all participants
    uint8_t  num_participants;
    uint16_t commitment_bytes_received;
    uint8_t  commitment_list[MAX_PARTICIPANTS * COMMITMENT_ENTRY_SIZE];
} frost_ctx_t;

// RAM context declaration (G_ prefix for RAM globals)
extern frost_ctx_t G_frost_ctx;

// ============================================================================
// Storage Functions
// ============================================================================

// Initialize storage on app start
void frost_storage_init(void);

// Inject FROST key share (after DKG)
// Returns true on success
bool frost_inject_keys(uint8_t curve_id,
                       const uint8_t *group_pubkey,
                       uint16_t identifier,
                       const uint8_t *secret_share);

// Check if keys are loaded
bool frost_has_keys(void);

// Get participant identifier
uint16_t frost_get_identifier(void);

// Get group public key
const uint8_t *frost_get_group_pubkey(void);

// Clear all FROST keys from storage
void frost_clear_keys(void);

// ============================================================================
// Signing Context Functions
// ============================================================================

// Reset signing context to idle state
void frost_ctx_reset(void);

// Check current signing state
frost_state_t frost_ctx_get_state(void);
