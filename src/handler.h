#pragma once

#include <stdint.h>

// ============================================================================
// APDU Constants
// ============================================================================

// Class byte
#define CLA_DEFAULT                     0xE0

// Instruction bytes (matching Go implementation)
#define INS_GET_VERSION                 0x00
#define INS_GET_PUBLIC_KEY              0x01
#define INS_FROST_INJECT_KEYS           0x19
#define INS_FROST_COMMIT                0x1A
#define INS_FROST_INJECT_MESSAGE        0x1B
#define INS_FROST_INJECT_COMMITMENTS_P1 0x1C
#define INS_FROST_INJECT_COMMITMENTS_P2 0x1D
#define INS_FROST_PARTIAL_SIGN          0x1E
#define INS_FROST_RESET                 0x1F

// Curve identifier is defined in curve.h as CURVE_ID

// Status words
#define SW_OK                           0x9000
#define SW_WRONG_LENGTH                 0x6700
#define SW_WRONG_P1P2                   0x6A86
#define SW_CONDITIONS_NOT_SAT           0x6985
#define SW_INVALID_DATA                 0x6A80
#define SW_INS_NOT_SUPPORTED            0x6D00
#define SW_CLA_NOT_SUPPORTED            0x6E00
#define SW_USER_REJECTED                0x6985
#define SW_INTERNAL_ERROR               0x6F00

// ============================================================================
// Handler Functions
// ============================================================================

// Get app version
// P1: 0x00
// P2: 0x00
// Response: major (1) || minor (1) || patch (1)
uint16_t handle_get_version(uint8_t *response, uint8_t *response_len);

// Get group public key (if keys are loaded)
// P1: 0x00
// P2: 0x00
// Response: group_public_key (32, compressed)
uint16_t handle_get_public_key(uint8_t *response, uint8_t *response_len);

// Inject FROST keys
// P1: curve_id (must match CURVE_ID)
// P2: 0x00
// Data: group_pubkey (32) || identifier (32) || secret_key (32) = 96 bytes
// Response: none
uint16_t handle_inject_keys(uint8_t p1, uint8_t p2,
                            uint8_t *data, uint8_t data_len,
                            uint8_t *response, uint8_t *response_len);

// Generate FROST commitment
// P1: 0x00
// P2: 0x00
// Response: hiding_commit (32) || binding_commit (32) = 64 bytes
uint16_t handle_commit(uint8_t *response, uint8_t *response_len);

// Inject message hash to sign
// P1: 0x00
// P2: 0x00
// Data: message_hash (32)
// Response: none
uint16_t handle_inject_message(uint8_t *data, uint8_t data_len);

// Inject commitment list (part 1)
// P1: num_participants
// P2: 0x00
// Data: first 240 bytes of commitment list
// Response: bytes_received (2)
uint16_t handle_inject_commitments_p1(uint8_t p1,
                                      uint8_t *data, uint8_t data_len,
                                      uint8_t *response, uint8_t *response_len);

// Inject commitment list (part 2)
// P1: 0x00
// P2: 0x00
// Data: remaining bytes of commitment list
// Response: bytes_received (2)
uint16_t handle_inject_commitments_p2(uint8_t *data, uint8_t data_len,
                                      uint8_t *response, uint8_t *response_len);

// Compute partial signature
// P1: 0x00
// P2: 0x00
// Response: partial_sig (32)
uint16_t handle_partial_sign(uint8_t *response, uint8_t *response_len);

// Reset FROST state
// P1: 0x00
// P2: 0x00
// Response: none
uint16_t handle_reset(void);
