#pragma once

// ============================================================================
// FROST Protocol Operations (Curve-Agnostic)
// ============================================================================
//
// This module implements the FROST (Flexible Round-Optimized Schnorr Threshold)
// signature scheme operations that are independent of the underlying curve.
//
// Compatible with fy library (github.com/f3rmion/fy) Blake2bHasher.
// Uses Blake2b-512 with domain separation prefix "FROST-EDBABYJUJUB-BLAKE512-v1"
//
// All operations use the curve abstraction layer defined in curve.h.
// ============================================================================

#include <stdint.h>
#include <stdbool.h>
#include "curve.h"

// Maximum participants supported
#define MAX_PARTICIPANTS 16

// Commitment entry size: ID (32) + Hiding (32) + Binding (32)
#define COMMITMENT_ENTRY_SIZE 96

// Domain separation prefix (fy Blake2bHasher compatible)
#define FROST_DOMAIN_PREFIX "FROST-EDBABYJUJUB-BLAKE512-v1"

// ============================================================================
// Commitment Encoding (fy-compatible)
// ============================================================================

// Encode commitment list for hashing
// Format: For each participant: ID (32 bytes) || HidingPoint (32) || BindingPoint (32)
// Returns the encoded length
uint16_t frost_encode_commitments(uint8_t *output,
                                  const uint8_t *commitment_list,
                                  uint8_t num_participants);

// ============================================================================
// FROST Hash Functions (fy Blake2bHasher compatible)
// ============================================================================

// H1: Compute per-participant binding factor
// binding_factor = Blake2b(prefix || "rho" || message || encCommitList || signerID) mod order
// Output interpreted as little-endian before reducing
void frost_compute_binding_factor(uint8_t result[CURVE_SCALAR_SIZE],
                                  const uint8_t *message_hash,
                                  const uint8_t *enc_commit_list,
                                  uint16_t enc_commit_list_len,
                                  const uint8_t *signer_id);

// H2: Compute FROST challenge
// challenge = Blake2b(prefix || "chal" || R || Y || message) mod order
// Output interpreted as little-endian before reducing
void frost_compute_challenge(uint8_t result[CURVE_SCALAR_SIZE],
                             const uint8_t *group_commitment,
                             const uint8_t *group_pubkey,
                             const uint8_t *message_hash);

// ============================================================================
// Group Commitment Computation
// ============================================================================

// Compute group commitment R from individual commitments and binding factors
// R = sum(HidingPoint_i + rho_i * BindingPoint_i) for all participants
bool frost_compute_group_commitment(uint8_t result[CURVE_POINT_SIZE],
                                    const uint8_t *commitment_list,
                                    const uint8_t *binding_factors,
                                    uint8_t num_participants);

// ============================================================================
// Partial Signature Computation
// ============================================================================

// Compute partial signature
// z_i = hiding_nonce + (binding_nonce * binding_factor) + (secret * challenge * lambda_i)
bool frost_compute_partial_sig(uint8_t result[CURVE_SCALAR_SIZE],
                               const uint8_t *hiding_nonce,
                               const uint8_t *binding_nonce,
                               const uint8_t *binding_factor,
                               const uint8_t *secret_share,
                               const uint8_t *challenge,
                               uint16_t identifier,
                               const uint16_t *participant_ids,
                               uint8_t num_participants);
