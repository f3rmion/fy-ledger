#pragma once

#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Baby Jubjub Curve Parameters
// ============================================================================
//
// Baby Jubjub is a twisted Edwards curve defined over the BN254 scalar field.
//
// Curve equation: a*x^2 + y^2 = 1 + d*x^2*y^2
// where:
//   a = 168700
//   d = 168696
//
// Base field: F_p where p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// Scalar field order: 2736030358979909402780800718157159386076813972158567259200215660948447373041
//
// Generator point G:
//   x = 5299619240641551281634865583518297030282874472190772894086521144482721001553
//   y = 16950150798460657717958625567821834550301663161624707787222815936182638968203
//
// ============================================================================

#define BJJ_POINT_BYTES   64  // Uncompressed point: x (32 bytes) || y (32 bytes)
#define BJJ_SCALAR_BYTES  32  // Scalar field element

// Baby Jubjub scalar field order (big-endian for Ledger SDK)
extern const uint8_t BJJ_ORDER[32];

// Baby Jubjub generator point (big-endian, uncompressed: x || y)
extern const uint8_t BJJ_GENERATOR[64];

// ============================================================================
// Point Operations
// ============================================================================

// Scalar multiplication: result = scalar * point
// Returns true on success, false if point is invalid
bool bjj_scalar_mult(uint8_t result[BJJ_POINT_BYTES],
                     const uint8_t scalar[BJJ_SCALAR_BYTES],
                     const uint8_t point[BJJ_POINT_BYTES]);

// Base point multiplication: result = scalar * G
// More efficient than general scalar_mult
bool bjj_base_mult(uint8_t result[BJJ_POINT_BYTES],
                   const uint8_t scalar[BJJ_SCALAR_BYTES]);

// Point addition: result = p1 + p2
bool bjj_point_add(uint8_t result[BJJ_POINT_BYTES],
                   const uint8_t p1[BJJ_POINT_BYTES],
                   const uint8_t p2[BJJ_POINT_BYTES]);

// Check if point is on curve
bool bjj_is_on_curve(const uint8_t point[BJJ_POINT_BYTES]);

// ============================================================================
// Scalar Operations
// ============================================================================

// Scalar addition: result = (a + b) mod order
void bjj_scalar_add(uint8_t result[BJJ_SCALAR_BYTES],
                    const uint8_t a[BJJ_SCALAR_BYTES],
                    const uint8_t b[BJJ_SCALAR_BYTES]);

// Scalar multiplication: result = (a * b) mod order
void bjj_scalar_mul(uint8_t result[BJJ_SCALAR_BYTES],
                    const uint8_t a[BJJ_SCALAR_BYTES],
                    const uint8_t b[BJJ_SCALAR_BYTES]);

// Reduce scalar modulo order
void bjj_scalar_reduce(uint8_t result[BJJ_SCALAR_BYTES],
                       const uint8_t value[BJJ_SCALAR_BYTES]);

// ============================================================================
// FROST-specific Operations
// ============================================================================

// Compute binding factor for FROST
// binding_factor = H(group_pubkey || commitment_list || message)
void bjj_compute_binding_factor(uint8_t result[BJJ_SCALAR_BYTES],
                                const uint8_t *group_pubkey,
                                const uint8_t *commitment_list,
                                uint16_t commitment_list_len,
                                const uint8_t *message_hash);

// Compute FROST challenge
// challenge = H(group_commitment || group_pubkey || message)
void bjj_compute_challenge(uint8_t result[BJJ_SCALAR_BYTES],
                           const uint8_t *group_commitment,
                           const uint8_t *group_pubkey,
                           const uint8_t *message_hash);

// Compute partial signature
// z_i = hiding_nonce + (binding_nonce * binding_factor) + (secret * challenge * lambda_i)
bool bjj_compute_partial_sig(uint8_t result[BJJ_SCALAR_BYTES],
                             const uint8_t *hiding_nonce,
                             const uint8_t *binding_nonce,
                             const uint8_t *binding_factor,
                             const uint8_t *secret_share,
                             const uint8_t *challenge,
                             uint16_t identifier,
                             const uint16_t *participant_ids,
                             uint8_t num_participants);
