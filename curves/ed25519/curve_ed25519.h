#pragma once

// ============================================================================
// Ed25519 Curve Implementation
// ============================================================================
//
// Ed25519 is a twisted Edwards curve used for fast signatures.
// This implementation uses Ledger SDK's native cx_ecfp_* APIs.
//
// Curve equation: -x^2 + y^2 = 1 + d*x^2*y^2
// where d = -121665/121666
//
// Base field: F_p where p = 2^255 - 19
// Scalar field order: 2^252 + 27742317777372353535851937790883648493
//
// Ed25519 natively uses 32-byte compressed points (Y with sign bit).
// ============================================================================

#include <stdint.h>
#include <stdbool.h>

// Curve identifier
#define CURVE_ID  0x01

// Ed25519 scalar field order (big-endian)
extern const uint8_t CURVE_ORDER[32];

// Ed25519 generator point (compressed, 32 bytes)
extern const uint8_t CURVE_GENERATOR[32];

// ============================================================================
// Point Operations (32-byte compressed points)
// ============================================================================

// Scalar multiplication: result = scalar * point
bool curve_scalar_mult(uint8_t result[32],
                       const uint8_t scalar[32],
                       const uint8_t point[32]);

// Base point multiplication: result = scalar * G
bool curve_base_mult(uint8_t result[32],
                     const uint8_t scalar[32]);

// Point addition: result = p1 + p2
bool curve_point_add(uint8_t result[32],
                     const uint8_t p1[32],
                     const uint8_t p2[32]);

// Check if compressed point is valid
bool curve_is_valid_point(const uint8_t point[32]);

// ============================================================================
// Scalar Operations (mod subgroup order)
// ============================================================================

// Scalar addition: result = (a + b) mod order
void curve_scalar_add(uint8_t result[32],
                      const uint8_t a[32],
                      const uint8_t b[32]);

// Scalar multiplication: result = (a * b) mod order
void curve_scalar_mul(uint8_t result[32],
                      const uint8_t a[32],
                      const uint8_t b[32]);

// Reduce scalar modulo order
void curve_scalar_reduce(uint8_t result[32],
                         const uint8_t value[32]);
