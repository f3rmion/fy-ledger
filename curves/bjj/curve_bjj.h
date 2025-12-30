#pragma once

// ============================================================================
// Baby Jubjub Curve Implementation
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
// This implementation uses 32-byte compressed points (Y coordinate + sign bit)
// compatible with gnark-crypto's Baby Jubjub implementation.
// ============================================================================

#include <stdint.h>
#include <stdbool.h>

// Curve identifier
#define CURVE_ID  0x00

// Baby Jubjub scalar field order (big-endian)
extern const uint8_t CURVE_ORDER[32];

// Baby Jubjub generator point (compressed, 32 bytes)
extern const uint8_t CURVE_GENERATOR[32];

// ============================================================================
// Point Operations (32-byte compressed points)
// ============================================================================

// Scalar multiplication: result = scalar * point
// All points are 32-byte compressed format
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

// Reduce scalar modulo order (32-byte input)
void curve_scalar_reduce(uint8_t result[32],
                         const uint8_t value[32]);

// Reduce 64-byte value modulo order (for hash outputs)
void curve_scalar_reduce_64(uint8_t result[32],
                            const uint8_t value[64]);

// ============================================================================
// Compression/Decompression (internal use)
// ============================================================================

// Compress 64-byte point to 32-byte format
// Uses gnark-crypto compatible format: Y with sign bit in MSB
void bjj_compress(uint8_t out[32], const uint8_t point[64]);

// Decompress 32-byte point to 64-byte format
// Returns false if point is invalid
bool bjj_decompress(uint8_t point[64], const uint8_t compressed[32]);
