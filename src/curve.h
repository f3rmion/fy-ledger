#pragma once

// ============================================================================
// Curve Abstraction Layer
// ============================================================================
//
// This header provides a compile-time curve selection mechanism.
// Build with -DCURVE_BJJ or -DCURVE_ED25519 to select the curve.
//
// All curves use uniform 32-byte compressed point format.
// ============================================================================

#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Compile-time Curve Selection
// ============================================================================

#if defined(CURVE_BJJ)
    #include "curve_bjj.h"
#elif defined(CURVE_ED25519)
    #include "curve_ed25519.h"
#else
    // Default to BJJ for backwards compatibility
    #define CURVE_BJJ
    #include "curve_bjj.h"
#endif

// ============================================================================
// Uniform Sizes (all curves use 32-byte compressed points)
// ============================================================================

#define CURVE_POINT_SIZE   32   // Compressed point
#define CURVE_SCALAR_SIZE  32   // Scalar field element

// ============================================================================
// Curve Interface
// ============================================================================
//
// Each curve implementation must provide:
//
// Constants:
//   CURVE_ID              - Curve identifier (0x00 = BJJ, 0x01 = Ed25519)
//   CURVE_ORDER[32]       - Scalar field order (big-endian)
//   CURVE_GENERATOR[32]   - Generator point (compressed)
//
// Point Operations (all use 32-byte compressed points):
//   bool curve_scalar_mult(uint8_t result[32], const uint8_t scalar[32], const uint8_t point[32]);
//   bool curve_base_mult(uint8_t result[32], const uint8_t scalar[32]);
//   bool curve_point_add(uint8_t result[32], const uint8_t p1[32], const uint8_t p2[32]);
//   bool curve_is_valid_point(const uint8_t point[32]);
//
// Scalar Operations:
//   void curve_scalar_add(uint8_t result[32], const uint8_t a[32], const uint8_t b[32]);
//   void curve_scalar_mul(uint8_t result[32], const uint8_t a[32], const uint8_t b[32]);
//   void curve_scalar_reduce(uint8_t result[32], const uint8_t value[32]);
//
// ============================================================================
