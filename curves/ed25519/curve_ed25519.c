#include "curve_ed25519.h"
#include "os.h"
#include "cx.h"
#include <string.h>

// ============================================================================
// Ed25519 Constants
// ============================================================================

// Scalar field order (big-endian)
// 2^252 + 27742317777372353535851937790883648493
const uint8_t CURVE_ORDER[32] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
    0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
};

// Generator point (compressed, 32 bytes)
// This is the standard Ed25519 base point in compressed form
const uint8_t CURVE_GENERATOR[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

// ============================================================================
// Internal: Convert between compressed (32 bytes) and SDK format (65 bytes)
// ============================================================================

// Ledger SDK uses 65-byte uncompressed format: 0x04 || X (32) || Y (32)
// Ed25519 compressed format: Y with sign bit in MSB

static bool decompress_point(uint8_t out[65], const uint8_t compressed[32]) {
    cx_ecfp_public_key_t pub;

    // Use SDK to decompress the point
    // cx_ecfp_init_public_key expects compressed format for Ed25519
    if (cx_ecfp_init_public_key_no_throw(CX_CURVE_Ed25519,
                                          compressed, 32,
                                          &pub) != CX_OK) {
        return false;
    }

    // Copy the uncompressed point (65 bytes: 04 || X || Y)
    memcpy(out, pub.W, 65);
    return true;
}

static void compress_point(uint8_t out[32], const uint8_t uncompressed[65]) {
    // For Ed25519, compressed = Y with sign bit of X in MSB
    // Y is bytes 33-64 in uncompressed format (after 04 || X)
    memcpy(out, uncompressed + 33, 32);

    // Set sign bit based on X coordinate (bytes 1-32)
    // If X is odd (LSB set), set sign bit in Y
    if (uncompressed[32] & 0x01) {
        out[31] |= 0x80;
    }
}

// ============================================================================
// Point Operations
// ============================================================================

bool curve_scalar_mult(uint8_t result[32],
                       const uint8_t scalar[32],
                       const uint8_t point[32]) {
    uint8_t uncompressed[65];
    uint8_t result_uncompressed[65];

    // Decompress input point
    if (!decompress_point(uncompressed, point)) {
        return false;
    }

    // Copy for in-place multiplication
    memcpy(result_uncompressed, uncompressed, 65);

    // Perform scalar multiplication
    if (cx_ecfp_scalar_mult_no_throw(CX_CURVE_Ed25519,
                                      result_uncompressed,
                                      scalar, 32) != CX_OK) {
        return false;
    }

    // Compress result
    compress_point(result, result_uncompressed);
    return true;
}

bool curve_base_mult(uint8_t result[32],
                     const uint8_t scalar[32]) {
    cx_ecfp_public_key_t pub;
    cx_ecfp_private_key_t priv;

    // Initialize private key with scalar
    if (cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519,
                                           scalar, 32,
                                           &priv) != CX_OK) {
        return false;
    }

    // Generate public key (scalar * G)
    if (cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519,
                                        &pub, &priv, 1) != CX_OK) {
        explicit_bzero(&priv, sizeof(priv));
        return false;
    }

    // Clear private key
    explicit_bzero(&priv, sizeof(priv));

    // Compress result
    compress_point(result, pub.W);
    return true;
}

bool curve_point_add(uint8_t result[32],
                     const uint8_t p1[32],
                     const uint8_t p2[32]) {
    uint8_t p1_uncompressed[65];
    uint8_t p2_uncompressed[65];
    uint8_t result_uncompressed[65];

    // Decompress both points
    if (!decompress_point(p1_uncompressed, p1)) {
        return false;
    }
    if (!decompress_point(p2_uncompressed, p2)) {
        return false;
    }

    // Copy p1 for in-place addition
    memcpy(result_uncompressed, p1_uncompressed, 65);

    // Perform point addition
    if (cx_ecfp_add_point_no_throw(CX_CURVE_Ed25519,
                                    result_uncompressed,
                                    p1_uncompressed,
                                    p2_uncompressed) != CX_OK) {
        return false;
    }

    // Compress result
    compress_point(result, result_uncompressed);
    return true;
}

bool curve_is_valid_point(const uint8_t point[32]) {
    uint8_t uncompressed[65];
    return decompress_point(uncompressed, point);
}

// ============================================================================
// Scalar Operations
// ============================================================================

void curve_scalar_add(uint8_t result[32],
                      const uint8_t a[32],
                      const uint8_t b[32]) {
    cx_bn_t bn_a, bn_b, bn_r, bn_order;

    cx_bn_lock(32, 0);

    cx_bn_alloc(&bn_a, 32);
    cx_bn_alloc(&bn_b, 32);
    cx_bn_alloc(&bn_r, 32);
    cx_bn_alloc(&bn_order, 32);

    cx_bn_init(bn_a, a, 32);
    cx_bn_init(bn_b, b, 32);
    cx_bn_init(bn_order, CURVE_ORDER, 32);

    cx_bn_mod_add(bn_r, bn_a, bn_b, bn_order);

    cx_bn_export(bn_r, result, 32);

    cx_bn_destroy(&bn_a);
    cx_bn_destroy(&bn_b);
    cx_bn_destroy(&bn_r);
    cx_bn_destroy(&bn_order);

    cx_bn_unlock();
}

void curve_scalar_mul(uint8_t result[32],
                      const uint8_t a[32],
                      const uint8_t b[32]) {
    cx_bn_t bn_a, bn_b, bn_r, bn_order;

    cx_bn_lock(32, 0);

    cx_bn_alloc(&bn_a, 32);
    cx_bn_alloc(&bn_b, 32);
    cx_bn_alloc(&bn_r, 32);
    cx_bn_alloc(&bn_order, 32);

    cx_bn_init(bn_a, a, 32);
    cx_bn_init(bn_b, b, 32);
    cx_bn_init(bn_order, CURVE_ORDER, 32);

    cx_bn_mod_mul(bn_r, bn_a, bn_b, bn_order);

    cx_bn_export(bn_r, result, 32);

    cx_bn_destroy(&bn_a);
    cx_bn_destroy(&bn_b);
    cx_bn_destroy(&bn_r);
    cx_bn_destroy(&bn_order);

    cx_bn_unlock();
}

void curve_scalar_reduce(uint8_t result[32],
                         const uint8_t value[32]) {
    cx_bn_t bn_v, bn_r, bn_order;

    cx_bn_lock(32, 0);

    cx_bn_alloc(&bn_v, 32);
    cx_bn_alloc(&bn_r, 32);
    cx_bn_alloc(&bn_order, 32);

    cx_bn_init(bn_v, value, 32);
    cx_bn_init(bn_order, CURVE_ORDER, 32);

    cx_bn_reduce(bn_r, bn_v, bn_order);

    cx_bn_export(bn_r, result, 32);

    cx_bn_destroy(&bn_v);
    cx_bn_destroy(&bn_r);
    cx_bn_destroy(&bn_order);

    cx_bn_unlock();
}
