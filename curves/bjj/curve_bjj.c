#include "curve_bjj.h"
#include "os.h"
#include "cx.h"
#include <string.h>

// ============================================================================
// Baby Jubjub Constants
// ============================================================================

// Baby Jubjub base field prime (BN254 Fr modulus)
static const uint8_t BJJ_PRIME[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01
};

// (p - 1) / 2 for sign bit check
static const uint8_t BJJ_HALF_PRIME[32] = {
    0x18, 0x32, 0x27, 0x39, 0x70, 0x98, 0xd0, 0x14,
    0xdc, 0x28, 0x22, 0xdb, 0x40, 0xc0, 0xac, 0x2e,
    0x94, 0x19, 0xf4, 0x24, 0x3c, 0xdc, 0xb8, 0x48,
    0xa1, 0xf0, 0xfa, 0xc9, 0xf8, 0x00, 0x00, 0x00
};

// Curve parameter a = -1 mod p (gnark-crypto twisted Edwards form)
static const uint8_t BJJ_A[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00
};

// Curve parameter d (gnark-crypto twisted Edwards form)
static const uint8_t BJJ_D[32] = {
    0x1a, 0xee, 0x90, 0xf1, 0x5f, 0x21, 0x89, 0x69,
    0x3d, 0xf0, 0x72, 0xd7, 0x99, 0xfd, 0x11, 0xfc,
    0x03, 0x9b, 0x29, 0x59, 0xeb, 0xb7, 0xc8, 0x67,
    0xd0, 0x75, 0xca, 0x8c, 0xf4, 0xd7, 0xeb, 0x8e
};

// Baby Jubjub scalar field order (from gnark-crypto)
const uint8_t CURVE_ORDER[32] = {
    0x06, 0x0c, 0x89, 0xce, 0x5c, 0x26, 0x34, 0x05,
    0x37, 0x0a, 0x08, 0xb6, 0xd0, 0x30, 0x2b, 0x0b,
    0xab, 0x3e, 0xed, 0xb8, 0x39, 0x20, 0xee, 0x0a,
    0x67, 0x72, 0x97, 0xdc, 0x39, 0x21, 0x26, 0xf1
};

// Generator point G (uncompressed, 64 bytes) - gnark-crypto compatible
static const uint8_t BJJ_GENERATOR_UNCOMPRESSED[64] = {
    // x coordinate
    0x15, 0x61, 0xff, 0x83, 0x6c, 0xe1, 0x9d, 0x35,
    0x8a, 0x4e, 0xb7, 0xa4, 0xc1, 0x99, 0xe9, 0x4c,
    0x37, 0x7c, 0x74, 0x9a, 0xe6, 0xf2, 0xa2, 0x77,
    0xf1, 0xf9, 0x19, 0x5a, 0xfe, 0x55, 0x3f, 0x9f,
    // y coordinate
    0x25, 0x79, 0x72, 0x03, 0xf7, 0xa0, 0xb2, 0x49,
    0x25, 0x57, 0x2e, 0x1c, 0xd1, 0x6b, 0xf9, 0xed,
    0xfc, 0xe0, 0x05, 0x1f, 0xb9, 0xe1, 0x33, 0x77,
    0x4b, 0x3c, 0x25, 0x7a, 0x87, 0x2d, 0x7d, 0x8b
};

// Generator point (compressed, 32 bytes) - gnark-crypto compatible
const uint8_t CURVE_GENERATOR[32] = {
    0x8b, 0x7d, 0x2d, 0x87, 0x7a, 0x25, 0x3c, 0x4b,
    0x77, 0x33, 0xe1, 0xb9, 0x1f, 0x05, 0xe0, 0xfc,
    0xed, 0xf9, 0x6b, 0xd1, 0x1c, 0x2e, 0x57, 0x25,
    0x49, 0xb2, 0xa0, 0xf7, 0x03, 0x72, 0x79, 0x25
};

// Identity point (0, 1) uncompressed
static const uint8_t BJJ_IDENTITY[64] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

// ============================================================================
// Internal Field Arithmetic Context
// ============================================================================

typedef struct {
    cx_bn_t p;
    cx_bn_t a;
    cx_bn_t d;
    cx_bn_t one;
} bjj_field_ctx_t;

static cx_err_t field_init(bjj_field_ctx_t *ctx) {
    cx_err_t err;

    err = cx_bn_lock(32, 0);
    if (err != CX_OK) return err;

    err = cx_bn_alloc(&ctx->p, 32);
    if (err != CX_OK) goto cleanup;
    err = cx_bn_alloc(&ctx->a, 32);
    if (err != CX_OK) goto cleanup;
    err = cx_bn_alloc(&ctx->d, 32);
    if (err != CX_OK) goto cleanup;
    err = cx_bn_alloc(&ctx->one, 32);
    if (err != CX_OK) goto cleanup;

    err = cx_bn_init(ctx->p, BJJ_PRIME, 32);
    if (err != CX_OK) goto cleanup;
    err = cx_bn_init(ctx->a, BJJ_A, 32);
    if (err != CX_OK) goto cleanup;
    err = cx_bn_init(ctx->d, BJJ_D, 32);
    if (err != CX_OK) goto cleanup;

    uint8_t one_bytes[32] = {0};
    one_bytes[31] = 1;
    err = cx_bn_init(ctx->one, one_bytes, 32);
    if (err != CX_OK) goto cleanup;

    return CX_OK;

cleanup:
    cx_bn_unlock();
    return err;
}

static void field_cleanup(bjj_field_ctx_t *ctx) {
    cx_bn_destroy(&ctx->p);
    cx_bn_destroy(&ctx->a);
    cx_bn_destroy(&ctx->d);
    cx_bn_destroy(&ctx->one);
    cx_bn_unlock();
}

// ============================================================================
// Point Compression/Decompression
// ============================================================================

// Check if X > (p-1)/2 (i.e., X is "lexicographically largest")
static bool is_x_largest(const uint8_t x[32]) {
    // Compare X with (p-1)/2
    for (int i = 0; i < 32; i++) {
        if (x[i] > BJJ_HALF_PRIME[i]) return true;
        if (x[i] < BJJ_HALF_PRIME[i]) return false;
    }
    return false;  // Equal means not largest
}

void bjj_compress(uint8_t out[32], const uint8_t point[64]) {
    // gnark-crypto format: Y in little-endian with sign bit in MSB of LAST byte
    // Reverse Y coordinate to little-endian
    for (int i = 0; i < 32; i++) {
        out[i] = point[32 + 31 - i];
    }

    // Set sign bit on byte[31] if X is largest
    if (is_x_largest(point)) {
        out[31] |= 0x80;
    }
}

bool bjj_decompress(uint8_t point[64], const uint8_t compressed[32]) {
    bjj_field_ctx_t ctx;
    cx_err_t err;
    bool success = false;

    // gnark-crypto format: Y stored in little-endian with sign bit in byte[31]'s MSB
    // Extract sign for sqrt selection from compressed[31]'s high bit
    uint8_t sign = (compressed[31] & 0x80) >> 7;

    // Reverse Y from little-endian to big-endian
    // Clear the sign bit from byte[31] before reversing
    uint8_t temp[32];
    memcpy(temp, compressed, 32);
    temp[31] &= 0x7F;  // Clear sign bit from last byte
    for (int i = 0; i < 32; i++) {
        point[32 + i] = temp[31 - i];
    }

    err = field_init(&ctx);
    if (err != CX_OK) return false;

    cx_bn_t y, y2, x2, num, den, x, tmp;

    if (cx_bn_alloc(&y, 32) != CX_OK) goto cleanup_ctx;
    if (cx_bn_alloc(&y2, 32) != CX_OK) goto cleanup_y;
    if (cx_bn_alloc(&x2, 32) != CX_OK) goto cleanup_y2;
    if (cx_bn_alloc(&num, 32) != CX_OK) goto cleanup_x2;
    if (cx_bn_alloc(&den, 32) != CX_OK) goto cleanup_num;
    if (cx_bn_alloc(&x, 32) != CX_OK) goto cleanup_den;
    if (cx_bn_alloc(&tmp, 32) != CX_OK) goto cleanup_x;

    // Load Y
    cx_bn_init(y, point + 32, 32);

    // y² = y * y
    cx_bn_mod_mul(y2, y, y, ctx.p);

    // Compute x² = (y² - 1) / (d*y² - a)
    // num = y² - 1
    cx_bn_mod_sub(num, y2, ctx.one, ctx.p);

    // den = d*y² - a
    cx_bn_mod_mul(den, ctx.d, y2, ctx.p);
    cx_bn_mod_sub(den, den, ctx.a, ctx.p);

    // x² = num / den = num * den^(-1)
    cx_bn_mod_invert_nprime(tmp, den, ctx.p);
    cx_bn_mod_mul(x2, num, tmp, ctx.p);

    // x = sqrt(x²)
    // Note: cx_bn_mod_sqrt returns one of the two roots, we'll check sign after
    if (cx_bn_mod_sqrt(x, x2, ctx.p, 0) != CX_OK) {
        goto cleanup_tmp;
    }

    // Export X to check if it matches the sign bit
    cx_bn_export(x, point, 32);

    // Check if X is largest and negate if it doesn't match sign bit
    bool x_is_largest = is_x_largest(point);
    if (x_is_largest != (sign == 1)) {
        // Negate X: X = p - X (use tmp to avoid input/output overlap)
        cx_bn_mod_sub(tmp, ctx.p, x, ctx.p);
        cx_bn_export(tmp, point, 32);
    }

    success = true;

cleanup_tmp:
    cx_bn_destroy(&tmp);
cleanup_x:
    cx_bn_destroy(&x);
cleanup_den:
    cx_bn_destroy(&den);
cleanup_num:
    cx_bn_destroy(&num);
cleanup_x2:
    cx_bn_destroy(&x2);
cleanup_y2:
    cx_bn_destroy(&y2);
cleanup_y:
    cx_bn_destroy(&y);
cleanup_ctx:
    field_cleanup(&ctx);

    return success;
}

// ============================================================================
// Internal Point Operations (64-byte uncompressed)
// ============================================================================

static bool bjj_point_add_internal(uint8_t result[64],
                                   const uint8_t p1[64],
                                   const uint8_t p2[64]) {
    bjj_field_ctx_t ctx;
    cx_err_t err;
    bool success = false;

    cx_bn_t x1, y1, x2, y2, x3, y3;
    cx_bn_t t1, t2, t3, t4, t5, t6;

    err = field_init(&ctx);
    if (err != CX_OK) return false;

    if (cx_bn_alloc(&x1, 32) != CX_OK) goto cleanup_ctx;
    if (cx_bn_alloc(&y1, 32) != CX_OK) goto cleanup_x1;
    if (cx_bn_alloc(&x2, 32) != CX_OK) goto cleanup_y1;
    if (cx_bn_alloc(&y2, 32) != CX_OK) goto cleanup_x2;
    if (cx_bn_alloc(&x3, 32) != CX_OK) goto cleanup_y2;
    if (cx_bn_alloc(&y3, 32) != CX_OK) goto cleanup_x3;
    if (cx_bn_alloc(&t1, 32) != CX_OK) goto cleanup_y3;
    if (cx_bn_alloc(&t2, 32) != CX_OK) goto cleanup_t1;
    if (cx_bn_alloc(&t3, 32) != CX_OK) goto cleanup_t2;
    if (cx_bn_alloc(&t4, 32) != CX_OK) goto cleanup_t3;
    if (cx_bn_alloc(&t5, 32) != CX_OK) goto cleanup_t4;
    if (cx_bn_alloc(&t6, 32) != CX_OK) goto cleanup_t5;

    cx_bn_init(x1, p1, 32);
    cx_bn_init(y1, p1 + 32, 32);
    cx_bn_init(x2, p2, 32);
    cx_bn_init(y2, p2 + 32, 32);

    // t1 = x1 * x2
    cx_bn_mod_mul(t1, x1, x2, ctx.p);
    // t2 = y1 * y2
    cx_bn_mod_mul(t2, y1, y2, ctx.p);
    // t3 = x1 * y2
    cx_bn_mod_mul(t3, x1, y2, ctx.p);
    // t4 = y1 * x2
    cx_bn_mod_mul(t4, y1, x2, ctx.p);
    // t5 = d * x1 * x2 * y1 * y2
    cx_bn_mod_mul(t5, t1, t2, ctx.p);
    cx_bn_mod_mul(t5, ctx.d, t5, ctx.p);

    // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
    cx_bn_mod_add(t6, t3, t4, ctx.p);
    cx_bn_mod_add(t3, ctx.one, t5, ctx.p);
    cx_bn_mod_invert_nprime(t4, t3, ctx.p);
    cx_bn_mod_mul(x3, t6, t4, ctx.p);

    // y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
    cx_bn_mod_mul(t6, ctx.a, t1, ctx.p);
    cx_bn_mod_sub(t6, t2, t6, ctx.p);
    cx_bn_mod_sub(t3, ctx.one, t5, ctx.p);
    cx_bn_mod_invert_nprime(t4, t3, ctx.p);
    cx_bn_mod_mul(y3, t6, t4, ctx.p);

    cx_bn_export(x3, result, 32);
    cx_bn_export(y3, result + 32, 32);

    success = true;

    cx_bn_destroy(&t6);
cleanup_t5:
    cx_bn_destroy(&t5);
cleanup_t4:
    cx_bn_destroy(&t4);
cleanup_t3:
    cx_bn_destroy(&t3);
cleanup_t2:
    cx_bn_destroy(&t2);
cleanup_t1:
    cx_bn_destroy(&t1);
cleanup_y3:
    cx_bn_destroy(&y3);
cleanup_x3:
    cx_bn_destroy(&x3);
cleanup_y2:
    cx_bn_destroy(&y2);
cleanup_x2:
    cx_bn_destroy(&x2);
cleanup_y1:
    cx_bn_destroy(&y1);
cleanup_x1:
    cx_bn_destroy(&x1);
cleanup_ctx:
    field_cleanup(&ctx);

    return success;
}

static bool bjj_scalar_mult_internal(uint8_t result[64],
                                     const uint8_t scalar[32],
                                     const uint8_t point[64]) {
    uint8_t R[64];
    uint8_t Q[64];
    uint8_t temp[64];

    memcpy(R, BJJ_IDENTITY, 64);
    memcpy(Q, point, 64);

    for (int byte_idx = 31; byte_idx >= 0; byte_idx--) {
        uint8_t byte = scalar[byte_idx];

        for (int bit = 0; bit < 8; bit++) {
            if (byte & (1 << bit)) {
                if (!bjj_point_add_internal(temp, R, Q)) {
                    return false;
                }
                memcpy(R, temp, 64);
            }

            if (!bjj_point_add_internal(temp, Q, Q)) {
                return false;
            }
            memcpy(Q, temp, 64);
        }
    }

    memcpy(result, R, 64);
    return true;
}

// ============================================================================
// Public Interface (32-byte compressed points)
// ============================================================================

bool curve_scalar_mult(uint8_t result[32],
                       const uint8_t scalar[32],
                       const uint8_t point[32]) {
    uint8_t uncompressed[64];
    uint8_t result_uncompressed[64];

    if (!bjj_decompress(uncompressed, point)) {
        return false;
    }

    if (!bjj_scalar_mult_internal(result_uncompressed, scalar, uncompressed)) {
        return false;
    }

    bjj_compress(result, result_uncompressed);
    return true;
}

bool curve_base_mult(uint8_t result[32],
                     const uint8_t scalar[32]) {
    uint8_t result_uncompressed[64];

    if (!bjj_scalar_mult_internal(result_uncompressed, scalar, BJJ_GENERATOR_UNCOMPRESSED)) {
        return false;
    }

    bjj_compress(result, result_uncompressed);
    return true;
}

bool curve_point_add(uint8_t result[32],
                     const uint8_t p1[32],
                     const uint8_t p2[32]) {
    uint8_t p1_uncompressed[64];
    uint8_t p2_uncompressed[64];
    uint8_t result_uncompressed[64];

    if (!bjj_decompress(p1_uncompressed, p1)) {
        return false;
    }
    if (!bjj_decompress(p2_uncompressed, p2)) {
        return false;
    }

    if (!bjj_point_add_internal(result_uncompressed, p1_uncompressed, p2_uncompressed)) {
        return false;
    }

    bjj_compress(result, result_uncompressed);
    return true;
}

bool curve_is_valid_point(const uint8_t point[32]) {
    uint8_t uncompressed[64];
    return bjj_decompress(uncompressed, point);
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

// Precomputed: 2^256 mod BJJ scalar order (from gnark-crypto)
static const uint8_t MOD_2_256[32] = {
    0x01, 0xf1, 0x64, 0x24, 0xe1, 0xbb, 0x77, 0x24,
    0xf8, 0x5a, 0x92, 0x01, 0xd8, 0x18, 0xf0, 0x15,
    0xe7, 0xac, 0xff, 0xc6, 0xa0, 0x98, 0xf2, 0x4b,
    0x07, 0x33, 0x15, 0xde, 0xa0, 0x8f, 0x9c, 0x76
};

void curve_scalar_reduce_64(uint8_t result[32],
                            const uint8_t value[64]) {
    // Reduce 64-byte value v = (high * 2^256 + low) mod order
    // result = (high * MOD_2_256 + low) mod order

    cx_bn_t bn_high, bn_low, bn_tmp, bn_tmp2, bn_order, bn_mod256;

    cx_bn_lock(32, 0);

    cx_bn_alloc(&bn_high, 32);
    cx_bn_alloc(&bn_low, 32);
    cx_bn_alloc(&bn_tmp, 32);
    cx_bn_alloc(&bn_tmp2, 32);
    cx_bn_alloc(&bn_order, 32);
    cx_bn_alloc(&bn_mod256, 32);

    cx_bn_init(bn_order, CURVE_ORDER, 32);
    cx_bn_init(bn_mod256, MOD_2_256, 32);

    // Split 64-byte value: high (first 32) and low (last 32)
    cx_bn_init(bn_high, value, 32);
    cx_bn_init(bn_low, value + 32, 32);

    // high_reduced = high mod order
    cx_bn_reduce(bn_tmp, bn_high, bn_order);

    // tmp = high_reduced * MOD_2_256 mod order
    cx_bn_mod_mul(bn_tmp2, bn_tmp, bn_mod256, bn_order);

    // Reduce low mod order
    cx_bn_reduce(bn_tmp, bn_low, bn_order);

    // result = (tmp2 + tmp) mod order
    cx_bn_mod_add(bn_tmp, bn_tmp2, bn_tmp, bn_order);

    cx_bn_export(bn_tmp, result, 32);

    cx_bn_destroy(&bn_high);
    cx_bn_destroy(&bn_low);
    cx_bn_destroy(&bn_tmp);
    cx_bn_destroy(&bn_tmp2);
    cx_bn_destroy(&bn_order);
    cx_bn_destroy(&bn_mod256);

    cx_bn_unlock();
}
