#include "bjj.h"
#include "os.h"
#include "cx.h"
#include <string.h>

// ============================================================================
// Baby Jubjub Constants
// ============================================================================
//
// Curve: a*x² + y² = 1 + d*x²*y²  (twisted Edwards form)
// a = 168700
// d = 168696
//
// Base field p (BN254 scalar field):
// 21888242871839275222246405745257275088548364400416034343698204186575808495617
//
// Subgroup order:
// 2736030358979909402780800718157159386076813972158567259200215660948447373041
// ============================================================================

// Base field prime p (big-endian for Ledger SDK)
static const uint8_t BJJ_PRIME[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47
};

// Curve parameter a = 168700 (big-endian)
static const uint8_t BJJ_A[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x92, 0xfc
};

// Curve parameter d = 168696 (big-endian)
static const uint8_t BJJ_D[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x92, 0xf8
};

// Scalar field order (big-endian for Ledger SDK)
const uint8_t BJJ_ORDER[32] = {
    0x06, 0x0c, 0x89, 0xce, 0x5c, 0x26, 0x34, 0x05,
    0x29, 0x93, 0x0c, 0x2f, 0x51, 0xf2, 0x1d, 0xa6,
    0xe5, 0xc2, 0x4b, 0x59, 0x8c, 0xa9, 0x3e, 0x08,
    0xf8, 0x16, 0x19, 0x07, 0xfb, 0x01, 0x87, 0xd1
};

// Generator point G (big-endian, x then y)
// x = 5299619240641551281634865583518297030282874472190772894086521144482721001553
// y = 16950150798460657717958625567821834550301663161624707787222815936182638968203
const uint8_t BJJ_GENERATOR[64] = {
    // x coordinate (big-endian)
    0x0b, 0xb8, 0x5e, 0xde, 0x52, 0x6d, 0xce, 0x05,
    0x53, 0x44, 0x28, 0x0c, 0x05, 0x52, 0x1a, 0x97,
    0x9c, 0xdb, 0x8a, 0xa4, 0x0e, 0xb9, 0xd7, 0xf5,
    0x57, 0x6e, 0x4e, 0xa0, 0x5c, 0x5e, 0x4e, 0x11,
    // y coordinate (big-endian)
    0x25, 0x84, 0x66, 0xd5, 0xc7, 0x33, 0x09, 0xc4,
    0x2e, 0x8a, 0x19, 0xd0, 0xd7, 0x3a, 0xdc, 0x71,
    0x4a, 0xd4, 0xd5, 0xfc, 0xd1, 0x22, 0xf2, 0xe4,
    0x6a, 0x24, 0x69, 0x3d, 0xf8, 0xda, 0x84, 0x8b
};

// Identity point (0, 1)
static const uint8_t BJJ_IDENTITY[64] = {
    // x = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // y = 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

// ============================================================================
// Internal Field Arithmetic (mod p)
// ============================================================================

// Field context for bignum operations
typedef struct {
    cx_bn_t p;      // Prime modulus
    cx_bn_t a;      // Curve parameter a
    cx_bn_t d;      // Curve parameter d
    cx_bn_t one;    // Constant 1
} bjj_field_ctx_t;

// Initialize field context
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

// Cleanup field context
static void field_cleanup(bjj_field_ctx_t *ctx) {
    cx_bn_destroy(&ctx->p);
    cx_bn_destroy(&ctx->a);
    cx_bn_destroy(&ctx->d);
    cx_bn_destroy(&ctx->one);
    cx_bn_unlock();
}

// ============================================================================
// Point Addition (Twisted Edwards)
// ============================================================================
//
// For twisted Edwards curve: a*x² + y² = 1 + d*x²*y²
// Point addition formula:
//   x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
//   y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
//
// ============================================================================

bool bjj_point_add(uint8_t result[BJJ_POINT_BYTES],
                   const uint8_t p1[BJJ_POINT_BYTES],
                   const uint8_t p2[BJJ_POINT_BYTES]) {
    bjj_field_ctx_t ctx;
    cx_err_t err;
    bool success = false;

    // Temporary bignums
    cx_bn_t x1, y1, x2, y2, x3, y3;
    cx_bn_t t1, t2, t3, t4, t5, t6;

    err = field_init(&ctx);
    if (err != CX_OK) return false;

    // Allocate all temporaries
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

    // Load point coordinates
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

    // t5 = d * x1 * x2 * y1 * y2 = d * t1 * t2
    cx_bn_mod_mul(t5, t1, t2, ctx.p);
    cx_bn_mod_mul(t5, ctx.d, t5, ctx.p);

    // Numerator for x3: x1*y2 + y1*x2 = t3 + t4
    cx_bn_mod_add(t6, t3, t4, ctx.p);

    // Denominator for x3: 1 + d*x1*x2*y1*y2 = 1 + t5
    cx_bn_mod_add(t3, ctx.one, t5, ctx.p);

    // x3 = t6 / t3 = t6 * t3^(-1)
    cx_bn_mod_invert_nprime(t4, t3, ctx.p);
    cx_bn_mod_mul(x3, t6, t4, ctx.p);

    // Numerator for y3: y1*y2 - a*x1*x2 = t2 - a*t1
    cx_bn_mod_mul(t6, ctx.a, t1, ctx.p);
    cx_bn_mod_sub(t6, t2, t6, ctx.p);

    // Denominator for y3: 1 - d*x1*x2*y1*y2 = 1 - t5
    cx_bn_mod_sub(t3, ctx.one, t5, ctx.p);

    // y3 = t6 / t3 = t6 * t3^(-1)
    cx_bn_mod_invert_nprime(t4, t3, ctx.p);
    cx_bn_mod_mul(y3, t6, t4, ctx.p);

    // Export result
    cx_bn_export(x3, result, 32);
    cx_bn_export(y3, result + 32, 32);

    success = true;

    // Cleanup in reverse order
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

// ============================================================================
// Scalar Multiplication (Double-and-Add)
// ============================================================================

bool bjj_scalar_mult(uint8_t result[BJJ_POINT_BYTES],
                     const uint8_t scalar[BJJ_SCALAR_BYTES],
                     const uint8_t point[BJJ_POINT_BYTES]) {
    uint8_t R[BJJ_POINT_BYTES];  // Accumulator (starts at identity)
    uint8_t Q[BJJ_POINT_BYTES];  // Current point (P, 2P, 4P, ...)
    uint8_t temp[BJJ_POINT_BYTES];

    // Initialize R = identity (0, 1)
    memcpy(R, BJJ_IDENTITY, BJJ_POINT_BYTES);

    // Initialize Q = point
    memcpy(Q, point, BJJ_POINT_BYTES);

    // Process scalar bits from LSB to MSB (big-endian scalar)
    for (int byte_idx = 31; byte_idx >= 0; byte_idx--) {
        uint8_t byte = scalar[byte_idx];

        for (int bit = 0; bit < 8; bit++) {
            if (byte & (1 << bit)) {
                // R = R + Q
                if (!bjj_point_add(temp, R, Q)) {
                    return false;
                }
                memcpy(R, temp, BJJ_POINT_BYTES);
            }

            // Q = 2*Q (point doubling = adding point to itself)
            if (!bjj_point_add(temp, Q, Q)) {
                return false;
            }
            memcpy(Q, temp, BJJ_POINT_BYTES);
        }
    }

    memcpy(result, R, BJJ_POINT_BYTES);
    return true;
}

// ============================================================================
// Base Point Multiplication
// ============================================================================

bool bjj_base_mult(uint8_t result[BJJ_POINT_BYTES],
                   const uint8_t scalar[BJJ_SCALAR_BYTES]) {
    return bjj_scalar_mult(result, scalar, BJJ_GENERATOR);
}

// ============================================================================
// Point Validation
// ============================================================================

bool bjj_is_on_curve(const uint8_t point[BJJ_POINT_BYTES]) {
    bjj_field_ctx_t ctx;
    cx_err_t err;
    bool on_curve = false;

    cx_bn_t x, y, x2, y2, lhs, rhs, t1;

    err = field_init(&ctx);
    if (err != CX_OK) return false;

    if (cx_bn_alloc(&x, 32) != CX_OK) goto cleanup_ctx;
    if (cx_bn_alloc(&y, 32) != CX_OK) goto cleanup_x;
    if (cx_bn_alloc(&x2, 32) != CX_OK) goto cleanup_y;
    if (cx_bn_alloc(&y2, 32) != CX_OK) goto cleanup_x2;
    if (cx_bn_alloc(&lhs, 32) != CX_OK) goto cleanup_y2;
    if (cx_bn_alloc(&rhs, 32) != CX_OK) goto cleanup_lhs;
    if (cx_bn_alloc(&t1, 32) != CX_OK) goto cleanup_rhs;

    // Load coordinates
    cx_bn_init(x, point, 32);
    cx_bn_init(y, point + 32, 32);

    // x² and y²
    cx_bn_mod_mul(x2, x, x, ctx.p);
    cx_bn_mod_mul(y2, y, y, ctx.p);

    // LHS = a*x² + y²
    cx_bn_mod_mul(lhs, ctx.a, x2, ctx.p);
    cx_bn_mod_add(lhs, lhs, y2, ctx.p);

    // RHS = 1 + d*x²*y²
    cx_bn_mod_mul(t1, x2, y2, ctx.p);
    cx_bn_mod_mul(t1, ctx.d, t1, ctx.p);
    cx_bn_mod_add(rhs, ctx.one, t1, ctx.p);

    // Compare LHS == RHS
    int cmp;
    cx_bn_cmp(lhs, rhs, &cmp);
    on_curve = (cmp == 0);

    cx_bn_destroy(&t1);
cleanup_rhs:
    cx_bn_destroy(&rhs);
cleanup_lhs:
    cx_bn_destroy(&lhs);
cleanup_y2:
    cx_bn_destroy(&y2);
cleanup_x2:
    cx_bn_destroy(&x2);
cleanup_y:
    cx_bn_destroy(&y);
cleanup_x:
    cx_bn_destroy(&x);
cleanup_ctx:
    field_cleanup(&ctx);

    return on_curve;
}

// ============================================================================
// Scalar Operations (mod subgroup order)
// ============================================================================

void bjj_scalar_add(uint8_t result[BJJ_SCALAR_BYTES],
                    const uint8_t a[BJJ_SCALAR_BYTES],
                    const uint8_t b[BJJ_SCALAR_BYTES]) {
    cx_bn_t bn_a, bn_b, bn_r, bn_order;

    cx_bn_lock(32, 0);

    cx_bn_alloc(&bn_a, 32);
    cx_bn_alloc(&bn_b, 32);
    cx_bn_alloc(&bn_r, 32);
    cx_bn_alloc(&bn_order, 32);

    cx_bn_init(bn_a, a, 32);
    cx_bn_init(bn_b, b, 32);
    cx_bn_init(bn_order, BJJ_ORDER, 32);

    cx_bn_mod_add(bn_r, bn_a, bn_b, bn_order);

    cx_bn_export(bn_r, result, 32);

    cx_bn_destroy(&bn_a);
    cx_bn_destroy(&bn_b);
    cx_bn_destroy(&bn_r);
    cx_bn_destroy(&bn_order);

    cx_bn_unlock();
}

void bjj_scalar_mul(uint8_t result[BJJ_SCALAR_BYTES],
                    const uint8_t a[BJJ_SCALAR_BYTES],
                    const uint8_t b[BJJ_SCALAR_BYTES]) {
    cx_bn_t bn_a, bn_b, bn_r, bn_order;

    cx_bn_lock(32, 0);

    cx_bn_alloc(&bn_a, 32);
    cx_bn_alloc(&bn_b, 32);
    cx_bn_alloc(&bn_r, 32);
    cx_bn_alloc(&bn_order, 32);

    cx_bn_init(bn_a, a, 32);
    cx_bn_init(bn_b, b, 32);
    cx_bn_init(bn_order, BJJ_ORDER, 32);

    cx_bn_mod_mul(bn_r, bn_a, bn_b, bn_order);

    cx_bn_export(bn_r, result, 32);

    cx_bn_destroy(&bn_a);
    cx_bn_destroy(&bn_b);
    cx_bn_destroy(&bn_r);
    cx_bn_destroy(&bn_order);

    cx_bn_unlock();
}

void bjj_scalar_reduce(uint8_t result[BJJ_SCALAR_BYTES],
                       const uint8_t value[BJJ_SCALAR_BYTES]) {
    cx_bn_t bn_v, bn_r, bn_order;

    cx_bn_lock(32, 0);

    cx_bn_alloc(&bn_v, 32);
    cx_bn_alloc(&bn_r, 32);
    cx_bn_alloc(&bn_order, 32);

    cx_bn_init(bn_v, value, 32);
    cx_bn_init(bn_order, BJJ_ORDER, 32);

    cx_bn_reduce(bn_r, bn_v, bn_order);

    cx_bn_export(bn_r, result, 32);

    cx_bn_destroy(&bn_v);
    cx_bn_destroy(&bn_r);
    cx_bn_destroy(&bn_order);

    cx_bn_unlock();
}

// ============================================================================
// Lagrange Coefficient Computation
// ============================================================================

// Compute Lagrange coefficient for participant i among a set of participants
// lambda_i = product of (x_j / (x_j - x_i)) for all j != i
// where x_i = identifier_i (as field elements)
static void compute_lagrange_coeff(uint8_t result[BJJ_SCALAR_BYTES],
                                   uint16_t my_id,
                                   const uint16_t *participant_ids,
                                   uint8_t num_participants) {
    cx_bn_t lambda, num, den, xj, xi, tmp, order;

    cx_bn_lock(32, 0);

    cx_bn_alloc(&lambda, 32);
    cx_bn_alloc(&num, 32);
    cx_bn_alloc(&den, 32);
    cx_bn_alloc(&xj, 32);
    cx_bn_alloc(&xi, 32);
    cx_bn_alloc(&tmp, 32);
    cx_bn_alloc(&order, 32);

    cx_bn_init(order, BJJ_ORDER, 32);

    // Initialize lambda = 1
    uint8_t one[32] = {0};
    one[31] = 1;
    cx_bn_init(lambda, one, 32);

    // xi = my_id as big number
    uint8_t id_bytes[32] = {0};
    id_bytes[30] = (my_id >> 8) & 0xFF;
    id_bytes[31] = my_id & 0xFF;
    cx_bn_init(xi, id_bytes, 32);

    for (uint8_t j = 0; j < num_participants; j++) {
        if (participant_ids[j] == my_id) {
            continue;  // Skip self
        }

        // xj = participant_ids[j]
        uint8_t xj_bytes[32] = {0};
        xj_bytes[30] = (participant_ids[j] >> 8) & 0xFF;
        xj_bytes[31] = participant_ids[j] & 0xFF;
        cx_bn_init(xj, xj_bytes, 32);

        // num = xj
        cx_bn_copy(num, xj);

        // den = xj - xi (mod order)
        cx_bn_mod_sub(den, xj, xi, order);

        // tmp = num / den = num * den^(-1)
        cx_bn_mod_invert_nprime(tmp, den, order);
        cx_bn_mod_mul(tmp, num, tmp, order);

        // lambda = lambda * tmp
        cx_bn_mod_mul(lambda, lambda, tmp, order);
    }

    cx_bn_export(lambda, result, 32);

    cx_bn_destroy(&lambda);
    cx_bn_destroy(&num);
    cx_bn_destroy(&den);
    cx_bn_destroy(&xj);
    cx_bn_destroy(&xi);
    cx_bn_destroy(&tmp);
    cx_bn_destroy(&order);

    cx_bn_unlock();
}

// ============================================================================
// FROST-specific Operations
// ============================================================================

void bjj_compute_binding_factor(uint8_t result[BJJ_SCALAR_BYTES],
                                const uint8_t *group_pubkey,
                                const uint8_t *commitment_list,
                                uint16_t commitment_list_len,
                                const uint8_t *message_hash) {
    cx_sha256_t hash_ctx;
    uint8_t hash_output[32];

    cx_sha256_init(&hash_ctx);
    cx_hash((cx_hash_t *)&hash_ctx, 0, group_pubkey, BJJ_POINT_BYTES, NULL, 0);
    cx_hash((cx_hash_t *)&hash_ctx, 0, commitment_list, commitment_list_len, NULL, 0);
    cx_hash((cx_hash_t *)&hash_ctx, CX_LAST, message_hash, BJJ_SCALAR_BYTES, hash_output, 32);

    bjj_scalar_reduce(result, hash_output);
}

void bjj_compute_challenge(uint8_t result[BJJ_SCALAR_BYTES],
                           const uint8_t *group_commitment,
                           const uint8_t *group_pubkey,
                           const uint8_t *message_hash) {
    cx_sha256_t hash_ctx;
    uint8_t hash_output[32];

    cx_sha256_init(&hash_ctx);
    cx_hash((cx_hash_t *)&hash_ctx, 0, group_commitment, BJJ_POINT_BYTES, NULL, 0);
    cx_hash((cx_hash_t *)&hash_ctx, 0, group_pubkey, BJJ_POINT_BYTES, NULL, 0);
    cx_hash((cx_hash_t *)&hash_ctx, CX_LAST, message_hash, BJJ_SCALAR_BYTES, hash_output, 32);

    bjj_scalar_reduce(result, hash_output);
}

bool bjj_compute_partial_sig(uint8_t result[BJJ_SCALAR_BYTES],
                             const uint8_t *hiding_nonce,
                             const uint8_t *binding_nonce,
                             const uint8_t *binding_factor,
                             const uint8_t *secret_share,
                             const uint8_t *challenge,
                             uint16_t identifier,
                             const uint16_t *participant_ids,
                             uint8_t num_participants) {
    uint8_t lambda[BJJ_SCALAR_BYTES];
    uint8_t tmp1[BJJ_SCALAR_BYTES];
    uint8_t tmp2[BJJ_SCALAR_BYTES];

    // Compute Lagrange coefficient
    compute_lagrange_coeff(lambda, identifier, participant_ids, num_participants);

    // z_i = hiding_nonce + (binding_nonce * binding_factor) + (secret * challenge * lambda_i)

    // tmp1 = binding_nonce * binding_factor
    bjj_scalar_mul(tmp1, binding_nonce, binding_factor);

    // tmp2 = secret * challenge
    bjj_scalar_mul(tmp2, secret_share, challenge);

    // tmp2 = tmp2 * lambda
    bjj_scalar_mul(tmp2, tmp2, lambda);

    // result = hiding_nonce + tmp1
    bjj_scalar_add(result, hiding_nonce, tmp1);

    // result = result + tmp2
    bjj_scalar_add(result, result, tmp2);

    // Clear sensitive temporaries
    explicit_bzero(lambda, sizeof(lambda));
    explicit_bzero(tmp1, sizeof(tmp1));
    explicit_bzero(tmp2, sizeof(tmp2));

    return true;
}
