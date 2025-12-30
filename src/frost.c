#include "frost.h"
#include "os.h"
#include "cx.h"
#include <string.h>

// ============================================================================
// Helper: Reverse bytes (for little-endian interpretation)
// ============================================================================

static void reverse_bytes(uint8_t *out, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = in[len - 1 - i];
    }
}

// ============================================================================
// Commitment Encoding
// ============================================================================

uint16_t frost_encode_commitments(uint8_t *output,
                                  const uint8_t *commitment_list,
                                  uint8_t num_participants) {
    // Commitment list is already in the format: ID (32) || Hiding (32) || Binding (32)
    // Just copy it directly
    uint16_t total_len = num_participants * COMMITMENT_ENTRY_SIZE;
    memcpy(output, commitment_list, total_len);
    return total_len;
}

// ============================================================================
// Blake2b Hash Helper (fy Blake2bHasher compatible)
// ============================================================================

// Hash with domain separation: prefix || tag || data...
// Returns 64-byte hash interpreted as little-endian, reduced mod curve order
static void blake2b_hash_to_scalar(uint8_t result[CURVE_SCALAR_SIZE],
                                   const char *tag,
                                   const uint8_t *data1, size_t len1,
                                   const uint8_t *data2, size_t len2,
                                   const uint8_t *data3, size_t len3) {
    cx_blake2b_t ctx;
    uint8_t hash[64];
    uint8_t reversed[64];

    // Initialize Blake2b-512
    cx_blake2b_init_no_throw(&ctx, 512);

    // Hash: prefix || tag || data1 || data2 || data3
    cx_hash_no_throw((cx_hash_t *)&ctx, 0,
                     (uint8_t *)FROST_DOMAIN_PREFIX, strlen(FROST_DOMAIN_PREFIX),
                     NULL, 0);
    cx_hash_no_throw((cx_hash_t *)&ctx, 0,
                     (uint8_t *)tag, strlen(tag),
                     NULL, 0);

    if (data1 && len1 > 0) {
        cx_hash_no_throw((cx_hash_t *)&ctx, 0, data1, len1, NULL, 0);
    }
    if (data2 && len2 > 0) {
        cx_hash_no_throw((cx_hash_t *)&ctx, 0, data2, len2, NULL, 0);
    }
    if (data3 && len3 > 0) {
        cx_hash_no_throw((cx_hash_t *)&ctx, 0, data3, len3, NULL, 0);
    }

    cx_hash_no_throw((cx_hash_t *)&ctx, CX_LAST, NULL, 0, hash, 64);

    // Reverse for little-endian interpretation (fy compatibility)
    reverse_bytes(reversed, hash, 64);

    // Reduce full 64-byte value mod curve order
    curve_scalar_reduce_64(result, reversed);
}

// ============================================================================
// Lagrange Coefficient Computation
// ============================================================================

static void compute_lagrange_coeff(uint8_t result[CURVE_SCALAR_SIZE],
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

    cx_bn_init(order, CURVE_ORDER, 32);

    // Initialize lambda = 1
    uint8_t one[32] = {0};
    one[31] = 1;
    cx_bn_init(lambda, one, 32);

    // xi = my_id as big number (in last byte for small IDs)
    uint8_t id_bytes[32] = {0};
    id_bytes[31] = my_id & 0xFF;
    if (my_id > 255) {
        id_bytes[30] = (my_id >> 8) & 0xFF;
    }
    cx_bn_init(xi, id_bytes, 32);

    for (uint8_t j = 0; j < num_participants; j++) {
        if (participant_ids[j] == my_id) {
            continue;  // Skip self
        }

        // xj = participant_ids[j]
        uint8_t xj_bytes[32] = {0};
        xj_bytes[31] = participant_ids[j] & 0xFF;
        if (participant_ids[j] > 255) {
            xj_bytes[30] = (participant_ids[j] >> 8) & 0xFF;
        }
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
// FROST Operations
// ============================================================================

void frost_compute_binding_factor(uint8_t result[CURVE_SCALAR_SIZE],
                                  const uint8_t *message_hash,
                                  const uint8_t *enc_commit_list,
                                  uint16_t enc_commit_list_len,
                                  const uint8_t *signer_id) {
    // H1: Blake2b(prefix || "rho" || message || encCommitList || signerID)
    // We need to concatenate message, encCommitList, and signerID
    // For simplicity, we'll make multiple hash update calls

    cx_blake2b_t ctx;
    uint8_t hash[64];
    uint8_t reversed[64];

    cx_blake2b_init_no_throw(&ctx, 512);

    // prefix
    cx_hash_no_throw((cx_hash_t *)&ctx, 0,
                     (uint8_t *)FROST_DOMAIN_PREFIX, strlen(FROST_DOMAIN_PREFIX),
                     NULL, 0);
    // tag "rho"
    cx_hash_no_throw((cx_hash_t *)&ctx, 0,
                     (uint8_t *)"rho", 3,
                     NULL, 0);
    // message
    cx_hash_no_throw((cx_hash_t *)&ctx, 0,
                     message_hash, CURVE_SCALAR_SIZE,
                     NULL, 0);
    // encCommitList
    cx_hash_no_throw((cx_hash_t *)&ctx, 0,
                     enc_commit_list, enc_commit_list_len,
                     NULL, 0);
    // signerID (32 bytes)
    cx_hash_no_throw((cx_hash_t *)&ctx, CX_LAST,
                     signer_id, 32,
                     hash, 64);

    // Reverse for little-endian interpretation
    reverse_bytes(reversed, hash, 64);

    // Reduce full 64-byte value mod curve order
    curve_scalar_reduce_64(result, reversed);
}

void frost_compute_challenge(uint8_t result[CURVE_SCALAR_SIZE],
                             const uint8_t *group_commitment,
                             const uint8_t *group_pubkey,
                             const uint8_t *message_hash) {
    // H2: Blake2b(prefix || "chal" || R || Y || message)
    cx_blake2b_t ctx;
    uint8_t hash[64];
    uint8_t reversed[64];

    cx_blake2b_init_no_throw(&ctx, 512);

    // prefix
    cx_hash_no_throw((cx_hash_t *)&ctx, 0,
                     (uint8_t *)FROST_DOMAIN_PREFIX, strlen(FROST_DOMAIN_PREFIX),
                     NULL, 0);
    // tag "chal"
    cx_hash_no_throw((cx_hash_t *)&ctx, 0,
                     (uint8_t *)"chal", 4,
                     NULL, 0);
    // R (group commitment)
    cx_hash_no_throw((cx_hash_t *)&ctx, 0,
                     group_commitment, CURVE_POINT_SIZE,
                     NULL, 0);
    // Y (group pubkey)
    cx_hash_no_throw((cx_hash_t *)&ctx, 0,
                     group_pubkey, CURVE_POINT_SIZE,
                     NULL, 0);
    // message
    cx_hash_no_throw((cx_hash_t *)&ctx, CX_LAST,
                     message_hash, CURVE_SCALAR_SIZE,
                     hash, 64);

    // Reverse for little-endian interpretation
    reverse_bytes(reversed, hash, 64);

    // Reduce full 64-byte value mod curve order
    curve_scalar_reduce_64(result, reversed);
}

bool frost_compute_group_commitment(uint8_t result[CURVE_POINT_SIZE],
                                    const uint8_t *commitment_list,
                                    const uint8_t *binding_factors,
                                    uint8_t num_participants) {
    // R = sum(HidingPoint_i + rho_i * BindingPoint_i)
    uint8_t sum[CURVE_POINT_SIZE];
    uint8_t term[CURVE_POINT_SIZE];
    uint8_t rho_binding[CURVE_POINT_SIZE];
    bool first = true;

    for (uint8_t i = 0; i < num_participants; i++) {
        const uint8_t *entry = commitment_list + (i * COMMITMENT_ENTRY_SIZE);
        // entry: ID (32) || HidingPoint (32) || BindingPoint (32)
        const uint8_t *hiding_point = entry + 32;
        const uint8_t *binding_point = entry + 64;
        const uint8_t *rho_i = binding_factors + (i * CURVE_SCALAR_SIZE);

        // rho_binding = rho_i * BindingPoint_i
        if (!curve_scalar_mult(rho_binding, rho_i, binding_point)) {
            return false;
        }

        // term = HidingPoint_i + rho_binding
        if (!curve_point_add(term, hiding_point, rho_binding)) {
            return false;
        }

        if (first) {
            memcpy(sum, term, CURVE_POINT_SIZE);
            first = false;
        } else {
            // sum = sum + term
            if (!curve_point_add(sum, sum, term)) {
                return false;
            }
        }
    }

    memcpy(result, sum, CURVE_POINT_SIZE);
    return true;
}

bool frost_compute_partial_sig(uint8_t result[CURVE_SCALAR_SIZE],
                               const uint8_t *hiding_nonce,
                               const uint8_t *binding_nonce,
                               const uint8_t *binding_factor,
                               const uint8_t *secret_share,
                               const uint8_t *challenge,
                               uint16_t identifier,
                               const uint16_t *participant_ids,
                               uint8_t num_participants) {
    uint8_t lambda[CURVE_SCALAR_SIZE];
    uint8_t tmp1[CURVE_SCALAR_SIZE];
    uint8_t tmp2[CURVE_SCALAR_SIZE];

    // Compute Lagrange coefficient
    compute_lagrange_coeff(lambda, identifier, participant_ids, num_participants);

    // z_i = hiding_nonce + (binding_nonce * binding_factor) + (secret * challenge * lambda_i)

    // tmp1 = binding_nonce * binding_factor
    curve_scalar_mul(tmp1, binding_nonce, binding_factor);

    // tmp2 = secret * challenge
    curve_scalar_mul(tmp2, secret_share, challenge);

    // tmp2 = tmp2 * lambda
    curve_scalar_mul(tmp2, tmp2, lambda);

    // result = hiding_nonce + tmp1
    curve_scalar_add(result, hiding_nonce, tmp1);

    // result = result + tmp2
    curve_scalar_add(result, result, tmp2);

    // Clear sensitive temporaries
    explicit_bzero(lambda, sizeof(lambda));
    explicit_bzero(tmp1, sizeof(tmp1));
    explicit_bzero(tmp2, sizeof(tmp2));

    return true;
}
