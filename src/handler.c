#include "handler.h"
#include "frost_storage.h"
#include "bjj.h"
#include "ui.h"
#include "os.h"
#include "cx.h"
#include <string.h>

// ============================================================================
// Version Handler
// ============================================================================

uint16_t handle_get_version(uint8_t *response, uint8_t *response_len) {
    response[0] = MAJOR_VERSION;
    response[1] = MINOR_VERSION;
    response[2] = PATCH_VERSION;
    *response_len = 3;
    return SW_OK;
}

// ============================================================================
// Public Key Handler
// ============================================================================

uint16_t handle_get_public_key(uint8_t *response, uint8_t *response_len) {
    if (!frost_has_keys()) {
        return SW_CONDITIONS_NOT_SAT;
    }

    memcpy(response, frost_get_group_pubkey(), BJJ_POINT_SIZE);
    *response_len = BJJ_POINT_SIZE;
    return SW_OK;
}

// ============================================================================
// Key Injection Handler
// ============================================================================

uint16_t handle_inject_keys(uint8_t p1, uint8_t p2,
                            uint8_t *data, uint8_t data_len,
                            uint8_t *response, uint8_t *response_len) {
    (void)p2;
    (void)response;
    *response_len = 0;

    // Validate curve ID
    if (p1 != CURVE_BABY_JUBJUB) {
        return SW_WRONG_P1P2;
    }

    // Validate data length: 64 (pubkey) + 32 (id) + 32 (secret) = 128
    if (data_len != 128) {
        return SW_WRONG_LENGTH;
    }

    uint8_t *group_pubkey = data;
    uint8_t *id_bytes = data + 64;
    uint8_t *secret_share = data + 96;

    // Extract 16-bit identifier from first 2 bytes
    uint16_t identifier = ((uint16_t)id_bytes[0] << 8) | id_bytes[1];

    if (identifier == 0) {
        return SW_INVALID_DATA;  // FROST identifiers must be > 0
    }

    // Request user confirmation
    // Format the group key fingerprint for display
    uint8_t hash[32];
    cx_sha256_hash(group_pubkey, BJJ_POINT_SIZE, hash);

    // Use first 4 bytes as fingerprint
    if (!ui_confirm_inject_keys(hash, identifier)) {
        return SW_USER_REJECTED;
    }

    // Store the keys
    if (!frost_inject_keys(p1, group_pubkey, identifier, secret_share)) {
        return SW_INTERNAL_ERROR;
    }

    return SW_OK;
}

// ============================================================================
// Commitment Handler
// ============================================================================

uint16_t handle_commit(uint8_t *response, uint8_t *response_len) {
    if (!frost_has_keys()) {
        return SW_CONDITIONS_NOT_SAT;
    }

    // Check we're in the right state
    if (G_frost_ctx.state != FROST_STATE_IDLE) {
        // Already have nonces, reject
        return SW_CONDITIONS_NOT_SAT;
    }

    // Generate random nonces using secure RNG
    cx_rng(G_frost_ctx.hiding_nonce, BJJ_SCALAR_SIZE);
    cx_rng(G_frost_ctx.binding_nonce, BJJ_SCALAR_SIZE);

    // Reduce nonces modulo curve order
    bjj_scalar_reduce(G_frost_ctx.hiding_nonce, G_frost_ctx.hiding_nonce);
    bjj_scalar_reduce(G_frost_ctx.binding_nonce, G_frost_ctx.binding_nonce);

    // Compute commitments: C = nonce * G
    if (!bjj_base_mult(G_frost_ctx.hiding_commit, G_frost_ctx.hiding_nonce)) {
        frost_ctx_reset();
        return SW_INTERNAL_ERROR;
    }

    if (!bjj_base_mult(G_frost_ctx.binding_commit, G_frost_ctx.binding_nonce)) {
        frost_ctx_reset();
        return SW_INTERNAL_ERROR;
    }

    // Update state
    G_frost_ctx.state = FROST_STATE_COMMITTED;

    // Return commitments
    memcpy(response, G_frost_ctx.hiding_commit, BJJ_POINT_SIZE);
    memcpy(response + BJJ_POINT_SIZE, G_frost_ctx.binding_commit, BJJ_POINT_SIZE);
    *response_len = BJJ_POINT_SIZE * 2;

    return SW_OK;
}

// ============================================================================
// Message Injection Handler
// ============================================================================

uint16_t handle_inject_message(uint8_t *data, uint8_t data_len) {
    if (!frost_has_keys()) {
        return SW_CONDITIONS_NOT_SAT;
    }

    // Must have generated nonces first
    if (G_frost_ctx.state != FROST_STATE_COMMITTED) {
        return SW_CONDITIONS_NOT_SAT;
    }

    if (data_len != BJJ_SCALAR_SIZE) {
        return SW_WRONG_LENGTH;
    }

    // Store message hash
    memcpy(G_frost_ctx.message_hash, data, BJJ_SCALAR_SIZE);
    G_frost_ctx.state = FROST_STATE_MESSAGE_SET;

    return SW_OK;
}

// ============================================================================
// Commitment List Injection Handlers
// ============================================================================

uint16_t handle_inject_commitments_p1(uint8_t p1,
                                      uint8_t *data, uint8_t data_len,
                                      uint8_t *response, uint8_t *response_len) {
    if (!frost_has_keys()) {
        return SW_CONDITIONS_NOT_SAT;
    }

    // Must have message set first
    if (G_frost_ctx.state != FROST_STATE_MESSAGE_SET) {
        return SW_CONDITIONS_NOT_SAT;
    }

    // p1 = number of participants
    if (p1 < 2 || p1 > MAX_PARTICIPANTS) {
        return SW_INVALID_DATA;
    }

    // Reset commitment list
    G_frost_ctx.num_participants = p1;
    G_frost_ctx.commitment_bytes_received = 0;
    memset(G_frost_ctx.commitment_list, 0, sizeof(G_frost_ctx.commitment_list));

    // Copy first chunk
    uint16_t expected_total = p1 * COMMITMENT_ENTRY_SIZE;
    uint16_t to_copy = data_len;
    if (to_copy > expected_total) {
        to_copy = expected_total;
    }

    memcpy(G_frost_ctx.commitment_list, data, to_copy);
    G_frost_ctx.commitment_bytes_received = to_copy;

    // Check if we have all data
    if (G_frost_ctx.commitment_bytes_received >= expected_total) {
        G_frost_ctx.state = FROST_STATE_COMMITMENTS_SET;
    }

    // Return bytes received
    response[0] = (G_frost_ctx.commitment_bytes_received >> 8) & 0xFF;
    response[1] = G_frost_ctx.commitment_bytes_received & 0xFF;
    *response_len = 2;

    return SW_OK;
}

uint16_t handle_inject_commitments_p2(uint8_t *data, uint8_t data_len,
                                      uint8_t *response, uint8_t *response_len) {
    if (!frost_has_keys()) {
        return SW_CONDITIONS_NOT_SAT;
    }

    // Must be in the middle of receiving commitments
    if (G_frost_ctx.state != FROST_STATE_MESSAGE_SET) {
        return SW_CONDITIONS_NOT_SAT;
    }

    uint16_t expected_total = G_frost_ctx.num_participants * COMMITMENT_ENTRY_SIZE;
    uint16_t remaining = expected_total - G_frost_ctx.commitment_bytes_received;
    uint16_t to_copy = data_len;
    if (to_copy > remaining) {
        to_copy = remaining;
    }

    memcpy(G_frost_ctx.commitment_list + G_frost_ctx.commitment_bytes_received,
           data, to_copy);
    G_frost_ctx.commitment_bytes_received += to_copy;

    // Check if complete
    if (G_frost_ctx.commitment_bytes_received >= expected_total) {
        G_frost_ctx.state = FROST_STATE_COMMITMENTS_SET;
    }

    // Return bytes received
    response[0] = (G_frost_ctx.commitment_bytes_received >> 8) & 0xFF;
    response[1] = G_frost_ctx.commitment_bytes_received & 0xFF;
    *response_len = 2;

    return SW_OK;
}

// ============================================================================
// Partial Signature Handler
// ============================================================================

uint16_t handle_partial_sign(uint8_t *response, uint8_t *response_len) {
    if (!frost_has_keys()) {
        return SW_CONDITIONS_NOT_SAT;
    }

    // Must have all required data
    if (G_frost_ctx.state != FROST_STATE_COMMITMENTS_SET) {
        return SW_CONDITIONS_NOT_SAT;
    }

    // Request user confirmation
    if (!ui_confirm_sign(G_frost_ctx.message_hash)) {
        frost_ctx_reset();  // Clear nonces on rejection
        return SW_USER_REJECTED;
    }

    // Extract participant IDs from commitment list
    uint16_t participant_ids[MAX_PARTICIPANTS];
    for (uint8_t i = 0; i < G_frost_ctx.num_participants; i++) {
        uint8_t *entry = G_frost_ctx.commitment_list + (i * COMMITMENT_ENTRY_SIZE);
        participant_ids[i] = ((uint16_t)entry[0] << 8) | entry[1];
    }

    // Compute binding factor
    uint8_t binding_factor[BJJ_SCALAR_SIZE];
    bjj_compute_binding_factor(binding_factor,
                               frost_get_group_pubkey(),
                               G_frost_ctx.commitment_list,
                               G_frost_ctx.commitment_bytes_received,
                               G_frost_ctx.message_hash);

    // Compute group commitment (sum of all individual commitments)
    // R = sum of (hiding_i + binding_factor * binding_i)
    uint8_t group_commitment[BJJ_POINT_SIZE];
    // TODO: Compute group commitment from commitment list
    memset(group_commitment, 0, BJJ_POINT_SIZE);  // Placeholder

    // Compute challenge
    uint8_t challenge[BJJ_SCALAR_SIZE];
    bjj_compute_challenge(challenge,
                          group_commitment,
                          frost_get_group_pubkey(),
                          G_frost_ctx.message_hash);

    // Compute partial signature
    uint8_t partial_sig[BJJ_SCALAR_SIZE];
    if (!bjj_compute_partial_sig(partial_sig,
                                  G_frost_ctx.hiding_nonce,
                                  G_frost_ctx.binding_nonce,
                                  binding_factor,
                                  (const uint8_t *)N_frost.secret_share,
                                  challenge,
                                  frost_get_identifier(),
                                  participant_ids,
                                  G_frost_ctx.num_participants)) {
        frost_ctx_reset();
        return SW_INTERNAL_ERROR;
    }

    // CRITICAL: Clear nonces immediately after use
    explicit_bzero(G_frost_ctx.hiding_nonce, BJJ_SCALAR_SIZE);
    explicit_bzero(G_frost_ctx.binding_nonce, BJJ_SCALAR_SIZE);

    // Reset state
    frost_ctx_reset();

    // Return partial signature
    memcpy(response, partial_sig, BJJ_SCALAR_SIZE);
    *response_len = BJJ_SCALAR_SIZE;

    // Clear local sensitive data
    explicit_bzero(partial_sig, sizeof(partial_sig));
    explicit_bzero(binding_factor, sizeof(binding_factor));
    explicit_bzero(challenge, sizeof(challenge));

    return SW_OK;
}

// ============================================================================
// Reset Handler
// ============================================================================

uint16_t handle_reset(void) {
    frost_ctx_reset();
    return SW_OK;
}
