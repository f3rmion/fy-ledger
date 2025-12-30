#include "frost_storage.h"

// ============================================================================
// NVRAM Storage
// ============================================================================

// Persistent storage - initialized to zero bytes on app install
const frost_storage_t N_frost_real;

// ============================================================================
// RAM Context
// ============================================================================

// Ephemeral signing context
frost_ctx_t G_frost_ctx;

// ============================================================================
// Storage Implementation
// ============================================================================

void frost_storage_init(void) {
    // Reset RAM context on startup
    frost_ctx_reset();
}

bool frost_inject_keys(uint8_t curve_id,
                       const uint8_t *group_pubkey,
                       uint16_t identifier,
                       const uint8_t *secret_share) {

    // Validate inputs
    if (group_pubkey == NULL || secret_share == NULL) {
        return false;
    }

    if (identifier == 0) {
        return false;  // FROST identifiers must be non-zero
    }

    // Write each field to NVRAM
    // Using nvm_write() syscall for flash memory access

    uint8_t init_marker = 0x01;
    nvm_write((void *)&N_frost.initialized, &init_marker, sizeof(init_marker));
    nvm_write((void *)&N_frost.curve_id, &curve_id, sizeof(curve_id));
    nvm_write((void *)&N_frost.identifier, &identifier, sizeof(identifier));
    nvm_write((void *)&N_frost.group_public_key, (void *)group_pubkey, BJJ_POINT_SIZE);
    nvm_write((void *)&N_frost.secret_share, (void *)secret_share, BJJ_SCALAR_SIZE);

    return true;
}

bool frost_has_keys(void) {
    return N_frost.initialized == 0x01;
}

uint16_t frost_get_identifier(void) {
    return N_frost.identifier;
}

const uint8_t *frost_get_group_pubkey(void) {
    return (const uint8_t *)N_frost.group_public_key;
}

void frost_clear_keys(void) {
    // Zero out all storage
    frost_storage_t zeros;
    memset(&zeros, 0, sizeof(zeros));
    nvm_write((void *)&N_frost_real, &zeros, sizeof(frost_storage_t));

    // Also reset context
    frost_ctx_reset();
}

// ============================================================================
// Signing Context Implementation
// ============================================================================

void frost_ctx_reset(void) {
    // Clear entire context including sensitive nonces
    explicit_bzero(&G_frost_ctx, sizeof(G_frost_ctx));
    G_frost_ctx.state = FROST_STATE_IDLE;
}

frost_state_t frost_ctx_get_state(void) {
    return G_frost_ctx.state;
}
