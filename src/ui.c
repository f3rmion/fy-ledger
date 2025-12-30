#include "ui.h"
#include "os.h"
#include "ux.h"
#include "glyphs.h"
#include <string.h>
#include <stdio.h>

// ============================================================================
// UI State
// ============================================================================

// Volatile for UI callbacks
static volatile bool G_user_approved;
static volatile bool G_user_responded;

// Buffers for display strings
static char G_line1[32];
static char G_line2[32];

// ============================================================================
// Helper Functions
// ============================================================================

// Convert bytes to hex string (renamed to avoid SDK conflict)
static void frost_bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char hex_chars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

// ============================================================================
// BAGL UI Elements (for Nano S/S+/X)
// ============================================================================

#ifdef HAVE_BAGL

// Idle screen - use standard dashboard icon
UX_STEP_NOCB(
    ux_idle_flow_1_step,
    pnn,
    {
        &C_icon_dashboard,
        "FROSTGUARD",
        "Ready",
    });

UX_STEP_NOCB(
    ux_idle_flow_2_step,
    bn,
    {
        "Version",
        APPVERSION,
    });

UX_STEP_VALID(
    ux_idle_flow_3_step,
    pb,
    os_sched_exit(-1),
    {
        &C_icon_dashboard_x,
        "Quit",
    });

UX_FLOW(ux_idle_flow,
        &ux_idle_flow_1_step,
        &ux_idle_flow_2_step,
        &ux_idle_flow_3_step);

// Approval callback
static void ui_callback_approve(void) {
    G_user_approved = true;
    G_user_responded = true;
}

// Rejection callback
static void ui_callback_reject(void) {
    G_user_approved = false;
    G_user_responded = true;
}

// Confirmation flow for key injection
UX_STEP_NOCB(
    ux_inject_flow_1_step,
    pnn,
    {
        &C_icon_warning,
        "Inject FROST",
        "Key Share?",
    });

UX_STEP_NOCB(
    ux_inject_flow_2_step,
    bnnn_paging,
    {
        .title = "Group Key",
        .text = G_line1,
    });

UX_STEP_NOCB(
    ux_inject_flow_3_step,
    bn,
    {
        "Participant",
        G_line2,
    });

UX_STEP_CB(
    ux_inject_flow_4_step,
    pb,
    ui_callback_approve(),
    {
        &C_icon_validate_14,
        "Approve",
    });

UX_STEP_CB(
    ux_inject_flow_5_step,
    pb,
    ui_callback_reject(),
    {
        &C_icon_crossmark,
        "Reject",
    });

UX_FLOW(ux_inject_flow,
        &ux_inject_flow_1_step,
        &ux_inject_flow_2_step,
        &ux_inject_flow_3_step,
        &ux_inject_flow_4_step,
        &ux_inject_flow_5_step);

// Confirmation flow for signing
UX_STEP_NOCB(
    ux_sign_flow_1_step,
    pnn,
    {
        &C_icon_certificate,
        "Sign with",
        "FROST?",
    });

UX_STEP_NOCB(
    ux_sign_flow_2_step,
    bnnn_paging,
    {
        .title = "Message Hash",
        .text = G_line1,
    });

UX_STEP_CB(
    ux_sign_flow_3_step,
    pb,
    ui_callback_approve(),
    {
        &C_icon_validate_14,
        "Sign",
    });

UX_STEP_CB(
    ux_sign_flow_4_step,
    pb,
    ui_callback_reject(),
    {
        &C_icon_crossmark,
        "Reject",
    });

UX_FLOW(ux_sign_flow,
        &ux_sign_flow_1_step,
        &ux_sign_flow_2_step,
        &ux_sign_flow_3_step,
        &ux_sign_flow_4_step);

#endif  // HAVE_BAGL

// ============================================================================
// UI Implementation
// ============================================================================

void ui_init(void) {
    G_user_approved = false;
    G_user_responded = false;
}

void ui_idle(void) {
#ifdef HAVE_BAGL
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_idle_flow, NULL);
#endif
}

bool ui_confirm_inject_keys(const uint8_t fingerprint[4], uint16_t identifier) {
    (void)fingerprint;
    (void)identifier;
    // TODO: Implement proper async UI flow for production
    // Auto-approve for Speculos testing
    return true;
}

bool ui_confirm_sign(const uint8_t message_hash[32]) {
    (void)message_hash;
    // TODO: Implement proper async UI flow for production
    // Auto-approve for Speculos testing
    return true;
}

void ui_processing(void) {
    // Could show a processing animation
}

void ui_success(void) {
    // Could show success message briefly
    ui_idle();
}

void ui_error(const char *message) {
    (void)message;
    // Could show error message briefly
    ui_idle();
}
