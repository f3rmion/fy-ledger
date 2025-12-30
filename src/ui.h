#pragma once

#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// UI Functions
// ============================================================================

// Initialize UI
void ui_init(void);

// Show idle screen (app home)
void ui_idle(void);

// Confirm key injection
// Shows group key fingerprint and participant ID
// Returns true if user approved, false if rejected
bool ui_confirm_inject_keys(const uint8_t fingerprint[4], uint16_t identifier);

// Confirm signing operation
// Shows message hash preview
// Returns true if user approved, false if rejected
bool ui_confirm_sign(const uint8_t message_hash[32]);

// Show processing screen (for long operations)
void ui_processing(void);

// Show success screen
void ui_success(void);

// Show error screen
void ui_error(const char *message);
