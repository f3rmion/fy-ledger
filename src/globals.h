#pragma once

#include "os.h"
#include "ux.h"
#include "os_io_seproxyhal.h"

// ============================================================================
// Global Variables
// ============================================================================

// APDU buffer
extern uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

// UX state
extern ux_state_t G_ux;
extern bolos_ux_params_t G_ux_params;

// ============================================================================
// Application Constants
// ============================================================================

#ifndef MAJOR_VERSION
#define MAJOR_VERSION 1
#endif

#ifndef MINOR_VERSION
#define MINOR_VERSION 0
#endif

#ifndef PATCH_VERSION
#define PATCH_VERSION 0
#endif
