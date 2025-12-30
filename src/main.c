/**
 * FROSTGUARD Ledger Application
 *
 * FROST threshold signatures for Baby Jubjub curve.
 * Securely stores key shares and performs partial signing operations.
 */

#include "os.h"
#include "cx.h"
#include "os_io_seproxyhal.h"
#include "ux.h"

#include "globals.h"
#include "handler.h"
#include "frost_storage.h"
#include "ui.h"

// ============================================================================
// APDU Dispatcher
// ============================================================================

void app_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // Initialize storage
    frost_storage_init();

    // Initialize UI
    ui_init();
    ui_idle();

    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0;
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                if (rx == 0) {
                    THROW(SW_WRONG_LENGTH);
                }

                // Check CLA
                if (G_io_apdu_buffer[0] != CLA_DEFAULT) {
                    THROW(SW_CLA_NOT_SUPPORTED);
                }

                // Dispatch based on INS
                uint8_t ins = G_io_apdu_buffer[1];
                uint8_t p1 = G_io_apdu_buffer[2];
                uint8_t p2 = G_io_apdu_buffer[3];
                uint8_t lc = G_io_apdu_buffer[4];
                uint8_t *data = G_io_apdu_buffer + 5;

                // Response buffer starts after APDU header
                uint8_t *response = G_io_apdu_buffer;
                uint8_t response_len = 0;

                switch (ins) {
                    case INS_GET_VERSION:
                        sw = handle_get_version(response, &response_len);
                        break;

                    case INS_GET_PUBLIC_KEY:
                        sw = handle_get_public_key(response, &response_len);
                        break;

                    case INS_FROST_INJECT_KEYS:
                        sw = handle_inject_keys(p1, p2, data, lc,
                                                response, &response_len);
                        break;

                    case INS_FROST_COMMIT:
                        sw = handle_commit(response, &response_len);
                        break;

                    case INS_FROST_INJECT_MESSAGE:
                        sw = handle_inject_message(data, lc);
                        break;

                    case INS_FROST_INJECT_COMMITMENTS_P1:
                        sw = handle_inject_commitments_p1(p1, data, lc,
                                                          response, &response_len);
                        break;

                    case INS_FROST_INJECT_COMMITMENTS_P2:
                        sw = handle_inject_commitments_p2(data, lc,
                                                          response, &response_len);
                        break;

                    case INS_FROST_PARTIAL_SIGN:
                        sw = handle_partial_sign(response, &response_len);
                        break;

                    case INS_FROST_RESET:
                        sw = handle_reset();
                        break;

                    default:
                        THROW(SW_INS_NOT_SUPPORTED);
                }

                // Append status word
                tx = response_len;
                G_io_apdu_buffer[tx++] = (sw >> 8) & 0xFF;
                G_io_apdu_buffer[tx++] = sw & 0xFF;
            }
            CATCH(EXCEPTION_IO_RESET) {
                THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                    case 0x6000:
                        sw = e;
                        break;
                    case 0x9000:
                        sw = e;
                        break;
                    default:
                        sw = SW_INTERNAL_ERROR;
                        break;
                }

                // On error, reset signing state for safety
                if (sw != SW_OK && sw != SW_USER_REJECTED) {
                    frost_ctx_reset();
                }

                G_io_apdu_buffer[0] = (sw >> 8) & 0xFF;
                G_io_apdu_buffer[1] = sw & 0xFF;
                tx = 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}
