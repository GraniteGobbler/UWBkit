/*! ----------------------------------------------------------------------------
 * @file    sdk_config_nrf52840.h
 * @brief   nRF5 SDK configuration overrides for nRF52840.
 *
 * This file is included INSTEAD OF (or in addition to) the SDK's default
 * sdk_config.h. Place it in your include path before the SDK version so
 * that its defines take priority.
 *
 * Only settings that differ from the nRF52833 defaults used in the original
 * DWM3001C project are listed here. All other settings are inherited from
 * the SDK's sdk_config.h.
 * ----------------------------------------------------------------------------
 */

#ifndef SDK_CONFIG_NRF52840_H
#define SDK_CONFIG_NRF52840_H

/* Sanity check: ensure we are building for nRF52840 */
#ifndef NRF52840_XXAA
  #error "This sdk_config override is for NRF52840_XXAA only."
#endif

/* ------------------------------------------------------------------
 * Board selection
 * With BOARD_CUSTOM the application is responsible for defining
 * all pin numbers (see custom_board_nrf52840.h).
 * ------------------------------------------------------------------ */
#define BOARD_CUSTOM 1

/* ------------------------------------------------------------------
 * SPIM3 is available on both nRF52833 and nRF52840 and supports
 * 32 MHz operation.  No changes needed for the SPI driver.
 * ------------------------------------------------------------------ */
#define NRFX_SPIM_ENABLED       1
#define NRFX_SPIM3_ENABLED      1
#define SPI_ENABLED             1
#define SPI3_ENABLED            1
#define SPI_DEFAULT_CONFIG_IRQ_PRIORITY  6

/* ------------------------------------------------------------------
 * GPIOTE
 * ------------------------------------------------------------------ */
#define GPIOTE_ENABLED          1
#define NRFX_GPIOTE_ENABLED     1

/* ------------------------------------------------------------------
 * Clock driver
 * ------------------------------------------------------------------ */
#define CLOCK_ENABLED           1
#define NRFX_CLOCK_ENABLED      1

/* ------------------------------------------------------------------
 * Logging (Segger RTT back-end)
 * ------------------------------------------------------------------ */
#define NRF_LOG_ENABLED         1
#define NRF_LOG_DEFAULT_LEVEL   4   /* DEBUG */
#define NRF_LOG_BACKEND_RTT_ENABLED  1
#define NRF_LOG_DEFERRED        0

/* ------------------------------------------------------------------
 * Memory configuration
 * nRF52840 has 256 KB RAM so we can afford larger buffers.
 * ------------------------------------------------------------------ */
#define NRF_BALLOC_ENABLED      1
#define NRF_MEMOBJ_ENABLED      1

#endif /* SDK_CONFIG_NRF52840_H */
