/*! ----------------------------------------------------------------------------
 * @file    custom_board_nrf52840.h
 * @brief   Pin definitions for DW3000 / DWM3001C connected to an nRF52840 board.
 *
 *
 * Copyright 2024 (c) Port contributor.  Apache 2.0 License.
 * ----------------------------------------------------------------------------
 */

#include "nrf_gpio.h"
#include "nrf_spim.h"
#include "nrfx_uarte.h"

#ifndef CUSTOM_BOARD_NRF52840_H
#define CUSTOM_BOARD_NRF52840_H

#ifdef __cplusplus
extern "C" {
#endif

// LEDs definitions for PCA10056
//#define LEDS_NUMBER    4
#define LEDS_NUMBER    2

#define LED_1          NRF_GPIO_PIN_MAP(0,3)
#define LED_2          NRF_GPIO_PIN_MAP(1,13)
//#define LED_3          NRF_GPIO_PIN_MAP(,)
//#define LED_4          NRF_GPIO_PIN_MAP(,)
#define LED_START      LED_1
#define LED_STOP       LED_2
//#define LED_STOP       LED_4

#define LEDS_ACTIVE_STATE 0

//#define LEDS_LIST { LED_1, LED_2, LED_3, LED_4 }
#define LEDS_LIST { LED_1, LED_2 }

#define LEDS_INV_MASK  LEDS_MASK

#define BSP_LED_0      NRF_GPIO_PIN_MAP(0,3)
#define BSP_LED_1      NRF_GPIO_PIN_MAP(1,13)
//#define BSP_LED_2      15
//#define BSP_LED_3      16

//#define BUTTONS_NUMBER 4
#define BUTTONS_NUMBER 0
//#define BUTTON_1       11
//#define BUTTON_2       12
//#define BUTTON_3       24
//#define BUTTON_4       25
//#define BUTTON_PULL    NRF_GPIO_PIN_PULLUP

#define BUTTONS_ACTIVE_STATE 0

//#define BUTTONS_LIST { BUTTON_1, BUTTON_2, BUTTON_3, BUTTON_4 }

//#define BSP_BUTTON_0   BUTTON_1
//#define BSP_BUTTON_1   BUTTON_2
//#define BSP_BUTTON_2   BUTTON_3
//#define BSP_BUTTON_3   BUTTON_4




/* ---- DW3000 SPI interface ---- */
#define DW3000_CLK_Pin      NRF_GPIO_PIN_MAP(0,16)   /**< P0.16 - QM33120W SPI clock */
#define DW3000_MOSI_Pin     NRF_GPIO_PIN_MAP(0,17)   /**< P0.17 - QM33120W SPI MOSI  */
#define DW3000_MISO_Pin     NRF_GPIO_PIN_MAP(0,23)  /**< P0.23 - QM33120W SPI MISO  */
#define DW3000_CS_Pin       NRF_GPIO_PIN_MAP(0,20)  /**< P0.20 - QM33120W SPI chip-select (active-low) */

/* ---- DW3000 control / IRQ lines ---- */
#define DW3000_IRQ_Pin      NRF_GPIO_PIN_MAP(0,25)  /**< P0.25 - QM33120W interrupt (rising edge) */
#define DW3000_RST_Pin      NRF_GPIO_PIN_MAP(0,15)  /**< P0.15 - QM33120W hard reset (active-low) */
#define DW3000_WUP_Pin      NRF_GPIO_PIN_MAP(1,2)  /**< P1.02 - QM33120W wake-up pin             */

/* ---- Optional UART debug ---- */
#define RX_PIN_NUMBER    NRF_GPIO_PIN_MAP(0,8)
#define TX_PIN_NUMBER    NRF_GPIO_PIN_MAP(0,7)
#define CTS_PIN_NUMBER   NRF_UARTE_PSEL_DISCONNECTED
#define RTS_PIN_NUMBER   NRF_UARTE_PSEL_DISCONNECTED
#define HWFC             false

#ifdef __cplusplus
}
#endif

#endif /* CUSTOM_BOARD_NRF52840_H */
