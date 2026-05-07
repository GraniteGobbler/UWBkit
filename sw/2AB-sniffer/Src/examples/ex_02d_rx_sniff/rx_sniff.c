/*! ----------------------------------------------------------------------------
 *  @file    rx_sniff.c
 *  @brief   RX using SNIFF mode example code
 *
 * @attention
 *
 * Copyright 2016 - 2021 (c) Decawave Ltd, Dublin, Ireland.
 *
 * All rights reserved.
 *
 * @author Decawave
 */
#include "deca_probe_interface.h"
#include <deca_device_api.h>
#include <deca_spi.h>
#include <deca_interface.h>
#include <dw3000_deca_regs.h>
#include <example_selection.h>
#include <port.h>
#include <shared_defines.h>
#include <shared_functions.h>
#include <string.h>

#include "./platform/uwbkit_shared.h"



/* Defines for sysstatus translation */
typedef struct {
    uint32_t    mask;
    const char *name;
} dwt_int_flag_t;

static const dwt_int_flag_t dwt_int_flags[] = {
    { DWT_INT_TIMER1_BIT_MASK,    "TIMER1"    },
    { DWT_INT_TIMER0_BIT_MASK,    "TIMER0"    },
    { DWT_INT_ARFE_BIT_MASK,      "ARFE"      },
    { DWT_INT_CPERR_BIT_MASK,     "CPERR"     },
    { DWT_INT_HPDWARN_BIT_MASK,   "HPDWARN"   },
    { DWT_INT_RXSTO_BIT_MASK,     "RXSTO"     },
    { DWT_INT_PLL_HILO_BIT_MASK,  "PLL_HILO"  },
    { DWT_INT_RCINIT_BIT_MASK,    "RCINIT"    },
    { DWT_INT_SPIRDY_BIT_MASK,    "SPIRDY"    },
    { DWT_INT_RXPTO_BIT_MASK,     "RXPTO"     },
    { DWT_INT_RXOVRR_BIT_MASK,    "RXOVRR"    },
    { DWT_INT_VWARN_BIT_MASK,     "VWARN"     },
    { DWT_INT_CIAERR_BIT_MASK,    "CIAERR"    },
    { DWT_INT_RXFTO_BIT_MASK,     "RXFTO"     },
    { DWT_INT_RXFSL_BIT_MASK,     "RXFSL"     },
    { DWT_INT_RXFCE_BIT_MASK,     "RXFCE"     },
    { DWT_INT_RXFCG_BIT_MASK,     "RXFCG"     },
    { DWT_INT_RXFR_BIT_MASK,      "RXFR"      },
    { DWT_INT_RXPHE_BIT_MASK,     "RXPHE"     },
    { DWT_INT_RXPHD_BIT_MASK,     "RXPHD"     },
    { DWT_INT_CIADONE_BIT_MASK,   "CIADONE"   },
    { DWT_INT_RXSFDD_BIT_MASK,    "RXSFDD"    },
    { DWT_INT_RXPRD_BIT_MASK,     "RXPRD"     },
    { DWT_INT_TXFRS_BIT_MASK,     "TXFRS"     },
    { DWT_INT_TXPHS_BIT_MASK,     "TXPHS"     },
    { DWT_INT_TXPRS_BIT_MASK,     "TXPRS"     },
    { DWT_INT_TXFRB_BIT_MASK,     "TXFRB"     },
    { DWT_INT_AAT_BIT_MASK,       "AAT"       },
    { DWT_INT_SPICRCE_BIT_MASK,   "SPICRCE"   },
    { DWT_INT_CP_LOCK_BIT_MASK,   "CP_LOCK"   },
    { DWT_INT_IRQS_BIT_MASK,      "IRQS"      },
};
#define DWT_INT_FLAG_COUNT (sizeof(dwt_int_flags) / sizeof(dwt_int_flags[0]))


#if defined(TEST_RX_SNIFF)

extern void test_run_info(unsigned char *data);

static void print_status_flags(uint32_t status)
{
    static char buf[32];
    for (size_t i = 0; i < DWT_INT_FLAG_COUNT; i++)
    {
        if (status & dwt_int_flags[i].mask)
        {
            snprintf(buf, sizeof(buf), "INT: %s", dwt_int_flags[i].name);
            test_run_info((unsigned char *)buf);
        }
    }
}


/* Example application name and version to display on LCD screen. */
#define APP_NAME "RX SNIFF v1.0"

/* Default communication configuration. We use default non-STS DW mode. */
/* ---- Modified be identical to CONFIG_OPTIO_33 in config_options.c: ---- 
SFD 1 to 3 
STS MODE OFF to 1
STS LEN 64 to 128
*/
static dwt_config_t config = {
    5,                /* Channel number. */
    DWT_PLEN_128,     /* Preamble length. Used in TX only. */
    DWT_PAC8,         /* Preamble acquisition chunk size. Used in RX only. */
    9,                /* TX preamble code. Used in TX only. */
    9,                /* RX preamble code. Used in RX only. */
    3,                /* 0 to use standard 8 symbol SFD, 1 to use non-standard 8 symbol, 2 for non-standard 16 symbol SFD and 3 for 4z 8 symbol SDF type */
    DWT_BR_6M8,       /* Data rate. */
    DWT_PHRMODE_STD,  /* PHY header mode. */
    DWT_PHRRATE_STD,  /* PHY header rate. */
    (129 + 8 - 8),    /* SFD timeout (preamble length + 1 + SFD length - PAC size). Used in RX only. */
    DWT_STS_MODE_1, /* STS disabled */
    DWT_STS_LEN_128,   /* STS length see allowed values in Enum dwt_sts_lengths_e */
    DWT_PDOA_M0       /* PDOA mode off */
};

/* SNIFF mode on/off times.
 * ON time is expressed in multiples of PAC size (with the IC adding 1 PAC automatically). So the ON time of 1 here gives 2 PAC times and, since the
 * configuration (above) specifies DWT_PAC8, we get an ON time of 2x8 symbols, or around 16 s.
 * OFF time is expressed in multiples of 128/125 s (~1 s).
 * These values will lead to a roughly 50% duty-cycle, each ON and OFF phase lasting for about 16 s. */
#define SNIFF_ON_TIME  2
#define SNIFF_OFF_TIME 16

#define CIR_DUMMY_BYTE   1
#define CIR_SAMPLES_64M  1016
#define CIR_SAMPLES_PER_READ  33
#define BYTES_PER_SAMPLE 6   // 3 real + 3 imaginary

/* Buffer to store received frame. See NOTE 1 below. */
static uint8_t rx_buffer[FRAME_LEN_MAX];

/* Hold copy of status register state here for reference so that it can be examined at a debug breakpoint. */
static uint32_t status_reg = 0;

/* Hold copy of frame length of frame received (if good) so that it can be examined at a debug breakpoint. */
static uint16_t frame_len = 0;

/* Buffer to store CIR accumulator data */
static uint8_t cir_buffer[CIR_SAMPLE_BYTES*CIR_SAMPLES_64M];



//External LEDToggle declaration
extern void LEDToggle_ms(uint8_t cnt, uint32_t ms, int LED_NUM);

/**
 * Application entry point.
 */
int rx_sniff(void)
{
    /* Display application name on LCD. */
    test_run_info((unsigned char *)APP_NAME);

    /* Configure SPI rate, DW3000 supports up to 36 MHz */
    port_set_dw_ic_spi_fastrate();

    /* Reset DW IC */
    reset_DWIC(); /* Target specific drive of RSTn line into DW IC low for a period. */

    Sleep(2); // Time needed for DW3000 to start up (transition from INIT_RC to IDLE_RC, or could wait for SPIRDY event)

    /* Probe for the correct device driver. */
    dwt_probe((struct dwt_probe_s *)&dw3000_probe_interf);

    while (!dwt_checkidlerc()) /* Need to make sure DW IC is in IDLE_RC before proceeding */ { };

    if (dwt_initialise(DWT_DW_INIT) == DWT_ERROR)
    {
        test_run_info((unsigned char *)"INIT FAILED     ");
        while (1) { };
    }

    /* This is put here for testing, so that we can see the receiver ON/OFF pattern using an oscilloscope. */
    dwt_setlnapamode(DWT_LNA_ENABLE | DWT_PA_ENABLE);

    /* Configure DW IC. */
    /* if the dwt_configure returns DWT_ERROR either the PLL or RX calibration has failed the host should reset the device */
    if (dwt_configure(&config))
    {
        test_run_info((unsigned char *)"CONFIG FAILED     ");
        while (1) { };
    }

    /* Configure SNIFF mode. */
    dwt_setsniffmode(1, SNIFF_ON_TIME, SNIFF_OFF_TIME);


    /* Loop forever receiving frames. */
    while (1)
    {
        int i = 0;

        /* TESTING BREAKPOINT LOCATION #1 */
        //LEDToggle_ms(1, 50, LED_2);

        /* Clear local RX buffer to avoid having leftovers from previous receptions. This is not necessary but is included here to aid reading
         * the RX buffer.
         * This is a good place to put a breakpoint. Here (after first time through the loop) the local status register will be set for last event
         * and if a good receive has happened the data buffer will have the data in it, and frame_len will be set to the length of the RX frame. */
        for (i = 0; i < FRAME_LEN_MAX; i++)
        {
            rx_buffer[i] = 0;
        }

        /* Activate reception immediately. See NOTE 3 below. */
        dwt_rxenable(DWT_START_RX_IMMEDIATE);

   
        /* Poll until a frame is properly received or an RX error occurs. See NOTE 4 below.
         * STATUS register is 5 bytes long but we are not interested in the high byte here, so we read a more manageable 32-bits with this API call. */
        waitforsysstatus(&status_reg, NULL, (DWT_INT_RXFCG_BIT_MASK | SYS_STATUS_ALL_RX_ERR), 0);
        
        
        if (status_reg & DWT_INT_RXFCG_BIT_MASK)
        {
            /* Clear good RX frame event in the DW IC status register. */
            dwt_writesysstatuslo(DWT_INT_RXFCG_BIT_MASK);

            print_status_flags(status_reg);  //Only for debugging
            test_run_info((unsigned char *)"");

            /* A frame has been received, copy it to our local buffer. */
            frame_len = dwt_getframelength();
            if (frame_len <= FRAME_LEN_MAX)
            {               
                /* rx_buffer stores PHY payload, ex. { 0x41, 0x88, 0, 0xCA, 0xDE, 'W', 'A', 'V', 'E', 0xE0, 0, 0 } */
                dwt_readrxdata(rx_buffer, frame_len, 0); 
                /* cir_buffer stores significant part of ACC_MEM without the dummy byte from SPI reads*/
                cir_read(cir_buffer, CIR_SAMPLES_64M);  // 1016 samples in 64M PRF mode

                //uart_send_rx_as_zep(rx_buffer, frame_len, 5);
                uart_send_rx_and_cir_fragments_as_zep(rx_buffer, frame_len, cir_buffer, 
                                                      (uint16_t)(CIR_SAMPLES_64M * CIR_SAMPLE_BYTES), 5);
                
                LEDToggle_ms(1, 50, LED_2); // Blink LED 2 after UART transmit
            }         
            
        }
        else
        {
            /* Clear RX error events in the DW IC status register. */
            dwt_writesysstatuslo(SYS_STATUS_ALL_RX_ERR);
        }
    }
}
#endif
/*****************************************************************************************************************************************************
 * NOTES:
 *
 * 1. In this example, maximum frame length is set to 127 bytes which is 802.15.4 UWB standard maximum frame length. DW IC supports an extended
 *    frame length (up to 1023 bytes long) mode which is not used in this example.
 * 2. In this example, the DW IC is put into IDLE state after calling dwt_initialise(). This means that a fast SPI rate of up to 20 MHz can be used
 *    thereafter.
 * 3. Manual reception activation is performed here but DW IC offers several features that can be used to handle more complex scenarios or to
 *    optimise system's overall performance (e.g. timeout after a given time, automatic re-enabling of reception in case of errors, etc.).
 * 4. We use polled mode of operation here to keep the example as simple as possible but RXFCG and error/timeout status events can be used to generate
 *    interrupts. Please refer to DW IC User Manual for more details on "interrupts".
 * 5. The user is referred to DecaRanging ARM application (distributed with EVK1000 product) for additional practical example of usage, and to the
 *    DW IC API Guide for more details on the DW IC driver functions.
 ****************************************************************************************************************************************************/
