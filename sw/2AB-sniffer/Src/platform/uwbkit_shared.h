#ifndef UWBKIT_SHARED_H
#define UWBKIT_SHARED_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <boards.h>

#include "nrf_delay.h"
#include "nrfx_uarte.h"
#include "app_error.h"

#define UART_SYNC0 0xAB
#define UART_SYNC1 0xCD
#define UART_WRAPPER_OVERHEAD 6
#define ZEP_V2_HDR_LEN 32
#define ZEP_V3_HDR_LEN 32
#define DUMMY_IEEE154_LEN 11
#define ZEP_BUF_SIZE 192
#define UART_TX_BUF_SIZE 256

#define CIR_DUMMY_BYTE        1
#define CIR_SAMPLE_BYTES      6
#define MAX_LEN_PER_CALL      199    // DATALEN1 - 1 header byte
#define CIR_SAMPLES_64M       1016  // 64 MHz PRF CIR length
#define MAX_PAYLOAD_PER_CALL  (MAX_LEN_PER_CALL - 1)         // minus 1 dummy byte = 198
#define MAX_SAMPLES_PER_CALL  (MAX_PAYLOAD_PER_CALL / CIR_SAMPLE_BYTES)  // = 33

#define CIR_FRAGMENT_TAG     0xC1
#define CIR_FRAG_HDR_LEN     5


static volatile bool m_tx_busy;
static uint8_t m_uart_tx_buf[UART_TX_BUF_SIZE];
static uint8_t m_zep_buf[ZEP_BUF_SIZE];
static uint32_t m_seq;

static void uarte_handler(nrfx_uarte_event_t const *p_event, void *p_context);
void uart_init(void);
static uint16_t crc16_ccitt(const uint8_t *data, uint16_t len);
static void put_be16(uint8_t *p, uint16_t v);
static void put_be32(uint8_t *p, uint32_t v);
static void put_be64(uint8_t *p, uint64_t v);
static uint8_t build_dummy_ieee154(uint8_t *out);
uint16_t build_zep_packet_from_rx(uint8_t *out, const uint8_t *rx_buffer, uint16_t rx_len, uint8_t channel, uint16_t device_id, uint32_t seqno);
uint16_t build_zep_v2_packet(uint8_t *out, uint8_t channel, uint16_t device_id, uint32_t seqno);
uint16_t build_zepv3_packet_from_rx(uint8_t *out, const uint8_t *rx_buffer, uint16_t rx_len, uint8_t channel, uint16_t device_id, uint32_t seqno, uint64_t rel_timestamp, uint8_t band, uint8_t channel_page, uint8_t lqi, bool crc_mode);
uint16_t wrap_uart_frame(const uint8_t *zep, uint16_t zep_len, uint8_t *out);
void uart_send_blocking(const uint8_t *data, uint16_t len);
void uart_send_rx_as_zep(const uint8_t *rx_buffer, uint16_t rx_len, uint8_t channel);
void cir_read(uint8_t *out, uint16_t total_samples);
void uart_send_rx_and_cir_fragments_as_zep(const uint8_t *rx_buffer, uint16_t rx_len, const uint8_t *cir_buffer, uint16_t cir_len, uint8_t channel);
static uint16_t min_u16(uint16_t a, uint16_t b);

#endif