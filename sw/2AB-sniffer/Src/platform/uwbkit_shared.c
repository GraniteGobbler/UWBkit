#include "uwbkit_shared.h"
#include "shared_defines.h"

static const nrfx_uarte_t m_uarte = NRFX_UARTE_INSTANCE(0);
static volatile bool m_tx_busy = false;
static uint8_t m_uart_tx_buf[UART_TX_BUF_SIZE];
static uint8_t m_zep_buf[ZEP_BUF_SIZE];
static uint32_t m_seq = 0;

extern void dwt_readaccdata(uint8_t *buffer, uint16_t len, uint16_t accOffset);

static void uarte_handler(nrfx_uarte_event_t const *p_event, void *p_context)
{
    (void)p_context;

    if (p_event->type == NRFX_UARTE_EVT_TX_DONE)
    {
        m_tx_busy = false;
    }
    else if (p_event->type == NRFX_UARTE_EVT_ERROR)
    {
        m_tx_busy = false;
    }
}

void uart_init(void)
{
    nrfx_uarte_config_t config = NRFX_UARTE_DEFAULT_CONFIG;
    config.pseltxd  = TX_PIN_NUMBER;
    config.pselrxd  = RX_PIN_NUMBER;
    config.pselrts  = NRF_UARTE_PSEL_DISCONNECTED;
    config.pselcts  = NRF_UARTE_PSEL_DISCONNECTED;
    config.hwfc     = NRF_UARTE_HWFC_DISABLED;
    config.parity   = NRF_UARTE_PARITY_EXCLUDED;
    config.baudrate = NRF_UARTE_BAUDRATE_115200;

    APP_ERROR_CHECK(nrfx_uarte_init(&m_uarte, &config, uarte_handler));
}

static uint16_t crc16_ccitt(const uint8_t *data, uint16_t len)
{
    uint16_t crc = 0xFFFF;

    for (uint16_t i = 0; i < len; i++)
    {
        crc ^= (uint16_t)data[i] << 8;
        for (uint8_t b = 0; b < 8; b++)
        {
            if (crc & 0x8000)
            {
                crc = (crc << 1) ^ 0x1021;
            }
            else
            {
                crc <<= 1;
            }
        }
    }

    return crc;
}

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFF);
}

static void put_be64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
    {
        p[i] = (uint8_t)(v >> (56 - 8 * i));
    }
}

static uint8_t build_dummy_ieee154(uint8_t *out)
{
    static const uint8_t frame[DUMMY_IEEE154_LEN] = {
        0x41, 0x88,
        0x01,
        0x34, 0x12,
        0x78, 0x56,
        0xBC, 0x9A,
        0xAA, 0x55
    };

    memcpy(out, frame, sizeof(frame));
    return sizeof(frame);
}

uint16_t build_zep_v2_packet(uint8_t *out, uint8_t channel, uint16_t device_id, uint32_t seqno)
{
    uint8_t ieee_len = build_dummy_ieee154(&out[ZEP_V2_HDR_LEN]);

    out[0] = 'E';
    out[1] = 'X';
    out[2] = 0x02;
    out[3] = 0x01;
    out[4] = channel;
    put_be16(&out[5], device_id);
    out[7] = 0x00;
    out[8] = 0xFF;
    put_be64(&out[9], 0);
    put_be32(&out[17], seqno);
    memset(&out[21], 0, 10);
    out[31] = ieee_len;

    return (uint16_t)(ZEP_V2_HDR_LEN + ieee_len);
}

uint16_t build_zep_packet_from_rx(uint8_t *out, const uint8_t *rx_buffer, uint16_t rx_len, uint8_t channel, uint16_t device_id, uint32_t seqno)
{
    if (rx_len > FRAME_LEN_MAX) 
    {
      return 0;
    }

    out[0] = 'E';
    out[1] = 'X';
    out[2] = 0x02;
    out[3] = 0x01;
    out[4] = channel;
    put_be16(&out[5], device_id);
    out[7] = 0x00;
    out[8] = 0xFF;
    put_be64(&out[9], 0);
    put_be32(&out[17], seqno);
    memset(&out[21], 0, 10);
    out[31] = rx_len;

    memcpy(&out[ZEP_V2_HDR_LEN], rx_buffer, rx_len);

    return (uint16_t)(ZEP_V2_HDR_LEN + rx_len);
}


uint16_t build_zepv3_packet_from_rx(uint8_t *out,
                                    const uint8_t *rx_buffer,
                                    uint16_t rx_len,
                                    uint8_t channel,
                                    uint16_t device_id,
                                    uint32_t seqno,
                                    uint64_t rel_timestamp,
                                    uint8_t band,
                                    uint8_t channel_page,
                                    uint8_t lqi,
                                    bool crc_mode)
{
    if (rx_len > FRAME_LEN_MAX) {
        return 0;
    }

    out[0] = 'E';
    out[1] = 'X';
    out[2] = 0x03;                  /* ZEPv3 */
    out[3] = 0x01;                  /* data */
    out[4] = channel;
    put_be16(&out[5], device_id);
    out[7] = crc_mode ? 0x01 : 0x00;
    out[8] = lqi;

    put_be64(&out[9], rel_timestamp);
    put_be32(&out[17], seqno);

    out[21] = band;
    out[22] = channel_page;
    memset(&out[23], 0, 8);

    out[31] = (uint8_t)rx_len;

    memcpy(&out[ZEP_V3_HDR_LEN], rx_buffer, rx_len);

    return (uint16_t)(ZEP_V3_HDR_LEN + rx_len);
}

uint16_t wrap_uart_frame(const uint8_t *zep, uint16_t zep_len, uint8_t *out)
{
    uint16_t crc = crc16_ccitt(zep, zep_len);

    out[0] = UART_SYNC0;
    out[1] = UART_SYNC1;
    out[2] = (uint8_t)(zep_len & 0xFF);
    out[3] = (uint8_t)(zep_len >> 8);
    memcpy(&out[4], zep, zep_len);
    out[4 + zep_len] = (uint8_t)(crc & 0xFF);
    out[5 + zep_len] = (uint8_t)(crc >> 8);

    return (uint16_t)(zep_len + UART_WRAPPER_OVERHEAD);
}

void uart_send_blocking(const uint8_t *data, uint16_t len)
{
    while (m_tx_busy)
    {
    }

    memcpy(m_uart_tx_buf, data, len);
    m_tx_busy = true;
    APP_ERROR_CHECK(nrfx_uarte_tx(&m_uarte, m_uart_tx_buf, len));

    while (m_tx_busy)
    {
    }
}


void uart_send_rx_as_zep(const uint8_t *rx_buffer, uint16_t rx_len, uint8_t channel)
{
    //uint16_t zep_len = build_zep_packet_from_rx(m_zep_buf, rx_buffer, rx_len, channel, 0x1234, m_seq++);
    
    /* rx_buffer[2] - Sequence number in ds_twr_initiator_sts.c */
    uint16_t zep_len = build_zepv3_packet_from_rx(m_zep_buf, rx_buffer, rx_len, channel, 0x1234, rx_buffer[2], 0, 0, 0, 0, 0);
        
    if (zep_len == 0) {
        return;
    }

    uint16_t uart_len = wrap_uart_frame(m_zep_buf, zep_len, m_uart_tx_buf);
    uart_send_blocking(m_uart_tx_buf, uart_len);
}


void cir_read(uint8_t *out, uint16_t total_samples)
{
    uint16_t offset = 0;
    static uint8_t tmp_buf[MAX_LEN_PER_CALL];
    while (offset < total_samples)
    {
        uint16_t chunk = total_samples - offset;
        if (chunk > MAX_SAMPLES_PER_CALL)
            chunk = MAX_SAMPLES_PER_CALL;

        uint16_t length = chunk * CIR_SAMPLE_BYTES + 1; // +1 for dummy byte

        dwt_readaccdata(tmp_buf, length, offset);

        // skip dummy byte [0], copy real samples
        memcpy(out + offset * CIR_SAMPLE_BYTES,
               tmp_buf + 1,
               chunk * CIR_SAMPLE_BYTES);

        offset += chunk;
    }
}

static uint16_t min_u16(uint16_t a, uint16_t b)
{
    return (a < b) ? a : b;
}


void uart_send_rx_and_cir_fragments_as_zep(const uint8_t *rx_buffer, uint16_t rx_len, const uint8_t *cir_buffer, uint16_t cir_len, uint8_t channel)
{
    static uint8_t phy_frame[FRAME_LEN_MAX];
    uint16_t offset = 0;
    uint8_t frag_idx = 0;
    uint16_t payload_room;

    if ((rx_buffer == NULL) || (cir_buffer == NULL))
    {
        return;
    }

    if (rx_len > FRAME_LEN_MAX)
    {
        return;
    }

    if ((uint16_t)(rx_len + CIR_FRAG_HDR_LEN) > FRAME_LEN_MAX)
    {
        return;
    }

    payload_room = (uint16_t)(FRAME_LEN_MAX - rx_len - CIR_FRAG_HDR_LEN);
    if (payload_room == 0)
    {
        return;
    }

    while (offset < cir_len)
    {
        uint16_t chunk = min_u16((uint16_t)(cir_len - offset), payload_room);
        uint16_t total_len = (uint16_t)(rx_len + CIR_FRAG_HDR_LEN + chunk);

        memcpy(phy_frame, rx_buffer, rx_len);

        /* Reuse original RX frame as base, but make each fragment sequence unique. */
        //phy_frame[2] = (uint8_t)(rx_buffer[2] + frag_idx);

        /* Custom CIR fragment header placed after the original RX payload. */
        phy_frame[rx_len + 0] = CIR_FRAGMENT_TAG;
        phy_frame[rx_len + 1] = (uint8_t)(cir_len >> 8);
        phy_frame[rx_len + 2] = (uint8_t)(cir_len & 0xFF);
        phy_frame[rx_len + 3] = frag_idx;
        phy_frame[rx_len + 4] = (uint8_t)chunk;

        memcpy(&phy_frame[rx_len + CIR_FRAG_HDR_LEN],
               &cir_buffer[offset],
               chunk);

        uart_send_rx_as_zep(phy_frame, total_len, channel);

        offset = (uint16_t)(offset + chunk);
        frag_idx++;
    }
}