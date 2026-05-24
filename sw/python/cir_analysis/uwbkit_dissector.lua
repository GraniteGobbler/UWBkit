-- =============================================================================
-- UWB Custom UART Frame Dissector for Wireshark (Lua)
-- Compatible with Wireshark 1.12+
--
-- Decodes frames produced by uart_send_custom_packet() in firmware.
-- Transport: raw UDP on port 17754 carrying the unwrapped inner payload
-- (i.e. after the UART SYNC+LEN+CRC16 wrapper has been stripped).
--
-- ==============================================================================
--  INNER PAYLOAD LAYOUT  (all offsets from byte 0 of the UDP payload)
-- ==============================================================================
--
--  ┌───────────────────────────────────────────────────────────────────────────┐
--  │ Bytes       │ Block        │ Size  │ Description                          │
--  ├─────────────┼──────────────┼───────┼──────────────────────────────────────┤
--  │  BLOCK 1 — DIAGNOSTIC  (CUSTOM_DIAG_LEN = 33 B)                           │
--  │  0 –   1    │ Diag magic   │  2 B  │ ASCII "DG" (0x44 0x47)               │
--  │  2 –   6    │ ipatovRxTime │  5 B  │ BE * (1/(128*499.2e6)) → seconds     │
--  │  7 –  10    │ ipatovPeak   │  4 B  │ BE uint32 (raw dwt register)         │
--  │             │  Peak Index  │       │ bits 21:30 → (val>>21)&0x3FF         │
--  │             │  Peak Ampl.  │       │ bits  0:20 → val&0x1FFFFF / 2        │
--  │ 11 –  14    │ ipatovPower  │  4 B  │ BE uint32; bits 0:19 → val&0xFFFFF   │
--  │ 15 –  18    │ ipatovF1     │  4 B  │ BE uint32; bits 0:21 → val&0x3FFFFF/4│
--  │ 19 –  22    │ ipatovF2     │  4 B  │ BE uint32; bits 0:21 → val&0x3FFFFF/4│
--  │ 23 –  26    │ ipatovF3     │  4 B  │ BE uint32; bits 0:21 → val&0x3FFFFF/4│
--  │ 27 –  28    │ ipatovFpIdx  │  2 B  │ BE uint16; bits 6:15 → (val>>6)&0x3FF│
--  │ 29 –  30    │ ipatovAccum  │  2 B  │ BE uint16; bits 0:11 → val&0xFFF     │
--  │ 31          │ DGC Decision │  1 B  │ nlos_diag.D (full byte)              │
--  │ 32          │ Diag seqno   │  1 B  │ MAC seqno copied from RX frame       │
--  ├─────────────┼──────────────┼───────┼──────────────────────────────────────┤
--  │  BLOCK 2 — CONFIG / RSVD-A  (CUSTOM_RSVD_A_LEN = 32 B)                    │
--  │ 33 –  36    │ m_seq        │  4 B  │ BE uint32 monotonic packet counter   │
--  │ 37 –  38    │ m_rx_len     │  2 B  │ BE uint16 RX payload length          │
--  │ 39          │ chan         │  1 B  │ UWB channel number                   │
--  │ 40          │ dataRate     │  1 B  │ dwt_uwb_bit_rate_e                   │
--  │ 41          │ txCode       │  1 B  │ TX preamble code                     │
--  │ 42          │ rxCode       │  1 B  │ RX preamble code                     │
--  │ 43          │ txPreambLen  │  1 B  │ dwt_tx_plen_e                        │
--  │ 44          │ rxPAC        │  1 B  │ dwt_pac_size_e                       │
--  │ 45          │ sfdType      │  1 B  │ dwt_sfd_type_e                       │
--  │ 46          │ phrMode      │  1 B  │ dwt_phr_mode_e                       │
--  │ 47          │ phrRate      │  1 B  │ dwt_phr_rate_e                       │
--  │ 48 –  49    │ sfdTO        │  2 B  │ BE uint16 SFD timeout                │
--  │ 50          │ stsMode      │  1 B  │ dwt_sts_mode_e                       │
--  │ 51          │ stsLength    │  1 B  │ dwt_sts_lengths_e                    │
--  │ 52          │ pdoaMode     │  1 B  │ dwt_pdoa_mode_e                      │
--  │ 53 –  64    │ reserved     │ 12 B  │ zero-padded                          │
--  ├─────────────┼──────────────┼───────┼──────────────────────────────────────┤
--  │ BLOCK 3 — RX SLOT (CUSTOM_RX_SLOT = 127 B, zero-padded)                   │
--  │  If Frame Control == 0x8841 (Decawave ranging frame):                     │
--  │  Common header (all frames):                                              │
--  │ 65 – 66     │ Frame Ctrl   │ 2 B   │ LE uint16; 0x8841                    │
--  │ 67          │ MAC SeqNo    │ 1 B   │                                      │
--  │ 68 – 69     │ PAN ID       │ 2 B   │ LE uint16; 0xDECA                    │
--  │ 70 – 71     │ Dst Addr     │ 2 B   │ LE uint16                            │
--  │ 72 – 73     │ Src Addr     │ 2 B   │ LE uint16                            │
--  │ 74          │ Func Code    │ 1 B   │ 0xe0=Poll 0xe1=Resp 0xe2=Final       │
--  │  Poll only (rx_len = 12):                                                 │
--  │ 75 – 76     │ DW CRC       │ 2 B   │ Auto-set by DW IC                    │
--  │  Response / Final only (rx_len = 20):                                     │
--  │ 75 – 78     │ Poll RX TS   │ 4 B   │ Poll reception timestamp             │
--  │ 79 – 82     │ Resp TX TS   │ 4 B   │ Response transmission timestamp      │
--  │ 83 – 84     │ DW CRC       │ 2 B   │ Auto-set by DW IC                    │
--  │  Remaining bytes are zero-padding to fill the 127-byte slot               │
--  ├─────────────┼──────────────┼───────┼──────────────────────────────────────┤
--  │  BLOCK 4 — CIR DATA  (CUSTOM_CIR_LEN = 6096 B)                            │
--  │ 192 – 6287  │ CIR raw data │6096 B │ accumulator samples, raw bytes       │
--  │             │              │       │ decoded externally (see Python)      │
--  └─────────────┴──────────────┴───────┴──────────────────────────────────────┘
-- ==============================================================================

local _ok, p_kit = pcall(Proto, "uwb_kit", "UWBkit Dissector")
if not _ok then return end

-- ---------------------------------------------------------------------------
-- Block offsets (firmware constants)
-- ---------------------------------------------------------------------------
local DIAG_OFF      =   0
local DIAG_LEN      =  33
local RSVD_A_OFF    =  33
local RSVD_A_LEN    =  32
local RX_SLOT_OFF   =  65
local RX_SLOT_LEN   = 127
local CIR_OFF       = 192
local CIR_LEN       = 6096
local TOTAL_LEN     = 6288

local FCTL_DW_RANGING = 0x8841

local FUNC_POLL     = 0xe0
local FUNC_RESPONSE = 0xe1
local FUNC_FINAL    = 0xe2

local IPATOV_TIME_SCALE = 1.0 / (128.0 * 499.2e6)
local PWR_OFFSET        = -121.7

-- ---------------------------------------------------------------------------
-- Enum translation tables  (raw byte value → human-readable string)
-- ---------------------------------------------------------------------------

-- dwt_uwb_bit_rate_e
local DWT_BR = {
    [0] = "DWT_BR_850K (850 kbits/s)",
    [1] = "DWT_BR_6M8 (6.8 Mbits/s)",
    [2] = "DWT_BR_NODATA (SP3, no data)",
}

-- dwt_pac_size_e
local DWT_PAC = {
    [0] = "DWT_PAC8  (≤128 sym preamble)",
    [1] = "DWT_PAC16 (256 sym preamble)",
    [2] = "DWT_PAC32 (512 sym preamble)",
    [3] = "DWT_PAC4  (<127 sym preamble)",
}

-- dwt_tx_plen_e  (register-encoded values, not sequential)
local DWT_PLEN = {
    [0x01] = "DWT_PLEN_64   (64 sym)",
    [0x02] = "DWT_PLEN_1024 (1024 sym)",
    [0x03] = "DWT_PLEN_4096 (4096 sym)",
    [0x04] = "DWT_PLEN_32   (32 sym)",
    [0x05] = "DWT_PLEN_128  (128 sym)",
    [0x06] = "DWT_PLEN_1536 (1536 sym)",
    [0x07] = "DWT_PLEN_72   (72 sym)",
    [0x09] = "DWT_PLEN_256  (256 sym)",
    [0x0A] = "DWT_PLEN_2048 (2048 sym)",
    [0x0D] = "DWT_PLEN_512  (512 sym)",
}

-- dwt_sfd_type_e
local DWT_SFD = {
    [0] = "DWT_SFD_IEEE_4A (IEEE 8-bit ternary, len 8)",
    [1] = "DWT_SFD_DW_8    (DW 8-bit, len 8)",
    [2] = "DWT_SFD_DW_16   (DW 16-bit, len 16)",
    [3] = "DWT_SFD_IEEE_4Z (IEEE 8-bit binary / 4z, len 8)",
}

-- dwt_phr_mode_e
local DWT_PHRMODE = {
    [0] = "DWT_PHRMODE_STD (standard)",
    [1] = "DWT_PHRMODE_EXT (extended frames)",
}

-- dwt_phr_rate_e
local DWT_PHRRATE = {
    [0] = "DWT_PHRRATE_STD (standard rate)",
    [1] = "DWT_PHRRATE_DTA (data rate / 6M81)",
}

-- dwt_sts_mode_e
local DWT_STS_MODE = {
    [0x0] = "DWT_STS_MODE_OFF (STS off)",
    [0x1] = "DWT_STS_MODE_1",
    [0x2] = "DWT_STS_MODE_2",
    [0x3] = "DWT_STS_MODE_ND (no data)",
    [0x8] = "DWT_STS_MODE_SDC (super deterministic)",
}

-- dwt_sts_lengths_e  (register-encoded: value = log2(len/32))
local DWT_STS_LEN = {
    [0x00] = "DWT_STS_LEN_32",
    [0x01] = "DWT_STS_LEN_64",
    [0x02] = "DWT_STS_LEN_128",
    [0x03] = "DWT_STS_LEN_256",
    [0x04] = "DWT_STS_LEN_512",
    [0x05] = "DWT_STS_LEN_1024",
    [0x06] = "DWT_STS_LEN_2048",
}

-- dwt_pdoa_mode_e
local DWT_PDOA = {
    [0x0] = "DWT_PDOA_M0 (off)",
    [0x1] = "DWT_PDOA_M1",
    [0x3] = "DWT_PDOA_M3",
}

-- Helper: look up an enum table, fall back to hex string if unknown
local function enum_str(tbl, val)
    return tbl[val] or string.format("Unknown (0x%02x)", val)
end

-- ---------------------------------------------------------------------------
-- ProtoField declarations
-- ---------------------------------------------------------------------------

-- ── Block 1: Diagnostic ──────────────────────────────────────────────────
local f_diag_magic        = ProtoField.string ("uwb_kit.diag.magic",         "Magic")
local f_diag_rx_time_raw  = ProtoField.bytes  ("uwb_kit.diag.rx_time_raw",   "ipatovRxTime (raw 5 B)")
local f_diag_rx_time_s    = ProtoField.double ("uwb_kit.diag.rx_time_s",     "ipatovRxTime (s)")
local f_diag_peak_index   = ProtoField.uint32 ("uwb_kit.diag.peak_index",    "ipatovPeak Index",      base.DEC)
local f_diag_peak_ampl    = ProtoField.float  ("uwb_kit.diag.peak_ampl",     "ipatovPeak Amplitude")
local f_diag_power        = ProtoField.uint32 ("uwb_kit.diag.power",         "ipatovPower",           base.DEC)
local f_diag_f1           = ProtoField.float  ("uwb_kit.diag.f1",            "ipatovF1")
local f_diag_f2           = ProtoField.float  ("uwb_kit.diag.f2",            "ipatovF2")
local f_diag_f3           = ProtoField.float  ("uwb_kit.diag.f3",            "ipatovF3")
local f_diag_fp_index     = ProtoField.uint32 ("uwb_kit.diag.fp_index",      "ipatovFpIndex",         base.DEC)
local f_diag_accum_count  = ProtoField.uint32 ("uwb_kit.diag.accum_count",   "ipatovAccumCount",      base.DEC)
local f_diag_dgc_decision = ProtoField.uint8  ("uwb_kit.diag.dgc_decision",  "DGC Decision",          base.DEC)
local f_diag_seqno        = ProtoField.uint8  ("uwb_kit.diag.seqno",         "Diag Seq Number",       base.DEC)
local f_diag_fp_power     = ProtoField.double ("uwb_kit.diag.fp_power",      "FP Power (dBm)")
local f_diag_rx_power     = ProtoField.double ("uwb_kit.diag.rx_power",      "RX Power (dBm)")
local f_diag_peak_power   = ProtoField.double ("uwb_kit.diag.peak_power",    "Peak Power (dBm)")
local f_diag_peak_amp_v   = ProtoField.double ("uwb_kit.diag.peak_amp_v",    "Peak Amplitude (μV)")
local f_diag_delta_p      = ProtoField.double ("uwb_kit.diag.delta_p",       "ΔP = RX-FP (dB)")

-- ── Block 2: Config / Rsvd-A ─────────────────────────────────────────────
local f_cfg_m_seq         = ProtoField.uint32 ("uwb_kit.cfg.m_seq",          "m_seq (pkt counter)",   base.DEC)
local f_cfg_rx_len        = ProtoField.uint16 ("uwb_kit.cfg.rx_len",         "m_rx_len",              base.DEC)
local f_cfg_chan          = ProtoField.uint8  ("uwb_kit.cfg.chan",            "config.chan",           base.DEC)
-- Enum fields: stored as uint8 but displayed via value_string tables
local f_cfg_data_rate     = ProtoField.uint8  ("uwb_kit.cfg.data_rate",      "config.dataRate",       base.DEC, DWT_BR)
local f_cfg_tx_code       = ProtoField.uint8  ("uwb_kit.cfg.tx_code",        "config.txCode",         base.DEC)
local f_cfg_rx_code       = ProtoField.uint8  ("uwb_kit.cfg.rx_code",        "config.rxCode",         base.DEC)
local f_cfg_tx_preamb_len = ProtoField.uint8  ("uwb_kit.cfg.tx_preamb_len",  "config.txPreambLength", base.HEX, DWT_PLEN)
local f_cfg_rx_pac        = ProtoField.uint8  ("uwb_kit.cfg.rx_pac",         "config.rxPAC",          base.DEC, DWT_PAC)
local f_cfg_sfd_type      = ProtoField.uint8  ("uwb_kit.cfg.sfd_type",       "config.sfdType",        base.DEC, DWT_SFD)
local f_cfg_phr_mode      = ProtoField.uint8  ("uwb_kit.cfg.phr_mode",       "config.phrMode",        base.DEC, DWT_PHRMODE)
local f_cfg_phr_rate      = ProtoField.uint8  ("uwb_kit.cfg.phr_rate",       "config.phrRate",        base.DEC, DWT_PHRRATE)
local f_cfg_sfd_to        = ProtoField.uint16 ("uwb_kit.cfg.sfd_to",         "config.sfdTO",          base.DEC)
local f_cfg_sts_mode      = ProtoField.uint8  ("uwb_kit.cfg.sts_mode",       "config.stsMode",        base.HEX, DWT_STS_MODE)
local f_cfg_sts_length    = ProtoField.uint8  ("uwb_kit.cfg.sts_length",     "config.stsLength",      base.HEX, DWT_STS_LEN)
local f_cfg_pdoa_mode     = ProtoField.uint8  ("uwb_kit.cfg.pdoa_mode",      "config.pdoaMode",       base.HEX, DWT_PDOA)
local f_cfg_reserved      = ProtoField.bytes  ("uwb_kit.cfg.reserved",       "Reserved (12 B)")

-- ── Block 3: RX Slot — decoded (Frame Control == 0x8841) ─────────────────
local f_rx_fctl           = ProtoField.uint16 ("uwb_kit.rx.frame_ctrl",      "Frame Control",         base.HEX)
local f_rx_mac_seqno      = ProtoField.uint8  ("uwb_kit.rx.mac_seqno",       "MAC Sequence Number",   base.DEC)
local f_rx_pan_id         = ProtoField.uint16 ("uwb_kit.rx.pan_id",          "PAN ID",                base.HEX)
local f_rx_dst            = ProtoField.uint16 ("uwb_kit.rx.dst_addr",        "Destination Address",   base.HEX)
local f_rx_src            = ProtoField.uint16 ("uwb_kit.rx.src_addr",        "Source Address",        base.HEX)
local f_rx_func           = ProtoField.uint8  ("uwb_kit.rx.func_code",       "Function Code",         base.HEX,
                              {[0xe0]="Poll", [0xe1]="Response", [0xe2]="Final"})
local f_rx_poll_rx_ts     = ProtoField.uint32 ("uwb_kit.rx.poll_rx_ts",      "Poll RX Timestamp",     base.HEX)
local f_rx_resp_tx_ts     = ProtoField.uint32 ("uwb_kit.rx.resp_tx_ts",      "Resp TX Timestamp",     base.HEX)
local f_rx_checksum       = ProtoField.uint16 ("uwb_kit.rx.checksum",        "DW Checksum",           base.HEX)
local f_rx_padding        = ProtoField.bytes  ("uwb_kit.rx.padding",         "RX Slot Padding")
-- ── Block 3: RX Slot — undecoded (Frame Control != 0x8841) ───────────────
local f_rx_raw            = ProtoField.bytes  ("uwb_kit.rx.raw",             "RX Slot (raw)")

-- ── Block 4: CIR ─────────────────────────────────────────────────────────
local f_cir_data          = ProtoField.bytes  ("uwb_kit.cir.data",           "CIR Samples")

p_kit.fields = {
    f_diag_magic, f_diag_rx_time_raw, f_diag_rx_time_s,
    f_diag_peak_index, f_diag_peak_ampl, f_diag_power,
    f_diag_f1, f_diag_f2, f_diag_f3,
    f_diag_fp_index, f_diag_accum_count,
    f_diag_dgc_decision, f_diag_seqno,
    f_diag_fp_power, f_diag_rx_power, f_diag_peak_power,
    f_diag_peak_amp_v, f_diag_delta_p,
    f_cfg_m_seq, f_cfg_rx_len, f_cfg_chan, f_cfg_data_rate,
    f_cfg_tx_code, f_cfg_rx_code, f_cfg_tx_preamb_len, f_cfg_rx_pac,
    f_cfg_sfd_type, f_cfg_phr_mode, f_cfg_phr_rate, f_cfg_sfd_to,
    f_cfg_sts_mode, f_cfg_sts_length, f_cfg_pdoa_mode, f_cfg_reserved,
    f_rx_fctl, f_rx_mac_seqno, f_rx_pan_id, f_rx_dst, f_rx_src, f_rx_func,
    f_rx_poll_rx_ts, f_rx_resp_tx_ts, f_rx_checksum, f_rx_padding,
    f_rx_raw,
    f_cir_data,
}

-- ---------------------------------------------------------------------------
-- Helper: big-endian unsigned int
-- ---------------------------------------------------------------------------
local function be_uint(buf, offset, len)
    local val = 0
    for i = 0, len - 1 do
        val = val * 256 + buf(offset + i, 1):uint()
    end
    return val
end

-- ---------------------------------------------------------------------------
-- Block 1: Diagnostic (33 bytes)
-- ---------------------------------------------------------------------------
local function dissect_diagnostic(buf, offset, parent)
    parent:add(f_diag_magic,       buf(offset,     2), "DG")
    local rx_time_raw = be_uint(buf, offset + 2, 5)
    parent:add(f_diag_rx_time_raw, buf(offset + 2, 5))
    parent:add(f_diag_rx_time_s,   buf(offset + 2, 5), rx_time_raw * IPATOV_TIME_SCALE)

    local word_7     = be_uint(buf, offset + 7, 4)
    local peak_index = math.floor(word_7 / 2097152) % 1024
    local Pk         = (word_7 % 2097152) / 2.0
    parent:add(f_diag_peak_index,  buf(offset +  7, 4), peak_index)
    parent:add(f_diag_peak_ampl,   buf(offset +  7, 4), Pk)

    local ipatov_P = be_uint(buf, offset + 11, 4) % 1048576
    parent:add(f_diag_power,       buf(offset + 11, 4), ipatov_P)

    local F1 = (be_uint(buf, offset + 15, 4) % 4194304) / 4.0
    parent:add(f_diag_f1,          buf(offset + 15, 4), F1)
    local F2 = (be_uint(buf, offset + 19, 4) % 4194304) / 4.0
    parent:add(f_diag_f2,          buf(offset + 19, 4), F2)
    local F3 = (be_uint(buf, offset + 23, 4) % 4194304) / 4.0
    parent:add(f_diag_f3,          buf(offset + 23, 4), F3)

    local fp_index = math.floor(be_uint(buf, offset + 27, 2) / 64) % 1024
    parent:add(f_diag_fp_index,    buf(offset + 27, 2), fp_index)
    local accum_N  = be_uint(buf, offset + 29, 2) % 4096
    parent:add(f_diag_accum_count, buf(offset + 29, 2), accum_N)

    local dgc = buf(offset + 31, 1):uint()
    parent:add(f_diag_dgc_decision, buf(offset + 31, 1))
    parent:add(f_diag_seqno,        buf(offset + 32, 1))

    if accum_N == 0 then return end
    local N2    = accum_N * accum_N
    local dgc_6 = 6.0 * dgc
    local log10 = math.log(10)
    local anchor = buf(offset, 1)

    local fp_power   = 10.0*math.log((F1*F1+F2*F2+F3*F3)/N2)/log10 + dgc_6 + PWR_OFFSET
    parent:add(f_diag_fp_power,   anchor, fp_power)
    local rx_power   = 10.0*math.log((ipatov_P*131072.0)/N2)/log10  + dgc_6 + PWR_OFFSET
    parent:add(f_diag_rx_power,   anchor, rx_power)
    local peak_power = 10.0*math.log(3.0*Pk*Pk/N2)/log10            + dgc_6 + PWR_OFFSET
    parent:add(f_diag_peak_power, anchor, peak_power)
    parent:add(f_diag_peak_amp_v, anchor,
               math.sqrt(10.0^(peak_power/10.0)/1000.0*50.0)*1e6)
    parent:add(f_diag_delta_p,    anchor, rx_power - fp_power)
end

-- ---------------------------------------------------------------------------
-- Block 2: Config / Rsvd-A (32 bytes)
--
-- Enum fields use Wireshark's value_string mechanism: the ProtoField already
-- holds the translation table, so Wireshark displays e.g.
--   config.dataRate: DWT_BR_6M8 (6.8 Mbits/s) (1)
-- automatically when the field is added with :add().
-- ---------------------------------------------------------------------------
local function dissect_config(buf, offset, parent)
    parent:add(f_cfg_m_seq,         buf(offset +  0, 4))
    parent:add(f_cfg_rx_len,        buf(offset +  4, 2))
    parent:add(f_cfg_chan,          buf(offset +  6, 1))
    parent:add(f_cfg_data_rate,     buf(offset +  7, 1))  -- dwt_uwb_bit_rate_e
    parent:add(f_cfg_tx_code,       buf(offset +  8, 1))
    parent:add(f_cfg_rx_code,       buf(offset +  9, 1))
    parent:add(f_cfg_tx_preamb_len, buf(offset + 10, 1))  -- dwt_tx_plen_e
    parent:add(f_cfg_rx_pac,        buf(offset + 11, 1))  -- dwt_pac_size_e
    parent:add(f_cfg_sfd_type,      buf(offset + 12, 1))  -- dwt_sfd_type_e
    parent:add(f_cfg_phr_mode,      buf(offset + 13, 1))  -- dwt_phr_mode_e
    parent:add(f_cfg_phr_rate,      buf(offset + 14, 1))  -- dwt_phr_rate_e
    parent:add(f_cfg_sfd_to,        buf(offset + 15, 2))
    parent:add(f_cfg_sts_mode,      buf(offset + 17, 1))  -- dwt_sts_mode_e
    parent:add(f_cfg_sts_length,    buf(offset + 18, 1))  -- dwt_sts_lengths_e
    parent:add(f_cfg_pdoa_mode,     buf(offset + 19, 1))  -- dwt_pdoa_mode_e
    parent:add(f_cfg_reserved,      buf(offset + 20, 12))
end

-- ---------------------------------------------------------------------------
-- Block 3: RX Slot (127 bytes)
-- Decoded only when Frame Control == 0x8841; otherwise shown as raw bytes.
-- ---------------------------------------------------------------------------
local function dissect_rx_slot(buf, offset, rx_len, parent)
    local fctl = buf(offset, 2):le_uint()

    if fctl ~= FCTL_DW_RANGING then
        parent:add(f_rx_raw, buf(offset, RX_SLOT_LEN))
        return
    end

    parent:add_le(f_rx_fctl,     buf(offset + 0, 2))
    parent:add(f_rx_mac_seqno,   buf(offset + 2, 1))
    parent:add_le(f_rx_pan_id,   buf(offset + 3, 2))
    parent:add_le(f_rx_dst,      buf(offset + 5, 2))
    parent:add_le(f_rx_src,      buf(offset + 7, 2))
    local func = buf(offset + 9, 1):uint()
    parent:add(f_rx_func,        buf(offset + 9, 1))

    if func == FUNC_RESPONSE or func == FUNC_FINAL then
        if rx_len >= 14 then parent:add(f_rx_poll_rx_ts, buf(offset + 10, 4)) end
        if rx_len >= 18 then parent:add(f_rx_resp_tx_ts, buf(offset + 14, 4)) end
    end

    if rx_len >= 2 then
        parent:add_le(f_rx_checksum, buf(offset + rx_len - 2, 2))
    end

    local pad_len = RX_SLOT_LEN - rx_len
    if pad_len > 0 then
        parent:add(f_rx_padding, buf(offset + rx_len, pad_len))
    end
end

-- ---------------------------------------------------------------------------
-- Main dissector
-- ---------------------------------------------------------------------------
function p_kit.dissector(buf, pinfo, tree)
    local buf_len = buf:len()

    if buf_len < (DIAG_LEN + RSVD_A_LEN) then return 0 end
    if buf(DIAG_OFF, 2):string() ~= "DG"  then return 0 end

    pinfo.cols.protocol:set("UWBkit")

    -- Block 1: Diagnostic
    local diag_tree = tree:add(p_kit, buf(DIAG_OFF, DIAG_LEN),
                               "Diagnostic Block (33 B)")
    dissect_diagnostic(buf, DIAG_OFF, diag_tree)

    -- Block 2: Config
    if buf_len < RSVD_A_OFF + RSVD_A_LEN then
        pinfo.cols.info:set("UWBkit [no config block]")
        return
    end
    local cfg_tree = tree:add(p_kit, buf(RSVD_A_OFF, RSVD_A_LEN),
                              "Config Block (32 B)")
    dissect_config(buf, RSVD_A_OFF, cfg_tree)

    local m_seq   = be_uint(buf, RSVD_A_OFF + 0, 4)
    local rx_len  = be_uint(buf, RSVD_A_OFF + 4, 2)
    local chan     = buf(RSVD_A_OFF + 6, 1):uint()
    local diag_sn = buf(DIAG_OFF + 32, 1):uint()

    -- Block 3: RX Slot
    if buf_len < RX_SLOT_OFF + RX_SLOT_LEN then
        pinfo.cols.info:set("UWBkit m_seq=" .. m_seq .. " [no RX slot]")
        return
    end

    local fctl = buf(RX_SLOT_OFF, 2):le_uint()
    local frame_label
    if fctl ~= FCTL_DW_RANGING then
        frame_label = string.format("Unknown FCTL (0x%04x)", fctl)
    else
        local func_code = buf(RX_SLOT_OFF + 9, 1):uint()
        if     func_code == FUNC_POLL     then frame_label = "Poll"
        elseif func_code == FUNC_RESPONSE then frame_label = "Response"
        elseif func_code == FUNC_FINAL    then frame_label = "Final"
        else   frame_label = string.format("Unknown(0x%02x)", func_code)
        end
    end

    local rx_tree = tree:add(p_kit, buf(RX_SLOT_OFF, RX_SLOT_LEN),
                             "RX Slot — " .. frame_label .. " (127 B)")
    dissect_rx_slot(buf, RX_SLOT_OFF, rx_len, rx_tree)

    -- Block 4: CIR
    if buf_len >= CIR_OFF + 1 then
        local cir_avail = math.min(buf_len - CIR_OFF, CIR_LEN)
        local cir_tree  = tree:add(p_kit, buf(CIR_OFF, cir_avail),
            "CIR Samples (" .. cir_avail .. " / " .. CIR_LEN .. " B)")
        cir_tree:add(f_cir_data, buf(CIR_OFF, cir_avail))
    end

    pinfo.cols.info:set("UWBkit"
        .. "  " .. frame_label
        .. "  Chan="   .. chan
        .. "  m_seq="  .. m_seq
        .. "  sn="     .. diag_sn
        .. "  rx_len=" .. rx_len .. " B")
end

-- ---------------------------------------------------------------------------
-- Register on UDP port 17754
-- ---------------------------------------------------------------------------
local udp_table = DissectorTable.get("udp.port")
udp_table:add(17754, p_kit)

print("[UWBkit Dissector] Loaded on UDP port 17754")
