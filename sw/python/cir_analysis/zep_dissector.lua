-- =============================================================================
--  ZEP v3 / UWB Packet Dissector for Wireshark (Lua)
--  Compatible with Wireshark 1.12+  (uses add_expert_info API)
--
--  Matches uwbkit_shared.py decode functions exactly.
--  Decawave ranging frame dissection per IEEE 802.15.4 + DW application note.
--
-- =============================================================================
--  FULL PACKET LAYOUT (offsets relative to start of UDP payload)
-- =============================================================================
--
--  ┌──────────────────────────────────────────────────────────────────────────┐
--  │ Bytes     │ Layer                │ Size │ Description                    │
--  ├───────────┼──────────────────────┼──────┼────────────────────────────────┤
--  │  0 – 31   │ ZEP v3 Header        │ 32 B │ Custom UWB ZEP header          │
--  ├───────────┼──────────────────────┼──────┼────────────────────────────────┤
--  │  ZEP v3 HEADER DETAIL                                                    │
--  │  0 –  1   │   Magic              │  2 B │ ASCII "EX" (0x45 0x58)         │
--  │  2        │   Version            │  1 B │ 0x03                           │
--  │  3        │   Type               │  1 B │ Frame type                     │
--  │  4        │   Channel            │  1 B │ UWB channel                    │
--  │  5 –  6   │   Device ID          │  2 B │ Big-endian                     │
--  │  7        │   CRC Mode           │  1 B │ 0=LQI, 1=CRC                   │
--  │  8        │   LQI                │  1 B │ Link Quality Indicator         │
--  │  9 – 16   │   Rel. Timestamp     │  8 B │ 64-bit big-endian              │
--  │ 17 – 20   │   Sequence Number    │  4 B │ 32-bit big-endian              │
--  │ 21        │   Band               │  1 B │ UWB band                       │
--  │ 22        │   Channel Page       │  1 B │                                │
--  │ 23 – 30   │   Reserved           │  8 B │                                │
--  │ 31        │   Frame Length       │  1 B │ 802.15.4 payload length        │
--  ├───────────┼──────────────────────┼──────┼────────────────────────────────┤
--  │  ZEP PAYLOAD (byte 32 onwards)                                           │
--  ├───────────┼──────────────────────┼──────┼────────────────────────────────┤
--  │  DIAGNOSTIC PACKET (payload[0:2] == "DG"), 33 bytes total:               │
--  ├───────────┼──────────────────────┼──────┼────────────────────────────────┤
--  │  buf[] offsets below are relative to start of diagnostic payload (= 32) │
--  │  0 –  1   │   Magic "DG"         │  2 B │ 0x44 0x47                      │
--  │  2 –  6   │   Ipatov RX Time     │  5 B │ big-endian * (1/128/499.2e6)   │
--  │  7 – 10   │   Ipatov Peak Index  │  4 B │ bits 21:30 → (val>>21)&0x3FF   │
--  │           │   Ipatov Peak Ampl.  │      │ bits  0:20 → val&0x1FFFFF / 2  │
--  │ 11 – 14   │   Ipatov Power       │  4 B │ bits  0:19 → val&0xFFFFF       │
--  │ 15 – 18   │   Ipatov F1          │  4 B │ bits  0:21 → val&0x3FFFFF / 4  │
--  │ 19 – 22   │   Ipatov F2          │  4 B │ bits  0:21 → val&0x3FFFFF / 4  │
--  │ 23 – 26   │   Ipatov F3          │  4 B │ bits  0:21 → val&0x3FFFFF / 4  │
--  │ 27 – 28   │   Ipatov FP Index    │  2 B │ bits  6:15 → (val>>6)&0x3FF    │
--  │           │   Ipatov Accum Count │      │ bits  0:11 → val&0xFFF         │
--  │ 29 – 30   │   (continued above)  │  2 B │ same 2-byte word as FP Index   │
--  │ 31        │   DGC Decision       │  1 B │ full byte                      │
--  │ 32        │   Sequence Number    │  1 B │ diagnostic sequence counter    │
--  ├───────────┼──────────────────────┼──────┼────────────────────────────────┤
--  │  COMPUTED (derived from diagnostic fields, no raw bytes):                │
--  │           │   FP Power           │  –   │ 10*log10((F1²+F2²+F3²)/N²)    │
--  │           │                      │      │   + 6*DGC - 121.7  [dBm]       │
--  │           │   RX Power           │  –   │ 10*log10(P*2^17/N²)            │
--  │           │                      │      │   + 6*DGC - 121.7  [dBm]       │
--  │           │   Peak Power         │  –   │ 10*log10(3*Pk²/N²)             │
--  │           │                      │      │   + 6*DGC - 121.7  [dBm]       │
--  │           │   Peak Amplitude     │  –   │ sqrt(10^(PeakPwr/10)/1000*50)  │
--  │           │   Delta P            │  –   │ RX Power - FP Power  [dB]      │
--  ├───────────┼──────────────────────┼──────┼────────────────────────────────┤
--  │  NORMAL PACKET (RX Message + CIR):                                       │
--  ├───────────┼──────────────────────┼──────┼────────────────────────────────┤
--  │ 32 – 43   │ RX Message           │ 12 B │ Decawave ranging frame         │
--  │  0 –  1   │   Frame Control      │  2 B │ LE; 0x8841                     │
--  │  2        │   MAC Seq Number     │  1 B │                                │
--  │  3 –  4   │   PAN ID             │  2 B │ LE; 0xDECA                     │
--  │  5 –  6   │   Destination Addr   │  2 B │ LE                             │
--  │  7 –  8   │   Source Addr        │  2 B │ LE                             │
--  │  9        │   Function Code      │  1 B │ 0xe0=Poll 0xe1=Resp 0xe2=Final │
--  │  10 – 13  │   Poll RX Timestamp  │  4 B │ Response/Final only            │
--  │  14 – 17  │   Resp TX Timestamp  │  4 B │ Response/Final only            │
--  │  [last 2] │   DW Checksum        │  2 B │ Auto-set by DW IC              │
--  │ 44 – 48   │ CIR Fragment Header  │  5 B │                                │
--  │  0        │   Tag                │  1 B │                                │
--  │  1 –  2   │   Total CIR Length   │  2 B │ Big-endian                     │
--  │  3        │   Fragment Index     │  1 B │                                │
--  │  4        │   Chunk Length       │  1 B │                                │
--  │ 49 – ...  │ CIR Fragment Data    │  N B │ chunk_len bytes                │
--  └───────────┴──────────────────────┴──────┴────────────────────────────────┘
-- =============================================================================


-- Guard against double-loading on Ctrl+Shift+L reload
local _ok, p_zep = pcall(Proto, "uwb_zep", "UWB ZEP v3 Dissector")
if not _ok then return end


-- ---------------------------------------------------------------------------
-- ProtoField declarations
-- ---------------------------------------------------------------------------

-- ZEP v3 Header
local f_magic       = ProtoField.string ("uwb_zep.magic",              "Magic")
local f_version     = ProtoField.uint8  ("uwb_zep.version",            "Version",              base.DEC)
local f_type        = ProtoField.uint8  ("uwb_zep.type",               "Type",                 base.DEC)
local f_channel     = ProtoField.uint8  ("uwb_zep.channel",            "Channel",              base.DEC)
local f_device_id   = ProtoField.uint16 ("uwb_zep.device_id",          "Device ID",            base.HEX)
local f_crc_mode    = ProtoField.uint8  ("uwb_zep.crc_mode",           "CRC Mode",             base.DEC,
                        {[0]="LQI present", [1]="CRC present"})
local f_lqi         = ProtoField.uint8  ("uwb_zep.lqi",                "LQI",                  base.DEC)
local f_rel_ts      = ProtoField.uint64 ("uwb_zep.rel_timestamp",      "Rel. Timestamp",       base.DEC)
local f_seqno       = ProtoField.uint32 ("uwb_zep.seqno",              "Sequence Number",      base.DEC)
local f_band        = ProtoField.uint8  ("uwb_zep.band",               "Band",                 base.DEC)
local f_chan_page   = ProtoField.uint8  ("uwb_zep.channel_page",       "Channel Page",         base.DEC)
local f_reserved    = ProtoField.bytes  ("uwb_zep.reserved",           "Reserved (8 B)")
local f_frame_len   = ProtoField.uint8  ("uwb_zep.frame_len",          "Frame Length",         base.DEC)

-- Diagnostic payload fields
-- buf[] offsets are relative to the start of the diagnostic payload (ZEP byte 32)
local f_diag_magic        = ProtoField.string ("uwb_zep.diag.magic",         "Magic")
local f_diag_rx_time_raw  = ProtoField.bytes  ("uwb_zep.diag.rx_time_raw",   "Ipatov RX Time (raw 5 B)")
local f_diag_rx_time_s    = ProtoField.double ("uwb_zep.diag.rx_time_s",     "Ipatov RX Time (s)")
local f_diag_peak_index   = ProtoField.uint32 ("uwb_zep.diag.peak_index",    "Ipatov Peak Index",        base.DEC)
local f_diag_peak_ampl    = ProtoField.float  ("uwb_zep.diag.peak_ampl",     "Ipatov Peak Amplitude")
local f_diag_power        = ProtoField.uint32 ("uwb_zep.diag.power",         "Ipatov Power",             base.DEC)
local f_diag_f1           = ProtoField.float  ("uwb_zep.diag.f1",            "Ipatov F1")
local f_diag_f2           = ProtoField.float  ("uwb_zep.diag.f2",            "Ipatov F2")
local f_diag_f3           = ProtoField.float  ("uwb_zep.diag.f3",            "Ipatov F3")
local f_diag_fp_index     = ProtoField.uint32 ("uwb_zep.diag.fp_index",      "Ipatov FP Index",          base.DEC)
local f_diag_accum_count  = ProtoField.uint32 ("uwb_zep.diag.accum_count",   "Ipatov Accum Count",       base.DEC)
local f_diag_dgc_decision = ProtoField.uint8  ("uwb_zep.diag.dgc_decision",  "DGC Decision",             base.DEC)
local f_diag_seqno        = ProtoField.uint8  ("uwb_zep.diag.seqno",         "Diagnostic Seq Number",    base.DEC)

-- Computed / derived diagnostic fields (no raw bytes — anchored to first diag byte)
local f_diag_fp_power     = ProtoField.double ("uwb_zep.diag.fp_power",      "FP Power (dBm)")
local f_diag_rx_power     = ProtoField.double ("uwb_zep.diag.rx_power",      "RX Power (dBm)")
local f_diag_peak_power   = ProtoField.double ("uwb_zep.diag.peak_power",    "Peak Power (dBm)")
local f_diag_peak_amp_v   = ProtoField.double ("uwb_zep.diag.peak_amp_v",    "Peak Amplitude (μV)")
local f_diag_delta_p      = ProtoField.double ("uwb_zep.diag.delta_p",       "ΔP = RX-FP (dB)")

-- Decawave 802.15.4 ranging frame fields
local f_rx_fctl        = ProtoField.uint16 ("uwb_zep.rx.frame_ctrl",  "Frame Control",        base.HEX)
local f_rx_seqno       = ProtoField.uint8  ("uwb_zep.rx.seqno",       "MAC Sequence Number",  base.DEC)
local f_rx_pan_id      = ProtoField.uint16 ("uwb_zep.rx.pan_id",      "PAN ID",               base.HEX)
local f_rx_dst         = ProtoField.uint16 ("uwb_zep.rx.dst_addr",    "Destination Address",  base.HEX)
local f_rx_src         = ProtoField.uint16 ("uwb_zep.rx.src_addr",    "Source Address",       base.HEX)
local f_rx_func        = ProtoField.uint8  ("uwb_zep.rx.func_code",   "Function Code",        base.HEX,
                           {[0xe0]="Poll", [0xe1]="Response", [0xe2]="Final"})
local f_rx_poll_rx_ts  = ProtoField.uint32 ("uwb_zep.rx.poll_rx_ts",  "Poll RX Timestamp",    base.HEX)
local f_rx_resp_tx_ts  = ProtoField.uint32 ("uwb_zep.rx.resp_tx_ts",  "Resp TX Timestamp",    base.HEX)
local f_rx_checksum    = ProtoField.uint16 ("uwb_zep.rx.checksum",    "DW Checksum",          base.HEX)

-- CIR Fragment
local f_cir_tag        = ProtoField.uint8  ("uwb_zep.cir.tag",        "CIR Tag",              base.HEX)
local f_cir_total_len  = ProtoField.uint16 ("uwb_zep.cir.total_len",  "Total CIR Length",     base.DEC)
local f_cir_frag_idx   = ProtoField.uint8  ("uwb_zep.cir.frag_idx",   "Fragment Index",       base.DEC)
local f_cir_chunk_len  = ProtoField.uint8  ("uwb_zep.cir.chunk_len",  "Chunk Length",         base.DEC)
local f_cir_data       = ProtoField.bytes  ("uwb_zep.cir.data",       "CIR Fragment Data")

p_zep.fields = {
    f_magic, f_version, f_type, f_channel, f_device_id,
    f_crc_mode, f_lqi, f_rel_ts, f_seqno, f_band, f_chan_page,
    f_reserved, f_frame_len,
    -- Diagnostic (raw)
    f_diag_magic, f_diag_rx_time_raw, f_diag_rx_time_s,
    f_diag_peak_index, f_diag_peak_ampl, f_diag_power,
    f_diag_f1, f_diag_f2, f_diag_f3,
    f_diag_fp_index, f_diag_accum_count,
    f_diag_dgc_decision, f_diag_seqno,
    -- Diagnostic (computed)
    f_diag_fp_power, f_diag_rx_power, f_diag_peak_power,
    f_diag_peak_amp_v, f_diag_delta_p,
    -- RX message
    f_rx_fctl, f_rx_seqno, f_rx_pan_id, f_rx_dst, f_rx_src, f_rx_func,
    f_rx_poll_rx_ts, f_rx_resp_tx_ts, f_rx_checksum,
    -- CIR
    f_cir_tag, f_cir_total_len, f_cir_frag_idx, f_cir_chunk_len, f_cir_data,
}


-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------
local ZEP_V3_HDR_LEN   = 32
local RX_MSG_LEN       = 12
local CIR_FRAG_HDR_LEN = 5
local DIAG_MAGIC_LEN   = 2
local DIAG_DATA_LEN    = 33   -- total diag payload including "DG" magic

-- Decawave function codes
local FUNC_POLL     = 0xe0
local FUNC_RESPONSE = 0xe1
local FUNC_FINAL    = 0xe2

-- Ipatov RX time scale factor: 1 / (128 * 499.2e6)
local IPATOV_TIME_SCALE = 1.0 / (128.0 * 499.2e6)

-- Power formula constant offset (dBm)
local PWR_OFFSET = -121.7


-- ---------------------------------------------------------------------------
-- Helper: read a big-endian unsigned integer from buf at given offset/length
-- Wireshark's uint64 field only exists for 8-byte fields; for 5-byte reads
-- we must do manual byte-by-byte assembly.
-- ---------------------------------------------------------------------------
local function be_uint(buf, offset, len)
    local val = 0
    for i = 0, len - 1 do
        val = val * 256 + buf(offset + i, 1):uint()
    end
    return val
end


-- ---------------------------------------------------------------------------
-- Helper: dissect the 33-byte diagnostic payload
--   buf    = full UDP payload TVB
--   offset = absolute start of the diagnostic payload (= ZEP_V3_HDR_LEN = 32)
--   parent = tree node to attach fields to
--
--  All buf[] indices in comments are relative to 'offset' (= Python's buf[]).
-- ---------------------------------------------------------------------------
local function dissect_diagnostic(buf, offset, parent)
    -- buf[0:2]  — "DG" magic
    parent:add(f_diag_magic, buf(offset + 0, 2), "DG")

    -- buf[2:7]  — Ipatov RX Time (5 bytes, big-endian)
    --   Python: int.from_bytes(buf[2:7], 'big') * (1 / (128 * 499.2e6))
    local rx_time_raw = be_uint(buf, offset + 2, 5)
    parent:add(f_diag_rx_time_raw, buf(offset + 2, 5))
    local rx_time_s = rx_time_raw * IPATOV_TIME_SCALE
    parent:add(f_diag_rx_time_s, buf(offset + 2, 5), rx_time_s)

    -- buf[7:11] — 4-byte word containing Peak Index and Peak Amplitude
    --   Peak Index:     bits 21:30  → (word >> 21) & 0x3FF
    --   Peak Amplitude: bits  0:20  →  word & 0x1FFFFF / 2
    local word_7    = be_uint(buf, offset + 7, 4)
    local peak_index = math.floor(word_7 / 2097152) % 1024  -- (word>>21)&0x3FF
    local peak_ampl  = word_7 % 2097152                      -- word&0x1FFFFF
    local Pk         = peak_ampl / 2.0                       -- scaled float used in power calcs
    parent:add(f_diag_peak_index, buf(offset + 7, 4), peak_index)
    parent:add(f_diag_peak_ampl,  buf(offset + 7, 4), Pk)

    -- buf[11:15] — Ipatov Power: bits 0:19 → word & 0xFFFFF
    local word_11  = be_uint(buf, offset + 11, 4)
    local ipatov_P = word_11 % 1048576                       -- &0xFFFFF, integer
    parent:add(f_diag_power, buf(offset + 11, 4), ipatov_P)

    -- buf[15:19] — Ipatov F1: bits 0:21 → word & 0x3FFFFF / 4
    local word_15 = be_uint(buf, offset + 15, 4)
    local F1      = (word_15 % 4194304) / 4.0
    parent:add(f_diag_f1, buf(offset + 15, 4), F1)

    -- buf[19:23] — Ipatov F2: bits 0:21 → word & 0x3FFFFF / 4
    local word_19 = be_uint(buf, offset + 19, 4)
    local F2      = (word_19 % 4194304) / 4.0
    parent:add(f_diag_f2, buf(offset + 19, 4), F2)

    -- buf[23:27] — Ipatov F3: bits 0:21 → word & 0x3FFFFF / 4
    local word_23 = be_uint(buf, offset + 23, 4)
    local F3      = (word_23 % 4194304) / 4.0
    parent:add(f_diag_f3, buf(offset + 23, 4), F3)

    -- buf[27:28] — Ipatov FP Index: (word>>6)&0x3FF
    local word_27  = be_uint(buf, offset + 27, 2)
    local fp_index = math.floor(word_27 / 64) % 1024
    parent:add(f_diag_fp_index, buf(offset + 27, 2), fp_index)

    -- buf[29:31] — Ipatov Accum Count: word & 0xFFF
    local word_29   = be_uint(buf, offset + 29, 2)
    local accum_N   = word_29 % 4096
    parent:add(f_diag_accum_count, buf(offset + 29, 2), accum_N)

    -- buf[31]   — DGC Decision (full byte)
    local dgc = buf(offset + 31, 1):uint()
    parent:add(f_diag_dgc_decision, buf(offset + 31, 1))

    -- buf[32]   — Diagnostic Sequence Number (full byte)
    parent:add(f_diag_seqno, buf(offset + 32, 1))

    -- ── Computed fields ─────────────────────────────────────────────────────
    -- All formulae from uwbkit_shared.py; N = accum_N (ipatovAccumCount)
    --
    -- Guard against divide-by-zero if accum_N == 0
    if accum_N == 0 then return end

    local N2     = accum_N * accum_N   -- N^2
    local dgc_6  = 6.0 * dgc           -- 6 * DGC_DECISION
    local anchor = buf(offset, 1)      -- 1-byte TvbRange used to anchor computed fields
                                       -- (they have no dedicated raw bytes)

    -- FP_power = 10*log10((F1^2 + F2^2 + F3^2) / N^2) + 6*DGC - 121.7
    local fp_sum   = F1*F1 + F2*F2 + F3*F3
    local fp_power = 10.0 * math.log(fp_sum / N2) / math.log(10) + dgc_6 + PWR_OFFSET
    parent:add(f_diag_fp_power, anchor, fp_power)

    -- RX_power = 10*log10((ipatovPower * 2^17) / N^2) + 6*DGC - 121.7
    local rx_power = 10.0 * math.log((ipatov_P * 131072.0) / N2) / math.log(10) + dgc_6 + PWR_OFFSET
    parent:add(f_diag_rx_power, anchor, rx_power)

    -- Peak_Power = 10*log10(3 * Pk^2 / N^2) + 6*DGC - 121.7
    local peak_power = 10.0 * math.log(3.0 * Pk * Pk / N2) / math.log(10) + dgc_6 + PWR_OFFSET
    parent:add(f_diag_peak_power, anchor, peak_power)

    -- Peak_Amplitude = sqrt(10^(Peak_Power/10) / 1000 * 50) * 1000000 uV
    local peak_amp_v = math.sqrt(10.0^(peak_power / 10.0) / 1000.0 * 50.0) * 1000000
    parent:add(f_diag_peak_amp_v, anchor, peak_amp_v)

    -- delta_P = RX_power - FP_power
    local delta_p = rx_power - fp_power
    parent:add(f_diag_delta_p, anchor, delta_p)
end


-- ---------------------------------------------------------------------------
-- Helper: dissect a Decawave ranging frame (12-byte RX message window)
--   buf    = full UDP payload TVB
--   offset = absolute start of the RX message within buf
--   rx_tree = subtree to attach fields to
-- ---------------------------------------------------------------------------
local function dissect_dw_frame(buf, offset, rx_tree)
    local avail = buf:len() - offset

    if avail < 2  then return end
    rx_tree:add_le(f_rx_fctl,   buf(offset + 0, 2))  -- byte 0/1: Frame Control (LE)

    if avail < 3  then return end
    rx_tree:add(f_rx_seqno,     buf(offset + 2, 1))  -- byte 2:   MAC Sequence Number

    if avail < 5  then return end
    rx_tree:add_le(f_rx_pan_id, buf(offset + 3, 2))  -- byte 3/4: PAN ID (LE, 0xDECA)

    if avail < 7  then return end
    rx_tree:add_le(f_rx_dst,    buf(offset + 5, 2))  -- byte 5/6: Destination Address (LE)

    if avail < 9  then return end
    rx_tree:add_le(f_rx_src,    buf(offset + 7, 2))  -- byte 7/8: Source Address (LE)

    if avail < 10 then return end
    local func = buf(offset + 9, 1):uint()
    rx_tree:add(f_rx_func, buf(offset + 9, 1))       -- byte 9:   Function Code

    -- Response (0xe1) and Final (0xe2) carry two 4-byte timestamps
    if func == FUNC_RESPONSE or func == FUNC_FINAL then
        if avail >= 14 then
            rx_tree:add(f_rx_poll_rx_ts, buf(offset + 10, 4))  -- bytes 10-13
        end
        if avail >= 18 then
            rx_tree:add(f_rx_resp_tx_ts, buf(offset + 14, 4))  -- bytes 14-17
        end
    end

    -- DW IC auto-appended checksum: last 2 bytes of the 12-byte RX window
    local cs_off = offset + RX_MSG_LEN - 2
    if buf:len() >= cs_off + 2 then
        rx_tree:add_le(f_rx_checksum, buf(cs_off, 2))           -- bytes 10-11
    end
end


-- ---------------------------------------------------------------------------
-- Main dissector  (buf = UDP payload TVB)
-- ---------------------------------------------------------------------------
function p_zep.dissector(buf, pinfo, tree)
    local buf_len = buf:len()

    if buf_len < ZEP_V3_HDR_LEN   then return 0 end
    if buf(0, 2):string() ~= "EX" then return 0 end
    if buf(2, 1):uint()   ~= 3    then return 0 end

    pinfo.cols.protocol:set("UWB-ZEP")

    -- ── ZEP v3 Header (bytes 0-31) ──────────────────────────────────────────
    local hdr_tree = tree:add(p_zep, buf(0, ZEP_V3_HDR_LEN), "ZEP v3 Header (32 B)")

    hdr_tree:add(f_magic,     buf(0,  2), buf(0, 2):string())
    hdr_tree:add(f_version,   buf(2,  1))
    hdr_tree:add(f_type,      buf(3,  1))
    hdr_tree:add(f_channel,   buf(4,  1))
    local dev_id = buf(5, 1):uint() * 256 + buf(6, 1):uint()
    hdr_tree:add(f_device_id, buf(5,  2), dev_id)
    hdr_tree:add(f_crc_mode,  buf(7,  1))
    hdr_tree:add(f_lqi,       buf(8,  1))
    hdr_tree:add(f_rel_ts,    buf(9,  8))
    hdr_tree:add(f_seqno,     buf(17, 4))
    hdr_tree:add(f_band,      buf(21, 1))
    hdr_tree:add(f_chan_page, buf(22, 1))
    hdr_tree:add(f_reserved,  buf(23, 8))
    hdr_tree:add(f_frame_len, buf(31, 1))

    local seqno = buf(17, 4):uint()
    local chan   = buf(4,  1):uint()
    local lqi    = buf(8,  1):uint()

    -- ── ZEP Payload (byte 32 onwards) ───────────────────────────────────────
    local payload_off = ZEP_V3_HDR_LEN   -- = 32

    if buf_len <= payload_off then
        pinfo.cols.info:set("UWB-ZEP v3  Chan=" .. chan .. "  Seq=" .. seqno .. "  [no payload]")
        return
    end

    -- ── Diagnostic branch: payload[0:2] == "DG" ─────────────────────────────
    if buf_len >= payload_off + DIAG_MAGIC_LEN
       and buf(payload_off, DIAG_MAGIC_LEN):string() == "DG" then

        local diag_avail = buf_len - payload_off

        if diag_avail < DIAG_DATA_LEN then
            local t = tree:add(p_zep, buf(payload_off, diag_avail),
                               "Diagnostic Payload [truncated]")
            t:add_expert_info(PI_MALFORMED, PI_WARN,
                "Diagnostic data truncated: got " .. diag_avail
                .. " B, expected " .. DIAG_DATA_LEN .. " B")
            pinfo.cols.info:set("UWB-ZEP v3  DIAG [truncated]  Chan=" .. chan .. "  Seq=" .. seqno)
            return
        end

        local diag_tree = tree:add(p_zep, buf(payload_off, DIAG_DATA_LEN),
                                   "Diagnostic Payload (33 B)")
        dissect_diagnostic(buf, payload_off, diag_tree)

        pinfo.cols.info:set("UWB-ZEP v3  DIAG  Chan=" .. chan .. "  Seq=" .. seqno)
        return
    end

    -- ── Normal path: RX Message + CIR Fragment ──────────────────────────────
    local min_payload = RX_MSG_LEN + CIR_FRAG_HDR_LEN
    if buf_len < payload_off + min_payload then
        local t = tree:add(p_zep, buf(payload_off, buf_len - payload_off),
                           "ZEP Payload [truncated]")
        t:add_expert_info(PI_MALFORMED, PI_WARN,
            "Payload too short: need " .. min_payload .. " B for RX msg + CIR header")
        pinfo.cols.info:set("UWB-ZEP v3  TRUNCATED  Seq=" .. seqno)
        return
    end

    local rx_off    = payload_off                              -- abs: 32
    local func_code = buf(rx_off + 9, 1):uint()

    local frame_label
    if     func_code == FUNC_POLL     then frame_label = "Poll"
    elseif func_code == FUNC_RESPONSE then frame_label = "Response"
    elseif func_code == FUNC_FINAL    then frame_label = "Final"
    else   frame_label = string.format("Unknown(0x%02x)", func_code)
    end

    -- ── RX Message ───────────────────────────────────────────────────────────
    local rx_tree = tree:add(p_zep, buf(rx_off, RX_MSG_LEN),
                             "RX Message -- Decawave " .. frame_label .. " Frame (12 B)")
    dissect_dw_frame(buf, rx_off, rx_tree)

    -- ── CIR Fragment Header ───────────────────────────────────────────────────
    local cir_hdr_off = rx_off + RX_MSG_LEN                   -- abs: 44
    local cir_h_tree  = tree:add(p_zep, buf(cir_hdr_off, CIR_FRAG_HDR_LEN),
                                 "CIR Fragment Header (5 B)")
    cir_h_tree:add(f_cir_tag,       buf(cir_hdr_off + 0, 1))
    local total_cir = buf(cir_hdr_off + 1, 1):uint() * 256
                    + buf(cir_hdr_off + 2, 1):uint()
    cir_h_tree:add(f_cir_total_len, buf(cir_hdr_off + 1, 2), total_cir)
    local frag_idx  = buf(cir_hdr_off + 3, 1):uint()
    cir_h_tree:add(f_cir_frag_idx,  buf(cir_hdr_off + 3, 1))
    local chunk_len = buf(cir_hdr_off + 4, 1):uint()
    cir_h_tree:add(f_cir_chunk_len, buf(cir_hdr_off + 4, 1))

    -- ── CIR Fragment Data ─────────────────────────────────────────────────────
    local cir_data_off = cir_hdr_off + CIR_FRAG_HDR_LEN       -- abs: 49
    local avail        = buf_len - cir_data_off

    if chunk_len == 0 or avail <= 0 then
        local t = tree:add(p_zep, buf(cir_data_off, 0), "CIR Fragment Data [empty]")
        t:add_expert_info(PI_NOTE, PI_NOTE, "No CIR data bytes in this fragment")
    elseif avail < chunk_len then
        local t = tree:add(p_zep, buf(cir_data_off, avail), "CIR Fragment Data [truncated]")
        t:add_expert_info(PI_MALFORMED, PI_WARN,
            "CIR data truncated: got " .. avail .. " B, expected " .. chunk_len .. " B")
    else
        local t = tree:add(p_zep, buf(cir_data_off, chunk_len),
                           "CIR Fragment Data (" .. chunk_len .. " B)")
        t:add(f_cir_data, buf(cir_data_off, chunk_len))
    end

    pinfo.cols.info:set("UWB-ZEP v3"
        .. "  " .. frame_label
        .. "  Chan="  .. chan
        .. "  Seq="   .. seqno
        .. "  LQI="   .. lqi
        .. "  CIR["   .. frag_idx .. "]"
        .. "  "       .. chunk_len .. "/" .. total_cir .. " B")
end


-- ---------------------------------------------------------------------------
-- Register on UDP port 17754
-- ---------------------------------------------------------------------------
local udp_table = DissectorTable.get("udp.port")
udp_table:add(17754, p_zep)

print("[UWB ZEP v3 Dissector] Loaded on UDP port 17754")
