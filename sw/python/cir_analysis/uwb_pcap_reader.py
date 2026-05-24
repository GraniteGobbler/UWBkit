"""
uwb_pcap_reader.py
Reads UWB custom packets from a .pcapng file and decodes them.

Firmware packet layout (uart_send_custom_packet):
  Inner payload = DIAG(33 B) + CONFIG(32 B) + RX_SLOT(48 B) + CIR(6096 B)
  Transport: UDP port 17754, inner payload is the entire UDP payload.

Filter: UDP port 17754, excludes ICMP.
"""

import struct
import math
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import numpy as np

try:
    import matplotlib.pyplot as plt
    MPL_AVAILABLE = True
except ImportError:
    MPL_AVAILABLE = False

try:
    from scapy.all import rdpcap, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Firmware layout constants  (must match uart_send_custom_packet)
# ---------------------------------------------------------------------------
DIAG_OFF         =    0   # start of diagnostic block
DIAG_LEN         =   33   # CUSTOM_DIAG_LEN
RSVD_A_OFF       =   33   # DIAG_LEN
RSVD_A_LEN       =   32   # CUSTOM_RSVD_A_LEN
RX_SLOT_OFF      =   65   # DIAG_LEN + RSVD_A_LEN
RX_SLOT_LEN      =  127   # CUSTOM_RX_SLOT
CIR_OFF          =  192   # DIAG_LEN + RSVD_A_LEN + RX_SLOT_LEN
CIR_LEN          = 6096  # CUSTOM_CIR_LEN
CIR_SAMPLE_BYTES =    6  # int16 LE real + int16 LE imag
CIR_N_SAMPLES    = CIR_LEN // CIR_SAMPLE_BYTES  # 1016

INNER_MIN_LEN    = DIAG_LEN + RSVD_A_LEN        # minimum to be a valid packet
DIAG_MAGIC       = b"DG"

ZEP_UDP_PORT     = 17754

# Ipatov / power constants
IPATOV_TIME_SCALE = 1.0 / (128.0 * 499.2e6)
PWR_OFFSET        = -121.7

# Decawave function codes
FUNC_POLL     = 0xe0
FUNC_RESPONSE = 0xe1
FUNC_FINAL    = 0xe2
FUNC_NAMES    = {FUNC_POLL: "Poll", FUNC_RESPONSE: "Response", FUNC_FINAL: "Final"}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DiagBlock:
    rx_time_s:      float
    peak_index:     int
    peak_amplitude: float
    ipatov_power:   int
    f1:             float
    f2:             float
    f3:             float
    fp_index:       int
    accum_count:    int
    dgc_decision:   int
    diag_seqno:     int   # MAC seqno copied from RX frame
    # Computed power metrics (None if accum_count == 0)
    fp_power_dbm:   Optional[float] = None
    rx_power_dbm:   Optional[float] = None
    peak_power_dbm: Optional[float] = None
    peak_amp_uv:    Optional[float] = None
    delta_p_db:     Optional[float] = None


@dataclass
class ConfigBlock:
    m_seq:           int   # firmware monotonic counter
    rx_len:          int   # actual RX frame length
    chan:            int
    data_rate:       int
    tx_code:         int
    rx_code:         int
    tx_preamb_len:   int
    rx_pac:          int
    sfd_type:        int
    phr_mode:        int
    phr_rate:        int
    sfd_to:          int
    sts_mode:        int
    sts_length:      int
    pdoa_mode:       int


@dataclass
class RxSlot:
    frame_ctrl:    int
    mac_seqno:     int
    pan_id:        int
    dst_addr:      int
    src_addr:      int
    func_code:     int
    func_name:     str
    poll_rx_ts:    Optional[int] = None   # Response / Final only
    resp_tx_ts:    Optional[int] = None   # Response / Final only
    raw:           bytes = field(default_factory=bytes)


@dataclass
class CirData:
    """
    1524 complex samples decoded from the 6096-byte CIR block.

    samples    : list[complex]   real+imag as complex numbers
    real       : np.ndarray      int16 real parts  (shape: [1524])
    imag       : np.ndarray      int16 imag parts  (shape: [1524])
    magnitude  : np.ndarray      |I + jQ|          (shape: [1524])
    raw        : bytes           original 6096 bytes
    """
    samples:   list
    real:      "np.ndarray"
    imag:      "np.ndarray"
    magnitude: "np.ndarray"
    raw:       bytes


@dataclass
class CustomPacket:
    """One fully decoded uart_send_custom_packet() frame."""
    diag:   DiagBlock
    config: ConfigBlock
    rx:     RxSlot
    cir:    CirData


# ---------------------------------------------------------------------------
# Block decoders
# ---------------------------------------------------------------------------

def _be_uint(data: bytes, offset: int, length: int) -> int:
    """Read a big-endian unsigned integer of arbitrary byte length."""
    return int.from_bytes(data[offset:offset + length], "big")


def decode_diag_block(payload: bytes) -> DiagBlock:
    """Decode the 33-byte diagnostic block at payload[DIAG_OFF]."""
    b = payload[DIAG_OFF:]
    assert b[:2] == DIAG_MAGIC, f"Expected 'DG', got {b[:2].hex()}"

    rx_time_s    = _be_uint(b, 2, 5) * IPATOV_TIME_SCALE

    word7        = _be_uint(b, 7, 4)
    peak_index   = (word7 >> 21) & 0x3FF
    Pk           = (word7 & 0x1FFFFF) / 2.0

    ipatov_P     = _be_uint(b, 11, 4) & 0xFFFFF

    F1           = (_be_uint(b, 15, 4) & 0x3FFFFF) / 4.0
    F2           = (_be_uint(b, 19, 4) & 0x3FFFFF) / 4.0
    F3           = (_be_uint(b, 23, 4) & 0x3FFFFF) / 4.0

    fp_index     = (_be_uint(b, 27, 2) >> 6) & 0x3FF
    accum_N      = _be_uint(b, 29, 2) & 0xFFF

    dgc          = b[31]
    diag_seqno   = b[32]

    # Computed power fields
    fp_power = rx_power = peak_power = peak_amp_uv = delta_p = None
    if accum_N > 0:
        N2      = accum_N ** 2
        dgc_6   = 6.0 * dgc
        fp_power   = 10 * math.log10((F1**2 + F2**2 + F3**2) / N2) + dgc_6 + PWR_OFFSET
        rx_power   = 10 * math.log10((ipatov_P * 131072.0) / N2)   + dgc_6 + PWR_OFFSET
        peak_power = 10 * math.log10(3.0 * Pk**2 / N2)             + dgc_6 + PWR_OFFSET
        peak_amp_uv = math.sqrt(10 ** (peak_power / 10) / 1000 * 50) * 1e6
        delta_p     = rx_power - fp_power

    return DiagBlock(
        rx_time_s=rx_time_s, peak_index=peak_index, peak_amplitude=Pk,
        ipatov_power=ipatov_P, f1=F1, f2=F2, f3=F3,
        fp_index=fp_index, accum_count=accum_N,
        dgc_decision=dgc, diag_seqno=diag_seqno,
        fp_power_dbm=fp_power, rx_power_dbm=rx_power,
        peak_power_dbm=peak_power, peak_amp_uv=peak_amp_uv,
        delta_p_db=delta_p,
    )


def decode_config_block(payload: bytes) -> ConfigBlock:
    """Decode the 32-byte config / rsvd-A block at payload[RSVD_A_OFF]."""
    b = payload[RSVD_A_OFF:]
    return ConfigBlock(
        m_seq          = _be_uint(b,  0, 4),
        rx_len         = _be_uint(b,  4, 2),
        chan           = b[6],
        data_rate      = b[7],
        tx_code        = b[8],
        rx_code        = b[9],
        tx_preamb_len  = b[10],
        rx_pac         = b[11],
        sfd_type       = b[12],
        phr_mode       = b[13],
        phr_rate       = b[14],
        sfd_to         = _be_uint(b, 15, 2),
        sts_mode       = b[17],
        sts_length     = b[18],
        pdoa_mode      = b[19],
    )


def decode_rx_slot(payload: bytes, rx_len: int) -> RxSlot:
    """
    Decode the 48-byte RX slot at payload[RX_SLOT_OFF].
    rx_len is the actual frame length from the config block.
    """
    b = payload[RX_SLOT_OFF:]

    # All multi-byte fields in the 802.15.4 frame are little-endian
    frame_ctrl = struct.unpack_from("<H", b, 0)[0]
    mac_seqno  = b[2]
    pan_id     = struct.unpack_from("<H", b, 3)[0]
    dst_addr   = struct.unpack_from("<H", b, 5)[0]
    src_addr   = struct.unpack_from("<H", b, 7)[0]
    func_code  = b[9]

    poll_rx_ts = resp_tx_ts = None
    if func_code in (FUNC_RESPONSE, FUNC_FINAL):
        if rx_len >= 14:
            poll_rx_ts = struct.unpack_from(">I", b, 10)[0]
        if rx_len >= 18:
            resp_tx_ts = struct.unpack_from(">I", b, 14)[0]

    return RxSlot(
        frame_ctrl=frame_ctrl, mac_seqno=mac_seqno,
        pan_id=pan_id, dst_addr=dst_addr, src_addr=src_addr,
        func_code=func_code,
        func_name=FUNC_NAMES.get(func_code, f"Unknown(0x{func_code:02x})"),
        poll_rx_ts=poll_rx_ts, resp_tx_ts=resp_tx_ts,
        raw=bytes(b[:RX_SLOT_LEN]),
    )


def decode_cir_block(payload: bytes) -> CirData:
    raw = payload[CIR_OFF: CIR_OFF + CIR_LEN]
    n   = len(raw) // CIR_SAMPLE_BYTES

    real = np.empty(n, dtype=np.float64)
    imag = np.empty(n, dtype=np.float64)

    for i in range(n):
        o = i * CIR_SAMPLE_BYTES
        # 3-byte little-endian signed (18-bit value in 24-bit container)
        re = int.from_bytes(raw[o    :o + 3], "little", signed=True)
        im = int.from_bytes(raw[o + 3:o + 6], "little", signed=True)
        real[i] = re
        imag[i] = im

    mag     = np.sqrt(real**2 + imag**2)
    samples = [complex(real[i], imag[i]) for i in range(n)]
    return CirData(samples=samples, real=real, imag=imag, magnitude=mag, raw=raw)

# ---------------------------------------------------------------------------
# Top-level single-packet decoder
# ---------------------------------------------------------------------------

def decode_custom_packet(udp_payload: bytes) -> Optional[CustomPacket]:
    """
    Decode one uart_send_custom_packet() inner payload (= UDP payload bytes).

    Returns None if the payload is too short or does not start with 'DG'.
    """
    if len(udp_payload) < INNER_MIN_LEN:
        return None
    if udp_payload[DIAG_OFF:DIAG_OFF + 2] != DIAG_MAGIC:
        return None

    diag   = decode_diag_block(udp_payload)
    config = decode_config_block(udp_payload)
    rx     = decode_rx_slot(udp_payload, config.rx_len)

    # CIR block may be absent in truncated captures
    if len(udp_payload) < CIR_OFF + CIR_SAMPLE_BYTES:
        cir = None
    else:
        cir = decode_cir_block(udp_payload)

    return CustomPacket(diag=diag, config=config, rx=rx, cir=cir)


# ---------------------------------------------------------------------------
# pcapng reader
# ---------------------------------------------------------------------------

def read_custom_packets(pcapng_path: str | Path) -> list[CustomPacket]:
    """
    Read a .pcapng file and return a list of decoded CustomPacket objects,
    one per UDP frame on port 17754 that contains a valid custom payload.

    Requires: pip install scapy
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("scapy is required: pip install scapy")

    packets = rdpcap(str(pcapng_path))
    results = []

    for pkt in packets:
        if pkt.haslayer(ICMP):
            continue
        if not pkt.haslayer(UDP):
            continue
        udp = pkt[UDP]
        if ZEP_UDP_PORT not in (udp.sport, udp.dport):
            continue

        udp_payload = bytes(udp.payload)
        decoded = decode_custom_packet(udp_payload)
        if decoded is not None:
            results.append(decoded)

    return results


# ---------------------------------------------------------------------------
# Convenience accessors
# ---------------------------------------------------------------------------

def extract_cir_samples(
    pcapng_path: str | Path,
) -> tuple[list[int], list[list[complex]], list["np.ndarray"]]:
    """
    Read all custom packets from a capture and return:

    sequence_ids : list[int]          – firmware m_seq for each packet
    samples_list : list[list[complex]]– complex I+jQ samples per packet
    magnitudes   : list[np.ndarray]   – |I+jQ| magnitude array per packet

    Each inner list / array has CIR_N_SAMPLES (1524) entries.
    """
    pkts = read_custom_packets(pcapng_path)

    sequence_ids = []
    samples_list = []
    magnitudes   = []

    for p in pkts:
        if p.cir is None:
            continue
        sequence_ids.append(p.config.m_seq)
        samples_list.append(p.cir.samples)
        magnitudes.append(p.cir.magnitude)

    return sequence_ids, samples_list, magnitudes


def extract_cir_arrays(
    pcapng_path: str | Path,
) -> tuple[list[int], "np.ndarray", "np.ndarray", "np.ndarray"]:
    """
    Like extract_cir_samples but returns stacked NumPy arrays for
    easy bulk analysis:

    sequence_ids : list[int]      shape [N]
    real_matrix  : np.ndarray     shape [N, 1524]  – real parts
    imag_matrix  : np.ndarray     shape [N, 1524]  – imaginary parts
    mag_matrix   : np.ndarray     shape [N, 1524]  – magnitudes

    N = number of valid packets.
    """
    pkts = read_custom_packets(pcapng_path)
    valid = [p for p in pkts if p.cir is not None]

    if not valid:
        empty = np.empty((0, CIR_N_SAMPLES))
        return [], empty, empty, empty

    seq_ids = [p.config.m_seq for p in valid]
    real    = np.vstack([p.cir.real    for p in valid])
    imag    = np.vstack([p.cir.imag    for p in valid])
    mag     = np.vstack([p.cir.magnitude for p in valid])

    return seq_ids, real, imag, mag


# ---------------------------------------------------------------------------
# Analysis helper (kept compatible with existing analyze_cir call-site)
# ---------------------------------------------------------------------------

def analyze_cir(
    magnitude:     "np.ndarray",
    seqno:         int,
    samples:       list,
    first_path_id: int,
    peak_path_id:  int,
    output_graph:  bool = False,
):
    """
    Compute channel statistics from a CIR magnitude vector and optionally
    plot the result.  API is identical to the previous version.

    Returns: (P_tau_i, p_i, tau, tau_first, tau_last, rms_delay, B_c)
    """
    f_sample  = 2 * 499.2e6
    t_sample  = 1.0 / f_sample
    tau_i     = np.arange(len(magnitude))
    tau       = t_sample * tau_i

    noise_mean  = np.mean(magnitude[:601])
    noise_dev   = np.std(magnitude[:601])
    threshold_P = 100 * (noise_dev**2 + noise_mean**2)

    P_tau_i    = magnitude**2
    above_noise = P_tau_i >= threshold_P
    P_tau_i[~above_noise] = 0.0

    total_P   = np.sum(P_tau_i)
    if total_P == 0:
        total_P = 1.0
    p_i       = P_tau_i / total_P
    tau_mean  = np.sum(tau * p_i)
    tau_mean_n = np.sum(tau_i * p_i)
    rms_delay  = np.sqrt(np.sum((tau  - tau_mean)**2  * p_i))
    rms_delay_n = np.sqrt(np.sum((tau_i - tau_mean_n)**2 * p_i))

    idx_above = np.where(above_noise)[0]
    if len(idx_above) >= 2:
        tau_first   = tau[idx_above[0]]
        tau_last    = tau[idx_above[-1]]
        tau_first_n = int(idx_above[0])
        tau_last_n  = int(idx_above[-1])
    else:
        tau_first = tau_last = 0.0
        tau_first_n = tau_last_n = 0

    B_c   = 1.0 / (5.0 * rms_delay) if rms_delay > 0 else float("inf")
    B_c_n = 5.0 * rms_delay_n

    if MPL_AVAILABLE:
        samples_arr = np.array(samples)
        dft = np.fft.fft(samples_arr)
        dft[0] = 0

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 5), num=seqno)

        ax1.plot(magnitude, linewidth=1, color="black",
                 marker="x", markersize=4, markerfacecolor="black")
        ax1.axvline(first_path_id, color="blue",  linestyle="--")
        ax1.axvline(peak_path_id,  color="red",   linestyle="--")
        ax1.set_xlim(first_path_id - 20, first_path_id + 80)
        ax1.text(first_path_id - 18, np.max(magnitude) * 0.9,
                 f"First path ({first_path_id})", color="blue")
        ax1.text(first_path_id - 18, np.max(magnitude) * 0.8,
                 f"Peak path ({peak_path_id})",  color="red")
        ax1.set_xlabel("Sample index [-]")
        ax1.set_ylabel("Magnitude [-]")
        ax1.set_title(f"CIR Magnitude (m_seq={seqno}, {len(samples)} samples)")
        ax1.grid(True)

        half = 1016 // 2 + 1
        dft_mag = np.abs(dft[:half])
        peak_dft = np.max(dft_mag)
        if peak_dft > 0:
            dft_mag /= peak_dft
        ax2.set_title("CIR FFT Magnitude (normalised)")
        ax2.set_xlabel("Sample [-]")
        ax2.set_ylabel("Normalised magnitude [-]")
        ax2.plot(dft_mag, linewidth=1, color="black")
        ax2.grid(True)

        plt.tight_layout()
        if output_graph:
            Path("./figures").mkdir(parents=True, exist_ok=True)
            plt.savefig(f"./figures/cir_magnitude_{seqno}.pdf",
                        format="pdf", bbox_inches="tight")

    return P_tau_i, p_i, tau, tau_first, tau_last, rms_delay, B_c


def cir_compare(seqno1 : int, seqno2 : int, packets: list[CustomPacket], magnitudes: list["np.ndarray"], samples_list: list[list[complex]]):
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 5))

    ax1.plot(magnitudes[seqno1], linewidth=1, color="black",
                marker="x", markersize=4, markerfacecolor="black")
    ax1.axvline(packets[seqno1].diag.fp_index, color="blue",  linestyle="--")
    ax1.axvline(packets[seqno1].diag.peak_index,  color="red",   linestyle="--")
    ax1.set_xlim(packets[seqno1].diag.fp_index - 20, packets[seqno1].diag.fp_index + 80)
    ax1.text(packets[seqno1].diag.fp_index - 18, np.max(magnitudes[seqno1]) * 0.9,
                f"First path ({packets[seqno1].diag.fp_index})", color="blue")
    ax1.text(packets[seqno1].diag.fp_index - 18, np.max(magnitudes[seqno1]) * 0.8,
                f"Peak path ({packets[seqno1].diag.peak_index})",  color="red")
    ax1.set_xlabel("Sample index [-]")
    ax1.set_ylabel("Magnitude [-]")
    ax1.set_title(f"CIR Magnitude (m_seq={seqno1}, {len(samples_list[seqno1])} samples)")
    ax1.grid(True)

    ax2.plot(magnitudes[seqno2], linewidth=1, color="black",
                marker="x", markersize=4, markerfacecolor="black")
    ax2.axvline(packets[seqno2].diag.fp_index, color="blue",  linestyle="--")
    ax2.axvline(packets[seqno2].diag.peak_index,  color="red",   linestyle="--")
    ax2.set_xlim(packets[seqno2].diag.fp_index - 20, packets[seqno2].diag.fp_index + 80)
    ax2.text(packets[seqno2].diag.fp_index - 18, np.max(magnitudes[seqno2]) * 0.9,
                f"First path ({packets[seqno2].diag.fp_index})", color="blue")
    ax2.text(packets[seqno2].diag.fp_index - 18, np.max(magnitudes[seqno2]) * 0.8,
                f"Peak path ({packets[seqno2].diag.peak_index})",  color="red")
    ax2.set_xlabel("Sample index [-]")
    ax2.set_ylabel("Magnitude [-]")
    ax2.set_title(f"CIR Magnitude (m_seq={seqno2}, {len(samples_list[seqno2])} samples)")
    ax2.grid(True)

    plt.tight_layout()
    
    
    return

# ---------------------------------------------------------------------------
# Self-test  (no pcap file needed)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Build a minimal synthetic inner payload to exercise all decoders
    payload = bytearray(DIAG_LEN + RSVD_A_LEN + RX_SLOT_LEN + CIR_LEN)

    # Block 1: DG magic + dummy bytes
    payload[0:2] = b"DG"
    # ipatovRxTime (5 B BE) = 12345678
    payload[2:7] = (12345678).to_bytes(5, "big")
    # ipatovPeak = 0x00A00200 → peak_index=(0xA00200>>21)&0x3FF = 0x50 = 80
    struct.pack_into(">I", payload, 7,  0x00A00200)
    struct.pack_into(">I", payload, 11, 0x000FFFFF)   # ipatovPower
    struct.pack_into(">I", payload, 15, 0x003FFFFF)   # F1
    struct.pack_into(">I", payload, 19, 0x003FFFFF)   # F2
    struct.pack_into(">I", payload, 23, 0x003FFFFF)   # F3
    struct.pack_into(">H", payload, 27, 0x07C0)       # fp_index = (0x07C0>>6)&0x3FF = 31
    struct.pack_into(">H", payload, 29, 0x0100)       # accum_count = 0x100 & 0xFFF = 256
    payload[31] = 1   # DGC decision
    payload[32] = 7   # diag seqno

    # Block 2: m_seq=42, rx_len=12, chan=9
    struct.pack_into(">I", payload, RSVD_A_OFF + 0, 42)
    struct.pack_into(">H", payload, RSVD_A_OFF + 4, 12)
    payload[RSVD_A_OFF + 6] = 9    # chan

    # Block 3: Frame Control=0x8841 LE, PAN=0xDECA, func=Poll
    struct.pack_into("<H", payload, RX_SLOT_OFF + 0, 0x8841)  # frame ctrl
    payload[RX_SLOT_OFF + 2] = 5   # MAC seqno
    struct.pack_into("<H", payload, RX_SLOT_OFF + 3, 0xDECA)  # PAN ID
    struct.pack_into("<H", payload, RX_SLOT_OFF + 5, 0x0001)  # dst
    struct.pack_into("<H", payload, RX_SLOT_OFF + 7, 0x0002)  # src
    payload[RX_SLOT_OFF + 9] = FUNC_POLL

    # Block 4: synthetic CIR — sample[0] = I=100, Q=200; sample[1] = I=-50, Q=75
    struct.pack_into("<h", payload, CIR_OFF + 0,  100)
    struct.pack_into("<h", payload, CIR_OFF + 2,  200)
    struct.pack_into("<h", payload, CIR_OFF + 4,  -50)
    struct.pack_into("<h", payload, CIR_OFF + 6,   75)

    pkt = decode_custom_packet(bytes(payload))
    assert pkt is not None,                         "decode returned None"
    assert pkt.config.m_seq == 42,                  f"m_seq mismatch: {pkt.config.m_seq}"
    assert pkt.config.chan == 9,                     f"chan mismatch"
    assert pkt.rx.func_name == "Poll",              f"func mismatch: {pkt.rx.func_name}"
    assert pkt.cir.real[0] == 100,                  f"I[0] mismatch: {pkt.cir.real[0]}"
    assert pkt.cir.imag[0] == 200,                  f"Q[0] mismatch: {pkt.cir.imag[0]}"
    assert pkt.cir.real[1] == -50,                  f"I[1] mismatch: {pkt.cir.real[1]}"
    mag0_expected = math.sqrt(100**2 + 200**2)
    assert abs(pkt.cir.magnitude[0] - mag0_expected) < 0.01, \
        f"|mag[0]| mismatch: {pkt.cir.magnitude[0]:.2f} vs {mag0_expected:.2f}"

    print("Self-test passed!")
    print(f"  m_seq        : {pkt.config.m_seq}")
    print(f"  chan          : {pkt.config.chan}")
    print(f"  func          : {pkt.rx.func_name}")
    print(f"  diag seqno    : {pkt.diag.diag_seqno}")
    print(f"  fp_power dBm  : {pkt.diag.fp_power_dbm:.2f}")
    print(f"  CIR samples   : {len(pkt.cir.samples)}")
    print(f"  I[0], Q[0]    : {int(pkt.cir.real[0])}, {int(pkt.cir.imag[0])}")
    print(f"  |mag[0]|      : {pkt.cir.magnitude[0]:.2f}")
    print()
    print("Usage example:")
    print("  from uwb_pcap_reader import extract_cir_samples, extract_cir_arrays")
    print("  seq_ids, samples_list, magnitudes = extract_cir_samples('capture.pcapng')")
    print("  seq_ids, real, imag, mag = extract_cir_arrays('capture.pcapng')")
    print("    → real.shape == (N, 1524),  mag.shape == (N, 1524)")
