"""
uwb_pcap_reader.py
Reads UWB packets from a .pcapng file and decodes them.
Filter: UDP dst port 17754, excludes ICMP.
"""

import struct
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

try:
    from scapy.all import rdpcap, UDP, IP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants matching uwbkit_shared.c
# ---------------------------------------------------------------------------
ZEP_V3_HDR_LEN   = 32
RX_MSG_LEN       = 12
CIR_FRAG_HDR_LEN = 5
ZEP_UDP_PORT     = 17754
ZEP_MAGIC        = b'EX'

# Byte offsets inside a captured loopback UDP packet
# [0..3]   Loopback header  (4 B)
# [4..23]  IPv4 header      (20 B)
# [24..31] UDP header       (8 B)
# [32..63] ZEPv3 header     (32 B)  <-- UDP payload starts here
# [64..75] 12-byte RX msg
# [76..80] 5-byte CIR frag header
# [81..]   CIR fragment data (chunk_len bytes)

LOOPBACK_HDR_LEN = 4
IP_HDR_LEN       = 20
UDP_HDR_LEN      = 8
UDP_PAYLOAD_OFF  = LOOPBACK_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN   # 32
ZEP_PAYLOAD_OFF  = UDP_PAYLOAD_OFF   + ZEP_V3_HDR_LEN              # 64
RX_MSG_OFF       = ZEP_PAYLOAD_OFF                                  # 64
CIR_HDR_OFF      = RX_MSG_OFF        + RX_MSG_LEN                   # 76
CIR_DATA_OFF     = CIR_HDR_OFF       + CIR_FRAG_HDR_LEN             # 81


def decode_zepv3_header(data: bytes) -> dict:
    """Parse the 32-byte ZEPv3 header starting at data[0]."""
    assert data[:2] == ZEP_MAGIC, f"Bad ZEP magic: {data[:2].hex()}"
    assert data[2] == 0x03,       f"Not ZEPv3 (version=0x{data[2]:02x})"
    return {
        "version":       data[2],
        "type":          data[3],
        "channel":       data[4],
        "device_id":     (data[5] << 8) | data[6],
        "crc_mode":      data[7],
        "lqi":           data[8],
        "rel_timestamp": int.from_bytes(data[9:17],  "big"),
        "seqno":         int.from_bytes(data[17:21], "big"),
        "band":          data[21],
        "channel_page":  data[22],
        "frame_len":     data[31],
    }


def decode_cir_fragment_header(data: bytes) -> dict:
    """Parse the 5-byte CIR fragment header."""
    return {
        "tag":           data[0],
        "total_cir_len": (data[1] << 8) | data[2],
        "frag_idx":      data[3],
        "chunk_len":     data[4],
    }


def decode_uwb_packet(raw: bytes) -> dict | None:
    """
    Decode a single raw loopback-captured UWB packet.
    Returns a dict with 'rx_message', 'cir_header', 'cir_data',
    and 'zep_header', or None if the packet does not match the
    expected structure.
    """
    min_len = CIR_DATA_OFF + 1   # at least 1 byte of CIR data
    if len(raw) < min_len:
        return None

    zep_raw = raw[UDP_PAYLOAD_OFF:]
    if zep_raw[:2] != ZEP_MAGIC or zep_raw[2] != 0x03:
        return None

    zep_hdr  = decode_zepv3_header(zep_raw[:ZEP_V3_HDR_LEN])
    rx_msg   = raw[RX_MSG_OFF : RX_MSG_OFF + RX_MSG_LEN]
    cir_hdr  = decode_cir_fragment_header(raw[CIR_HDR_OFF : CIR_HDR_OFF + CIR_FRAG_HDR_LEN])
    chunk    = cir_hdr["chunk_len"]
    cir_data = raw[CIR_DATA_OFF : CIR_DATA_OFF + chunk]

    if len(cir_data) < chunk:
        return None   # truncated

    return {
        "zep_header": zep_hdr,
        "rx_message": rx_msg,          # bytes, length 12
        "cir_header": cir_hdr,
        "cir_data":   cir_data,        # bytes, length chunk_len
    }


# ---------------------------------------------------------------------------
# pcapng reader  (requires scapy: pip install scapy)
# ---------------------------------------------------------------------------

def read_uwb_packets(pcapng_path: str | Path) -> list[dict]:
    """
    Read a .pcapng file and return a list of decoded UWB packets.

    Filters applied:
      - UDP destination port == 17754
      - Not ICMP

    Each returned dict contains:
      'rx_message'  : bytes (12 B)  -- the original IEEE 802.15.4 frame
      'cir_header'  : dict          -- TAG, total_cir_len, frag_idx, chunk_len
      'cir_data'    : bytes         -- raw CIR fragment (chunk_len bytes)
      'zep_header'  : dict          -- ZEPv3 metadata (channel, seqno, etc.)

    Requires:  pip install scapy
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("scapy is required: pip install scapy")

    packets = rdpcap(str(pcapng_path))
    results = []

    for pkt in packets:
        # Exclude ICMP
        if pkt.haslayer(ICMP):
            continue

        # Keep only UDP on port 17754 (src or dst)
        if not pkt.haslayer(UDP):
            continue
        udp = pkt[UDP]
        if ZEP_UDP_PORT not in (udp.sport, udp.dport):
            continue

        # Reconstruct the raw bytes as seen in Wireshark (loopback capture)
        raw = bytes(pkt)
        decoded = decode_uwb_packet(raw)
        if decoded is not None:
            results.append(decoded)

    return results


def read_uwb_packets_cir(pcapng_path: str | Path) -> tuple[bytes, list[dict]]:
    """
    Returns:
      cir_bytes  -- all CIR chunks concatenated into one bytes object
      index      -- list of dicts, one per packet:
                    { 'rx_message', 'cir_offset', 'chunk_len', 'frag_idx', 'seqno' }
                    cir_offset is the byte offset into cir_bytes where this chunk starts
    """
    packets = read_uwb_packets(pcapng_path)
    chunks = []
    index  = []
    offset = 0

    for p in packets:
        chunk = p["cir_data"]
        chunks.append(chunk)
        index.append({
            "rx_message": p["rx_message"],
            "seqno":      p["zep_header"]["seqno"],
            "frag_idx":   p["cir_header"]["frag_idx"],
            "chunk_len":  p["cir_header"]["chunk_len"],
            "cir_offset": offset,
        })
        offset += len(chunk)

    return b"".join(chunks), index

def extract_cir_for_seqno(pcapng_path: str | Path, seqno: int = 0) -> tuple[bytes, bytes]:
    """
    Extract a complete CIR byte array for a single reception identified
    by its ZEPv3 sequence number.

    Fragments are collected in frag_idx order and concatenated.
    Also returns the RX message (12 bytes) from the first fragment.

    Returns:
      rx_message  -- 12-byte IEEE 802.15.4 frame
      cir_bytes   -- concatenated CIR data across all fragments for this seqno
    """
    packets = read_uwb_packets(pcapng_path)
    

    # Collect all fragments belonging to the requested seqno
    fragments = [
        p for p in packets
        if p["zep_header"]["seqno"] == seqno
    ]

    if not fragments:
        raise ValueError(f"No packets found for seqno={seqno}")

    # Sort by fragment index to guarantee correct order
    fragments.sort(key=lambda p: p["cir_header"]["frag_idx"])

    rx_message = fragments[0]["rx_message"]
    cir_bytes  = b"".join(p["cir_data"] for p in fragments)

    return rx_message, cir_bytes


def cir_bytes_to_complex(cir_bytes: bytes) -> list[complex]:
    """
    Parse raw CIR bytes from ACC_MEM into a list of complex samples.

    Format per sample (6 bytes total):
      [0..2]  real part       — 24-bit little-endian, 18-bit signed value
      [3..5]  imaginary part  — 24-bit little-endian, 18-bit signed value

    The upper 6 bits are sign-extension (all 0s or all 1s depending on sign).
    We simply read the full 3 bytes as a signed 24-bit integer.

    Returns a list of complex numbers.
    """
    SAMPLE_BYTES = 6
    n_samples = len(cir_bytes) // SAMPLE_BYTES
    samples = []

    for i in range(n_samples):
        offset = i * SAMPLE_BYTES
        re = int.from_bytes(cir_bytes[offset    :offset + 3], "little", signed=True)
        im = int.from_bytes(cir_bytes[offset + 3:offset + 6], "little", signed=True)
        samples.append(complex(re, im))

    return samples


def extract_cir_as_complex(pcapng_path: str | Path, seqno: int = 0) -> tuple[bytes, list[complex]]:
    """
    Extract the complete CIR for a given sequence number and return
    the samples as a list of complex numbers.

    Returns:
      rx_message  -- 12-byte IEEE 802.15.4 frame
      samples     -- list of complex(re, im), one per CIR sample
    """
    rx_message, cir_bytes = extract_cir_for_seqno(pcapng_path, seqno)
    samples = cir_bytes_to_complex(cir_bytes)
    return rx_message, samples

def max_seqno(pcapng_path: str | Path) -> int:
    """Return the maximum sequence number found in the capture."""
    packets = read_uwb_packets(pcapng_path)
    return max(p["zep_header"]["seqno"] for p in packets)


def export_cir_to_svg(pcapng_path: str | Path, start_seqno: int = 0, end_seqno: int = 0):
    rx_msgs = []
    samples_list = []
    magnitudes = []

    for i in range(start_seqno,end_seqno+1):
    # print(i)
        try:
            rx_msg, samples = extract_cir_as_complex(pcapng_path, seqno=i)
        except ValueError:
            print(f"Error reading seqno: {i}")
            continue  # missing or incomplete reception, skip to next

        magnitude = np.abs(samples)

        plt.figure(figsize=(12, 4), num=i)
        plt.plot(magnitude, linewidth=1)
        plt.xlim(700, 700+152)
        plt.xlabel("Sample index")
        plt.ylabel("Magnitude")
        plt.title(f"CIR Magnitude  (RX poll #{i},  {len(samples)} samples)")
        plt.grid(True)
        plt.tight_layout()

        # plt.savefig(f"figures/cir_magnitude_{i}.svg", format="svg", bbox_inches="tight")

        rx_msgs.append(rx_msg)
        samples_list.append(samples)
        magnitudes.append(magnitude)

    return rx_msgs, samples_list, magnitudes


def get_first_path(magnitude: np.ndarray, threshold: float = 0.35) -> int:
    # First path detector.
    threshold = 0.35 # threshold as fraction of max magnitude
    rMax = np.max(magnitude) 
    n0 = np.flatnonzero((magnitude[:-1] <= threshold*rMax) & (magnitude[1:] >= threshold*rMax))+1
    n0=n0[0]
    print(f"First path: {n0}")

    return n0

def get_PDP_delays(magnitude: np.ndarray, threshold: float = 5e-3):

    # Power Delay Profile
    f_chip = 499.2e6  # chip rate in Hz
    t_sample = 1/f_chip  # seconds per chip
    tau_i = np.arange(len(magnitude))   # sample indices
    tau = t_sample * tau_i  # delay in seconds
    T_symbol = 1016/f_chip  # symbol duration in seconds

    P_tau_i = magnitude**2  # power of each sample

    above_noise = np.zeros_like(P_tau_i, dtype=bool)  # track which samples are above noise floor
    for k in range(len(P_tau_i)):   # zero out noise floor below 1e-3
        if P_tau_i[k] < threshold*np.max(P_tau_i):
            P_tau_i[k] = 0
        else:
            above_noise[k] = True

    p_i = P_tau_i / np.sum(P_tau_i)  # normalize to get power delay profile
    tau_mean = np.sum(tau * p_i)  # mean delay
    rms_delay = np.sqrt(np.sum((tau - tau_mean)**2 * p_i))  # RMS delay spread

    # maximum excess delay, e.g. where power drops below 1% of peak
    tau_first = tau[above_noise][0]  # delay of first path, CURRENTLY NOT SAME AS n0 from get_first_path()
    tau_last = tau[above_noise][-1]  # delay of last significant path
    T_m = tau_last - tau_first

    # Coherence bandwidth (approximate)
    B_c = 1 / (5 * rms_delay)  # coherence bandwidth (Hz),

    print(f"Delay of first path: {tau_first}")
    print(f"Delay of last significant path: {tau_last}")
    print(f"Maximum excess delay: {T_m}")
    print(f"RMS delay spread: {rms_delay}")
    print(f"Coherence bandwidth: {B_c/1e6:.2f} MHz")
    print("Fading type:", "frequency-selective" if rms_delay >= T_symbol/5 else "flat") # Fading type
    
    
    plt.figure(figsize=(12, 4))
    plt.plot(tau, p_i, linewidth=1)
    plt.axvline(tau_first, color='red', linestyle='--')
    plt.axvline(tau_last, color='red', linestyle='--')
    plt.xlim(tau_first-10*t_sample, tau_last+10*t_sample)
    plt.grid(True)
    plt.tight_layout()


    return P_tau_i, p_i, tau, tau_first, tau_last, rms_delay, B_c








# ---------------------------------------------------------------------------
# Quick self-test against the known example packet
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    raw_hex = (
        "02 00 00 00 45 00 00 bb 31 41 00 00 80 11 0a ef "
        "7f 00 00 01 7f 00 00 01 f1 12 45 5a 00 a7 b5 03 "
        "45 58 03 01 05 12 34 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 7f "
        "41 88 00 ca de 57 41 56 45 e0 34 d7 c1 17 d0 00 "
        "6e e8 ff ff 10 00 00 ed ff ff 10 00 00 d4 ff ff "
        "25 00 00 e0 ff ff 2c 00 00 d8 ff ff 2d 00 00 ff "
        "ff ff 1c 00 00 5c 00 00 17 00 00 32 00 00 13 00 "
        "00 fe ff ff 03 00 00 4c 00 00 4f 00 00 28 00 00 "
        "10 00 00 1b 00 00 1a 00 00 34 00 00 14 00 00 24 "
        "00 00 10 00 00 dd 00 00 14 00 00 68 00 00 e1 ff "
        "ff fd ff ff 11 00 00 32 00 00 23 00 00 28 00"
    )
    raw = bytes(int(h, 16) for h in raw_hex.split())
    r = decode_uwb_packet(raw)
    assert r is not None, "decode failed"
    print("Self-test passed!")
    print(f"  RX message  : {r['rx_message'].hex()}")
    print(f"  CIR header  : {r['cir_header']}")
    print(f"  CIR data    : {r['cir_data'].hex()}")
    print(f"  ZEP seqno   : {r['zep_header']['seqno']}")
