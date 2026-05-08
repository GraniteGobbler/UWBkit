# from uwb_pcap_reader import read_uwb_packets

# packets = read_uwb_packets("capture.pcapng")
# for p in packets:
#     rx  = p["rx_message"]   # 12 bytes
#     cir = p["cir_data"]     # 110 bytes (or whatever chunk_len says)
#     hdr = p["cir_header"]
#     seqno = p['zep_header']['seqno']
#     print(rx.hex(), seqno, hdr, cir.hex())

# from uwb_pcap_reader import read_uwb_packets_cir
# cir_bytes, index = read_uwb_packets_cir("capture.pcapng")

# # Slice back an individual chunk
# entry = index[0]
# chunk = cir_bytes[entry["cir_offset"] : entry["cir_offset"] + entry["chunk_len"]]

# # Parse as 3-byte little-endian signed integers (DW1000 accumulator format)
# samples = [
#     int.from_bytes(cir_bytes[i:i+3], "little", signed=True)
#     for i in range(0, len(cir_bytes) - 2, 3)
# ]


import matplotlib.pyplot as plt
import numpy as np
from uwb_pcap_reader import extract_cir_as_complex


# print(rx_msg.hex())   # 12-byte message
# print(len(cir))       # total CIR bytes across all fragments

# # Example: print magnitude of each sample
# for i, s in enumerate(samples):
#     print(f"[{i:4d}]  re={s.real:8.0f}  im={s.imag:8.0f}  |s|={abs(s):.1f}")
seqno = 0
rx_msg, samples = extract_cir_as_complex("captures/capture.pcapng", seqno=seqno)

magnitude = np.abs(samples)

plt.figure(figsize=(12, 4))
plt.plot(magnitude)
plt.xlim(700, 850)
plt.xlabel("Sample index")
plt.ylabel("Magnitude")
plt.title(f"CIR Magnitude  (RX poll #{seqno},  {len(samples)} samples)")
plt.grid(True)
plt.tight_layout()
plt.show()
