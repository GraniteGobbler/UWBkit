import matplotlib.pyplot as plt
import numpy as np
from uwb_pcap_reader import extract_cir_samples, analyze_cir, read_custom_packets, cir_compare

file_path = "captures/capture_bigpackets2.pcapng"

res = read_custom_packets(file_path)
seq_ids, samples_list, magnitudes = extract_cir_samples(file_path)
# analyze_cir(magnitudes[0], seq_ids[0], samples_list[0], res[0].diag.fp_index, res[0].diag.peak_index)

# Compare two CIRs in a plot for seq_ids[m_seq]
cir_compare(seq_ids[0], seq_ids[3], res, magnitudes, samples_list)


plt.show()