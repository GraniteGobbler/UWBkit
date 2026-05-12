import matplotlib.pyplot as plt
import numpy as np
from uwb_pcap_reader import export_cir_to_svg, max_seqno

file_path = "captures/capture_07052026_2251.pcapng"

max_seq = max_seqno(file_path)
print(f"Max seqno: {max_seq}")

[rx_msgs, samples_list, magnitudes] = export_cir_to_svg(file_path, start_seqno=19, end_seqno=19)

stdDev = np.std(magnitudes[0][0:500])
rMax = np.max(magnitudes[0])
a = 20
b = 0.4
tL = np.where(np.abs(magnitudes[0]) >= a*stdDev)[0][-1]
tH = np.where(np.abs(magnitudes[0]) >= b*rMax)[0][0]
nH = np.where(np.abs(magnitudes[0]) >= b*rMax)[0][0]
nr = 0

tRise = tL - tH
n0 = nH - nr

print(n0)



plt.figure(figsize=(12, 4))
plt.plot(magnitudes[0], linewidth=1)
plt.axvline(n0, color='red', linestyle='--')
plt.xlim(700, 700+152)
plt.xlabel("Sample index")
plt.ylabel("Magnitude")
plt.title(f"CIR Magnitude slope")
plt.grid(True)
plt.tight_layout()
plt.show()