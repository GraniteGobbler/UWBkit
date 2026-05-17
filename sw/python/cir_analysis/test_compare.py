import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
import numpy as np
from uwb_pcap_reader import extract_cir_samples, max_seqno, analyze_cir, read_uwb_diag_seqno, parse_diagnostic_packet

file_path = ["captures/capture_diagtest4.pcapng", "captures/capture_diagtest5.pcapng"]

max_seq = max_seqno(file_path[0])
print(f"Max seqno: {max_seq}")
max_seq = max_seqno(file_path[1])
print(f"Max seqno: {max_seq}")

sequence_ids = []
samples_list = []
magnitudes = []

[sequence_ids1, samples_list1, magnitudes1] = extract_cir_samples(file_path[0], 
                                                               start_seqno=1, 
                                                               end_seqno=1,)


[sequence_ids2, samples_list2, magnitudes2] = extract_cir_samples(file_path[1], 
                                                               start_seqno=1, 
                                                               end_seqno=1,)

sequence_ids = [sequence_ids1[0], sequence_ids2[0]]
samples_list = [samples_list1[0], samples_list2[0]]
magnitudes = [magnitudes1[0], magnitudes2[0]]

############################################################################################################
diag_dicts = []
for i in range(len(magnitudes)):
    [diag_data, found_seqno] = read_uwb_diag_seqno(file_path[i], sequence_ids[i])
    diag_dict = parse_diagnostic_packet(diag_data)   
    
    print(diag_dict)
    diag_dicts.append(diag_dict)  


    F1 = diag_dict["ipatovF1"] / 4  # frac(30.2) to float
    F2 = diag_dict["ipatovF2"] / 4
    F3 = diag_dict["ipatovF3"] / 4
    Pk = diag_dict["ipatovPeakAmplitude"] / 2

    FP_power = 10*np.log10((F1**2 + F2**2 + F3**2)/(diag_dict["ipatovAccumCount"]**2)) + 6*diag_dict["DGC_DECISION"] - 121.7
    RX_power = 10*np.log10((diag_dict["ipatovPower"]*(2**17))/(diag_dict["ipatovAccumCount"]**2)) + 6*diag_dict["DGC_DECISION"] - 121.7
    
    Peak_Power = 10*np.log10(3 * (Pk**2)/(diag_dict["ipatovAccumCount"]**2)) + 6*diag_dict["DGC_DECISION"] - 121.7
    Peak_Amplitude = np.sqrt(10**(Peak_Power/10)/1000 * 50)
    
    delta_P = RX_power - FP_power
    
    print(f"FP power: {FP_power:.3f} dBm")
    print(f"RX power: {RX_power:.3f} dBm")
    print(f"Delta P: {delta_P:.3f} dB")
    print(f"Peak power: {Peak_Power:.3f} dBm")
    print(f"Peak amplitude: {Peak_Amplitude*1e6:.3f} uV")
    print("--------------------------------------------------")

    # Sampling frequency of CIR accumulator?
    # Peak power/amplitude even real?
    # Correlator FFT sensible?
    # Other analysis metrics?
    # What is the point of a custom ZEP dissector?

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 5))

ax1.plot(magnitudes[0], linewidth=1, color='black', marker='x', markersize=4, markerfacecolor='black')
ax1.axvline(diag_dicts[0]["ipatovFpIndex"], color='blue', linestyle='--')
ax1.axvline(diag_dicts[0]["ipatovPeakIndex"], color='red', linestyle='--')
ax1.set_xlim(diag_dicts[0]["ipatovFpIndex"]-20, diag_dicts[0]["ipatovFpIndex"]+80)

ax1.text(diag_dicts[0]["ipatovFpIndex"]-18, np.max(magnitudes[0])*0.9, f"First path ({diag_dicts[0]['ipatovFpIndex']})", color='blue')
ax1.text(diag_dicts[0]["ipatovFpIndex"]-18, np.max(magnitudes[0])*0.8, f"Peak path ({diag_dicts[0]['ipatovPeakIndex']})", color='red')

ax1.set_xlabel("Sample index [-]")
ax1.set_ylabel("Magnitude [-]")
ax1.set_title(f"CIR Correlation Magnitude  (RX poll #{sequence_ids[0]},  {len(samples_list[0])} samples)")
ax1.grid(True)

# plt.subplot(2, 1, 1).locator_params(axis='y', nbins=6)



ax2.plot(magnitudes[1], linewidth=1, color='black', marker='x', markersize=4, markerfacecolor='black')
ax2.axvline(diag_dicts[1]["ipatovFpIndex"], color='blue', linestyle='--')
ax2.axvline(diag_dicts[1]["ipatovPeakIndex"], color='red', linestyle='--')
ax2.set_xlim(diag_dicts[1]["ipatovFpIndex"]-20, diag_dicts[1]["ipatovFpIndex"]+80)

ax2.text(diag_dicts[1]["ipatovFpIndex"]-18, np.max(magnitudes[1])*0.9, f"First path ({diag_dicts[1]['ipatovFpIndex']})", color='blue')
ax2.text(diag_dicts[1]["ipatovFpIndex"]-18, np.max(magnitudes[1])*0.8, f"Peak path ({diag_dicts[1]['ipatovPeakIndex']})", color='red')

ax2.set_xlabel("Sample index [-]")
ax2.set_ylabel("Magnitude [-]")
ax2.set_title(f"CIR Correlation Magnitude  (RX poll #{sequence_ids[1]},  {len(samples_list[1])} samples)")
ax2.grid(True)

ax1.yaxis.set_major_locator(MaxNLocator(nbins=6))
ax2.yaxis.set_major_locator(MaxNLocator(nbins=5))

plt.tight_layout()

plt.savefig(f"./figures/cir_compare.pdf", format="pdf", bbox_inches="tight")

plt.show()