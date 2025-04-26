import joblib
import threading
import queue
import time
import concurrent.futures
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scapy.all import sniff
from statistics import mean, stdev
from collections import defaultdict

# --- Load Models and Scaler ---
hmm_models = {
    0: joblib.load("C:/Users/gokul/digital_twin/models/hmm_level_1/hmm_model_class_0.0.pkl"),
    1: joblib.load("C:/Users/gokul/digital_twin/models/hmm_level_1/hmm_model_class_1.0.pkl"),
    2: joblib.load("C:/Users/gokul/digital_twin/models/hmm_level_1/hmm_model_class_2.0.pkl"),
}

label_mapping_inv = {0: "Anomaly", 1: "Benign", 2: "Ping Sweep (Potential Anomaly)"}
scaler = joblib.load("C:/Users/gokul/digital_twin/models/hmm_level_1/scaler.pkl")

# --- Queues and Flow Storage ---
'''raw_feature_queue = queue.Queue()
processed_feature_queue = queue.Queue()
stop_event = threading.Event()'''
flow_cache = defaultdict(list)

# --- Utilities ---
def get_flow_id(pkt):
    if pkt.haslayer('IP') and pkt.haslayer('TCP'):
        ip, tcp = pkt['IP'], pkt['TCP']
        return f"{ip.src}-{ip.dst}-{tcp.sport}-{tcp.dport}-{ip.proto}"
    return None

def group_packets_to_flows(packets):
    flows = defaultdict(list)
    for pkt in packets:
        flow_id = get_flow_id(pkt)
        if flow_id:
            flows[flow_id].append(pkt)
    return flows

# --- Feature Extraction ---
def extract_features(flow_id, pkts):
    times = [pkt.time for pkt in pkts]
    src_ip = flow_id.split('-')[0]
    fwd, bwd, fwd_iat, bwd_iat = [], [], [], []
    last_fwd = last_bwd = None
    fwd_count = bwd_count = 0
    fin = syn = rst = psh = ack = urg = cwr = ece = 0

    for pkt in pkts:
        if pkt.haslayer('IP') and pkt.haslayer('TCP'):
            ip, tcp = pkt['IP'], pkt['TCP']
            length = len(pkt)
            if ip.src == src_ip:
                fwd.append(length)
                fwd_count += 1
                if last_fwd: fwd_iat.append(pkt.time - last_fwd)
                last_fwd = pkt.time
            else:
                bwd.append(length)
                bwd_count += 1
                if last_bwd: bwd_iat.append(pkt.time - last_bwd)
                last_bwd = pkt.time

            flags = tcp.flags
            fin += flags & 0x01 != 0
            syn += flags & 0x02 != 0
            rst += flags & 0x04 != 0
            psh += flags & 0x08 != 0
            ack += flags & 0x10 != 0
            urg += flags & 0x20 != 0
            cwr += flags & 0x80 != 0
            ece += flags & 0x40 != 0

    total = fwd + bwd
    duration = max(times) - min(times) if len(times) > 1 else 0
    iat_deltas = [t2 - t1 for t1, t2 in zip(sorted(times), sorted(times)[1:])]

    active, idle = [], []
    sorted_times = sorted(times)
    session_start = sorted_times[0] if sorted_times else None
    active_timeout = 1.0

    for i in range(1, len(sorted_times)):
        gap = sorted_times[i] - sorted_times[i - 1]
        if gap > active_timeout:
            if sorted_times[i - 1] > session_start:
                active.append(sorted_times[i - 1] - session_start)
            idle.append(gap)
            session_start = sorted_times[i]
    if session_start and sorted_times[-1] > session_start:
        active.append(sorted_times[-1] - session_start)

    return {
        "Flow ID": flow_id,
        "Flow Duration": duration,
        "Total Fwd Packet": fwd_count,
        "Total Bwd packets": bwd_count,
        "Fwd Packet Length Mean": mean(fwd) if fwd else 0,
        "Fwd Packet Length Std": stdev(fwd) if len(fwd) > 1 else 0,
        "Bwd Packet Length Mean": mean(bwd) if bwd else 0,
        "Bwd Packet Length Std": stdev(bwd) if len(bwd) > 1 else 0,
        "Flow Bytes/s": sum(total)/duration if duration else 0,
        "Flow Packets/s": len(pkts)/duration if duration else 0,
        "Flow IAT Mean": mean(iat_deltas) if iat_deltas else 0,
        "Flow IAT Std": stdev(iat_deltas) if len(iat_deltas) > 1 else 0,
        "Fwd IAT Mean": mean(fwd_iat) if fwd_iat else 0,
        "Fwd IAT Std": stdev(fwd_iat) if len(fwd_iat) > 1 else 0,
        "Bwd IAT Total": sum(bwd_iat),
        "Bwd IAT Mean": mean(bwd_iat) if bwd_iat else 0,
        "Bwd IAT Std": stdev(bwd_iat) if len(bwd_iat) > 1 else 0,
        "Fwd Packets/s": fwd_count/duration if duration else 0,
        "Bwd Packets/s": bwd_count/duration if duration else 0,
        "Packet Length Mean": mean(total) if total else 0,
        "Packet Length Std": stdev(total) if len(total) > 1 else 0,
        "FIN Flag Count": fin,
        "SYN Flag Count": syn,
        "RST Flag Count": rst,
        "PSH Flag Count": psh,
        "ACK Flag Count": ack,
        "URG Flag Count": urg,
        "CWR Flag Count": cwr,
        "ECE Flag Count": ece,
        "Down/Up Ratio": bwd_count/fwd_count if fwd_count else 0,
        "Subflow Fwd Packets": fwd_count,
        "Subflow Fwd Bytes": sum(fwd),
        "Subflow Bwd Packets": bwd_count,
        "Subflow Bwd Bytes": sum(bwd),
        "Active Mean": mean(active) if active else 0,
        "Active Std": stdev(active) if len(active) > 1 else 0,
        "Idle Mean": mean(idle) if idle else 0,
        "Idle Std": stdev(idle) if len(idle) > 1 else 0,
    }

# --- Feature Processing ---
def process_features(raw_features):
    df = pd.DataFrame(raw_features)
    df = df.replace([np.inf, -np.inf], np.nan).fillna(df.median(numeric_only=True))
    features = df.drop(columns=["Flow ID"], errors='ignore')
    scaled = scaler.transform(features)
    df_scaled = pd.DataFrame(scaled, columns=features.columns)
    df_scaled["Flow ID"] = df["Flow ID"].values
    return df.to_dict(orient='records'), df_scaled

# --- HMM Prediction ---
def classify_sequence(seq):
    log_likelihoods = {}
    for class_label, model in hmm_models.items():
        try:
            log_likelihoods[class_label] = model.score(seq)
        except:
            log_likelihoods[class_label] = float('-inf')
    return max(log_likelihoods, key=log_likelihoods.get)

# --- Visualization ---
def plot_emission_means(model, feature_names, class_name):
    plt.figure(figsize=(12, 6))
    for i in range(model.n_components):
        plt.plot(model.means_[i], label=f"State {i}")
    plt.xticks(ticks=np.arange(len(feature_names)), labels=feature_names, rotation=90)
    plt.title(f"Emission Means per State - {class_name}")
    plt.ylabel("Mean Value (standardized)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"emission_means_{class_name}_{int(time.time())}.png")

packets = sniff(timeout = 5)
flows = group_packets_to_flows(packets)
for fid, pkts in flows.items():
    flow_cache[fid].extend(pkts)
expired = [fid for fid, pkts in flow_cache.items() if len(pkts) >= 5 or (time.time() - pkts[0].time) > 3]
for fid in expired:
    batch, initial_batch = [], []
    features = extract_features(fid, flow_cache[fid])
    initial, processed = process_features([features])
    batch.append(processed)
    initial_batch.extend(initial)
    df = pd.concat(batch, ignore_index=True)
    feature_names = df.drop(columns=["Flow ID"]).columns

    for fid, group in df.groupby("Flow ID"):
        seq = group.drop(columns=["Flow ID"]).values
        pred_class = classify_sequence(seq)
        label = label_mapping_inv[pred_class]

        # 🔥 Visualization
        model = hmm_models[pred_class]
        plot_emission_means(model, feature_names, label)


'''for class_label, model in hmm_models.items():
    print(f"\nParameters for {label_mapping_inv[class_label]}:")
    print("Number of states:", model.n_components)
    print("Start probabilities:\n", model.startprob_)
    print("Transition matrix:\n", model.transmat_)
    print("Means:\n", model.means_)
    print("Covariances:\n", model.covars_)'''

'''from scipy.stats import multivariate_normal
import numpy as np

def emission_prob(x, state, model):
    x = np.array(x).reshape(-1)  # Ensure it's a 1D vector
    mean = model.means_[state]
    cov = model.covars_[state]
    return multivariate_normal.pdf(x, mean=mean, cov=cov)


# Example: emission prob of obs [1.2, 0.5, ...] in state 0 of class 1
# Use the dimensionality from the model
feature_dim = hmm_models[1].means_.shape[1]
obs = np.random.rand(feature_dim)  # e.g. [0.2, 0.8, ..., 0.1] (length = 37)

for _, model in hmm_models.items():
    prob = emission_prob(obs, state=1, model = model)
    print(f"Emission probability: {prob}")'''
