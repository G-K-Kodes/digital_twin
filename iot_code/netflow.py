import joblib
import threading
import queue
import requests
import time
import concurrent.futures
import pandas as pd
import numpy as np
from scapy.all import sniff
from statistics import mean, stdev
from collections import defaultdict

# Load models and scaler
hmm_models = {
    0: joblib.load("C:/Users/gokul/digital_twin/models/hmm_level_1/hmm_model_class_0.0.pkl"),
    1: joblib.load("C:/Users/gokul/digital_twin/models/hmm_level_1/hmm_model_class_1.0.pkl"),
    2: joblib.load("C:/Users/gokul/digital_twin/models/hmm_level_1/hmm_model_class_2.0.pkl"),
}

label_mapping_inv = {0: "Anomaly", 1: "Benign", 2: "Ping Sweep (Potential Anomaly)"}
scaler = joblib.load("C:/Users/gokul/digital_twin/models/hmm_level_1/scaler.pkl")
url = "http://localhost:5000/predict/netflow"
session = requests.Session()
executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

# Queues and control
raw_feature_queue = queue.Queue()
processed_feature_queue = queue.Queue()
stop_event = threading.Event()
flow_cache = defaultdict(list)

# --- Utilities ---
def send_to_database_async(flow):
    headers = {'Content-Type': 'application/json'}
    executor.submit(session.post, url, json=flow, headers=headers)

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
    last_fwd, last_bwd = None, None
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
    iats = sorted(times)
    iat_deltas = [t2 - t1 for t1, t2 in zip(iats, iats[1:])]
    sorted_times = sorted(times)
    active_timeout = 1.0
    active, idle, session_start = [], [], sorted_times[0] if sorted_times else None

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

# --- Classification ---
def classify_sequence(seq):
    global hmm_models
    log_likelihoods = {}

    for class_label, model in hmm_models.items():
        try:
          log_likelihood = model.score(seq)  # Compute log probability
          log_likelihoods[class_label] = log_likelihood
        except:
          log_likelihoods[class_label] = float('-inf')

    # Return class with the highest likelihood
    return max(log_likelihoods, key=log_likelihoods.get)

# --- Threads ---
def packet_collector():
    while not stop_event.is_set():
        packets = sniff(timeout=1)
        flows = group_packets_to_flows(packets)
        for flow_id, pkts in flows.items():
            flow_cache[flow_id].extend(pkts)
        expired = [fid for fid, pkts in flow_cache.items() if len(pkts) >= 5 or (time.time() - pkts[0].time) > 3]
        for fid in expired:
            features = extract_features(fid, flow_cache[fid])
            raw_feature_queue.put([features])
            del flow_cache[fid]

def feature_processor():
    while not stop_event.is_set():
        try:
            raw_features = raw_feature_queue.get(timeout=1)
            initial, processed = process_features(raw_features)
            processed_feature_queue.put((initial, processed))
        except queue.Empty:
            continue

def predictor():
    while not stop_event.is_set():
        batch, initial_batch = [], []
        while len(batch) < 10:
            try:
                initial, processed = processed_feature_queue.get(timeout=0.5)
                batch.append(processed)
                initial_batch.extend(initial)
            except queue.Empty:
                break
        if not batch:
            continue
        df = pd.concat(batch, ignore_index=True)
        for fid, group in df.groupby("Flow ID"):
            seq = group.drop(columns=["Flow ID"]).values
            label = label_mapping_inv[classify_sequence(seq)]
            for flow in initial_batch:
                if flow["Flow ID"] == fid:
                    flow["Prediction"] = label
                    send_to_database_async(flow)
                    break

# --- Main ---
threads = [
    threading.Thread(target=packet_collector),
    threading.Thread(target=feature_processor),
    threading.Thread(target=predictor)
]

for t in threads: t.start()

try:
    while True: pass
except KeyboardInterrupt:
    print("Shutting down...")
    stop_event.set()
    for t in threads: t.join()