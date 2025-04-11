import joblib
from scapy.all import sniff
import pandas as pd
import numpy as np
from statistics import mean, stdev
import json
from collections import defaultdict
import threading
import queue
import requests
import time

""" 'Flow ID','Timestamp', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
    'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Fwd IAT Mean', 'Fwd IAT Std',
    'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Fwd Packets/s', 'Bwd Packets/s','Packet Length Mean',
    'Packet Length Std', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWR Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Active Mean', 'Active Std', 'Idle Mean', 'Idle Std' """

hmm_models = {
    np.int64(0) : joblib.load(r"C:\Users\gokul\digital_twin\models\hmm_level_1\hmm_model_class_0.0.pkl"),
    np.int64(1) : joblib.load(r"C:\Users\gokul\digital_twin\models\hmm_level_1\hmm_model_class_1.0.pkl"),
    np.int64(2) : joblib.load(r"C:\Users\gokul\digital_twin\models\hmm_level_1\hmm_model_class_2.0.pkl")
}

label_mapping = {"Anomaly": 0, "Benign": 1, "Ping Sweep (Potential Anomaly)": 2}

label_mapping_inv = {v: k for k, v in label_mapping.items()}

scaler = joblib.load(r"C:\Users\gokul\digital_twin\models\hmm_level_1\scaler.pkl")

url = "http://localhost:5000/predict/netflow"

def send_to_database(flow):
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, json=flow, headers=headers)
    print(response.text)

raw_feature_queue = queue.Queue()
processed_feature_queue = queue.Queue()
stop_event = threading.Event()

def get_flow_id(pkt):
    if pkt.haslayer('IP') and pkt.haslayer('TCP'):
        ip_layer = pkt['IP']
        tcp_layer = pkt['TCP']
        src = ip_layer.src
        dst = ip_layer.dst
        sport = tcp_layer.sport
        dport = tcp_layer.dport
        proto = ip_layer.proto
        return f"{src}-{dst}-{sport}-{dport}-{proto}"
    return None

def group_packets_to_flows(packets):
    flows = defaultdict(list)
    for pkt in packets:
        flow_id = get_flow_id(pkt)
        if flow_id:
            flows[flow_id].append(pkt)
    return flows

def extract_features(flow_id, pkts):
    times = [pkt.time for pkt in pkts]
    durations = max(times) - min(times) if len(times) > 1 else 0

    # Flow direction
    src_ip = flow_id.split('-')[0]
    fwd_lengths = []
    bwd_lengths = []
    fwd_iats = []
    bwd_iats = []
    last_fwd_time = None
    last_bwd_time = None

    fwd_count = bwd_count = 0
    fwd_times = []
    bwd_times = []

    fin = syn = rst = psh = ack = urg = cwr = ece = 0

    for pkt in pkts:
        if pkt.haslayer('IP') and pkt.haslayer('TCP'):
            ip = pkt['IP']
            tcp = pkt['TCP']
            length = len(pkt)

            if ip.src == src_ip:
                fwd_lengths.append(length)
                fwd_count += 1
                fwd_times.append(pkt.time)
                if last_fwd_time:
                    fwd_iats.append(pkt.time - last_fwd_time)
                last_fwd_time = pkt.time
            else:
                bwd_lengths.append(length)
                bwd_count += 1
                bwd_times.append(pkt.time)
                if last_bwd_time:
                    bwd_iats.append(pkt.time - last_bwd_time)
                last_bwd_time = pkt.time

            flags = tcp.flags
            fin += int(flags & 0x01 != 0)
            syn += int(flags & 0x02 != 0)
            rst += int(flags & 0x04 != 0)
            psh += int(flags & 0x08 != 0)
            ack += int(flags & 0x10 != 0)
            urg += int(flags & 0x20 != 0)
            ece += int(flags & 0x40 != 0)
            cwr += int(flags & 0x80 != 0)

    total_len = fwd_lengths + bwd_lengths
    iats = sorted(times)
    iat_deltas = [t2 - t1 for t1, t2 in zip(iats, iats[1:])]

    flow_duration = durations
    packet_len_mean = mean(total_len) if total_len else 0
    packet_len_std = stdev(total_len) if len(total_len) > 1 else 0

    flow_bytes = sum(total_len)
    flow_packets = len(pkts)
    flow_bps = flow_bytes / durations if durations > 0 else 0
    flow_pps = flow_packets / durations if durations > 0 else 0

    fwd_packet_len_mean = mean(fwd_lengths) if fwd_lengths else 0
    fwd_packet_len_std = stdev(fwd_lengths) if len(fwd_lengths) > 1 else 0
    bwd_packet_len_mean = mean(bwd_lengths) if bwd_lengths else 0
    bwd_packet_len_std = stdev(bwd_lengths) if len(bwd_lengths) > 1 else 0

    # Active/Idle time logic
    sorted_times = sorted(times)
    active_timeout = 1.0  # seconds

    active_periods = []
    idle_periods = []
    session_start = sorted_times[0] if sorted_times else None

    for i in range(1, len(sorted_times)):
        gap = sorted_times[i] - sorted_times[i - 1]
        if gap <= active_timeout:
            continue  # Still in same active period
        else:
            active_duration = sorted_times[i - 1] - session_start
            if active_duration > 0:
                active_periods.append(active_duration)
            idle_periods.append(gap)
            session_start = sorted_times[i]

    if session_start is not None and sorted_times[-1] > session_start:
        active_duration = sorted_times[-1] - session_start
        if active_duration > 0:
            active_periods.append(active_duration)

    features = {
        "Flow ID": flow_id,
        "Flow Duration": durations,
        "Total Fwd Packet": fwd_count,
        "Total Bwd packets": bwd_count,
        "Fwd Packet Length Mean": fwd_packet_len_mean,
        "Fwd Packet Length Std": fwd_packet_len_std,
        "Bwd Packet Length Mean": bwd_packet_len_mean,
        "Bwd Packet Length Std": bwd_packet_len_std,
        "Flow Bytes/s": flow_bps,
        "Flow Packets/s": flow_pps,
        "Flow IAT Mean": mean(iat_deltas) if iat_deltas else 0,
        "Flow IAT Std": stdev(iat_deltas) if len(iat_deltas) > 1 else 0,
        "Fwd IAT Mean": mean(fwd_iats) if fwd_iats else 0,
        "Fwd IAT Std": stdev(fwd_iats) if len(fwd_iats) > 1 else 0,
        "Bwd IAT Total": sum(bwd_iats),
        "Bwd IAT Mean": mean(bwd_iats) if bwd_iats else 0,
        "Bwd IAT Std": stdev(bwd_iats) if len(bwd_iats) > 1 else 0,
        "Fwd Packets/s": fwd_count / durations if durations > 0 else 0,
        "Bwd Packets/s": bwd_count / durations if durations > 0 else 0,
        "Packet Length Mean": packet_len_mean,
        "Packet Length Std": packet_len_std,
        "FIN Flag Count": fin,
        "SYN Flag Count": syn,
        "RST Flag Count": rst,
        "PSH Flag Count": psh,
        "ACK Flag Count": ack,
        "URG Flag Count": urg,
        "CWR Flag Count": cwr,
        "ECE Flag Count": ece,
        "Down/Up Ratio": bwd_count / fwd_count if fwd_count > 0 else 0,
        "Subflow Fwd Packets": fwd_count,
        "Subflow Fwd Bytes": sum(fwd_lengths),
        "Subflow Bwd Packets": bwd_count,
        "Subflow Bwd Bytes": sum(bwd_lengths),
        "Active Mean": mean(active_periods) if active_periods else 0,
        "Active Std": stdev(active_periods) if len(active_periods) > 1 else 0,
        "Idle Mean": mean(idle_periods) if idle_periods else 0,
        "Idle Std": stdev(idle_periods) if len(idle_periods) > 1 else 0,
    }
    return features

def process_features(raw_features):
    df_live = pd.DataFrame(raw_features)

    for col in df_live.columns:
        if col in ["Flow ID", "Timestamp"]:
            continue
        # Replace inf values
        df_live[col] = df_live[col].replace([np.inf, -np.inf], np.nan)
        # Fill NaNs with median
        df_live[col] = df_live[col].fillna(df_live[col].median())

    features_only = df_live.drop(columns=["Flow ID", "Timestamp"], errors='ignore')
    X_live_scaled = scaler.transform(features_only)

    df_live_scaled = pd.DataFrame(X_live_scaled, columns=features_only.columns)
    df_live_scaled["Flow ID"] = df_live["Flow ID"]
    df_live_scaled["Timestamp"] = df_live.get("Timestamp", pd.Timestamp.now())

    return df_live.to_dict(), df_live_scaled

def classify_sequence(seq, hmm_models):
    log_likelihoods = {}

    for class_label, model in hmm_models.items():
        try:
          log_likelihood = model.score(seq)  # Compute log probability
          log_likelihoods[class_label] = log_likelihood
        except:
          log_likelihoods[class_label] = float('-inf')

    # Return class with the highest likelihood
    return max(log_likelihoods, key=log_likelihoods.get)

# ---- 1. Collector Thread ----
def packet_collector():
    while not stop_event.is_set():
        packets = sniff(timeout=1, store=0)
        flows = group_packets_to_flows(packets)  # Define this
        for flow_id, pkts in flows.items():
            features = extract_features(flow_id, pkts)
            raw_feature_queue.put([features])

# ---- 2. Feature Processor Thread ----
def feature_processor():
    while not stop_event.is_set():
        try:
            raw_features = raw_feature_queue.get(timeout=1)
            initial_features, processed = process_features(raw_features)  # Includes NaN fill & scaling
            processed_feature_queue.put((initial_features, processed))
        except queue.Empty:
            continue

# ---- 3. Prediction Thread ----
def predictor():
    while not stop_event.is_set():
        try:
            batch = []
            initial_features_batch = []

            while len(batch) < 10:
                try:
                    initial_feature, feature = processed_feature_queue.get(timeout=0.5)
                    flat_feature = {k: list(v.values())[0] if isinstance(v, dict) else v for k, v in initial_feature.items()}
                    initial_features_batch.append(flat_feature)
                    batch.append(feature)
                except queue.Empty:
                    break

            if not batch:
                continue

            # Combine batch into a DataFrame
            df_live_scaled = pd.concat(batch, ignore_index=True)

            # Group by Flow ID to prepare sequences
            live_sequences = []
            flow_ids = []

            for flow_id, group in df_live_scaled.groupby("Flow ID"):
                X_seq = group.drop(columns=["Flow ID", "Timestamp"]).values
                live_sequences.append(X_seq)
                flow_ids.append(flow_id)

            predictions = [int(classify_sequence(seq, hmm_models)) for seq in live_sequences]
            readable_preds = [label_mapping_inv[pred] for pred in predictions]

            enriched_flows = []
            for fid, label in zip(flow_ids, readable_preds):
                # Find the corresponding feature by Flow ID
                for flow in initial_features_batch:
                    if flow["Flow ID"] == fid:
                        flow["Prediction"] = label
                        enriched_flows.append(flow)
                        # print(f"[{fid}] => {label}\n")
                        break
                
                for flow in enriched_flows:
                    send_to_database(flow)

        except queue.Empty:
            continue

# ---- Startup ----
collector_thread = threading.Thread(target=packet_collector)
processor_thread = threading.Thread(target=feature_processor)
predictor_thread = threading.Thread(target=predictor)

collector_thread.start()
processor_thread.start()
predictor_thread.start()

# ---- Graceful Shutdown (Ctrl+C) ----
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Shutting down...")
    stop_event.set()
    collector_thread.join()
    processor_thread.join()
    predictor_thread.join()