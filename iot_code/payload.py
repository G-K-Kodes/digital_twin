import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, Raw
import threading
import queue
from datetime import datetime
import requests
import json
import signal
import sys

# === Load Models ===
model_2 = joblib.load('C:/Users/gokul/digital_twin/models/network_anomaly_model_payload.pkl')
scaler_2 = joblib.load('C:/Users/gokul/digital_twin/models/scaler_payload.pkl')
label_mapping_2 = joblib.load('C:/Users/gokul/digital_twin/models/label_mapping_payload.pkl')

url = "http://localhost:5000/predict/payload"

# === Queues & Thread Control ===
raw_feature_queue = queue.Queue()
processed_feature_queue = queue.Queue()
stop_event = threading.Event()

def send_to_database(payload):
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, json=payload, headers=headers)
        print(f"[INFO] Sent to DB: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to send data: {e}")

def generate_flow_id(entry):
    return f"{entry['srcip']}-{entry['dstip']}-{entry['sport']}-{entry['dsport']}-{entry['protocol_m']}"

# === Feature Processing ===
def process_packet(packet_data):
    df = pd.DataFrame(packet_data)

    # Save raw flow info for logging
    flow_id_str = generate_flow_id(packet_data[0])
    timestamp = df.get("Timestamp", pd.Series([datetime.now().timestamp()]))

    # Factorize categorical columns
    for col in df.select_dtypes(include=['object']).columns:
        df[col], _ = pd.factorize(df[col])

    # Clean data
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(df.median(numeric_only=True), inplace=True)

    # Scale
    data_scaled = scaler_2.transform(df)
    return data_scaled, timestamp.iloc[0], flow_id_str

# === Packet Collector ===
def add_packets():
    while not stop_event.is_set():
        packets = sniff(timeout=1)
        for packet in packets:
            if IP in packet:
                entry = {
                    "srcip": packet[IP].src,
                    "sport": packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None,
                    "dstip": packet[IP].dst,
                    "dsport": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None,
                    "protocol_m": packet[IP].proto,
                    "sttl": packet[IP].ttl,
                    "total_len": packet[IP].len,
                    "payload": bytes(packet[Raw]).hex() if Raw in packet else None,
                    "Timestamp": packet.time
                }
                raw_feature_queue.put([entry])

# === Feature Processor ===
def packets_processor():
    while not stop_event.is_set():
        try:
            raw_features = raw_feature_queue.get(timeout=1)
            processed_data, timestamp, flow_id = process_packet(raw_features)
            processed_feature_queue.put((processed_data, timestamp, flow_id))
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[ERROR] Processing packet: {e}")

# === Predictor ===
def predict_packets():
    while not stop_event.is_set():
        try:
            data_scaled, timestamp, flow_id = processed_feature_queue.get(timeout=1)
            ts_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

            predictions = model_2.predict(data_scaled)
            readable_preds = [label_mapping_2.get(pred, "Unknown") for pred in predictions]

            for label in readable_preds:
                result = {
                    "Flow ID": flow_id,
                    "Stime": timestamp,
                    "Timestamp": ts_str,
                    "Prediction": label
                }
                send_to_database(result)
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[ERROR] Predicting packet: {e}")

# === Thread Management ===
def start_threads():
    threads = [
        threading.Thread(target=add_packets),
        threading.Thread(target=packets_processor),
        threading.Thread(target=predict_packets),
    ]
    for t in threads:
        t.start()
    return threads

def stop_threads(threads):
    stop_event.set()
    for t in threads:
        t.join()
    print("[INFO] All threads stopped.")

def signal_handler(sig, frame):
    print("\n[INFO] Interrupted! Stopping...")
    stop_threads(running_threads)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# === Start the Program ===
if __name__ == "__main__":
    running_threads = start_threads()
    try:
        print("[INFO] Starting real-time payload classifier...")

    except KeyboardInterrupt:
        print("Shutting down...")
        stop_threads(running_threads)
        sys.exit(0)
    
