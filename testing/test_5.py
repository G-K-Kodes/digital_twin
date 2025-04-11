import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, Raw
import threading
import queue
from datetime import datetime
import requests

# Load Models
model_2 = joblib.load('C:/Users/gokul/digital_twin/models/network_anomaly_model_payload.pkl')
scaler_2 = joblib.load('C:/Users/gokul/digital_twin/models/scaler_payload.pkl')
label_mapping_2 = joblib.load('C:/Users/gokul/digital_twin/models/label_mapping_payload.pkl')

url = "http://localhost:5000/predict/payload"

def send_to_database(payload):
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, json=payload, headers=headers)
    print(response.text)

# Queues & Thread Control
raw_feature_queue = queue.Queue()
processed_feature_queue = queue.Queue()
stop_event = threading.Event()

def flow_id(packet):
    return f"{packet["srcip"][0]}-{packet["dstip"][0]}-{packet["sport"][0]}-{packet["dsport"][0]}-{packet["protocol_m"][0]}"

# ---- Feature Processing ----
def process_packet(packet_data):
    df = pd.DataFrame(packet_data)
    flow = df[["srcip","sport","dstip","dsport", "protocol_m"]]

    encoding_map = {}
    for col in df.select_dtypes(include=['object']).columns:
        df[col], unique_values = pd.factorize(df[col])
        encoding_map[col] = dict(enumerate(unique_values))

    # Replace inf/nan
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df = df.fillna(df.median(numeric_only=True))

    # Scale
    data_scaled = scaler_2.transform(df)
    return data_scaled, df.get("Timestamp", pd.Timestamp.now()), flow_id(flow.to_dict())

# ---- Packet Collector ----
def add_packets():
    while not stop_event.is_set():
        packets = sniff(timeout=1)
        for packet in packets:
            if IP in packet:
                feature_entry = {
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
                raw_feature_queue.put([feature_entry])

# ---- Packet Processor ----
def packets_processor():
    while not stop_event.is_set():
        try:
            raw_features = raw_feature_queue.get(timeout=1)
            processed_data, timestamp, flow_id = process_packet(raw_features)
            processed_feature_queue.put((processed_data, timestamp, flow_id))
        except queue.Empty:
            continue

# ---- Predictor ----
def predict_packets():
    while not stop_event.is_set():
        try:
            data_scaled, timestamp, flow_id = processed_feature_queue.get(timeout=1)
            ts_str = datetime.fromtimestamp(timestamp.iloc[0]).strftime("%Y-%m-%d %H:%M:%S")

            predictions = model_2.predict(data_scaled)
            readable_preds = [label_mapping_2.get(pred, "Unknown") for pred in predictions]

            for label in readable_preds:
                #print(f"[{flow_id}, {timestamp[0]} ,{ts_str}] => {label}")
                result = {
                    "Flow ID" : flow_id,
                    "Stime" : timestamp[0],
                    "Timestamp" : ts_str,
                    "Prediction" : label
                }
                send_to_database(result)

        except queue.Empty:
            continue

# ---- Thread Management ----
collector_thread = threading.Thread(target=add_packets)
processor_thread = threading.Thread(target=packets_processor)
predictor_thread = threading.Thread(target=predict_packets)

collector_thread.start()
processor_thread.start()
predictor_thread.start()

try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping threads...")
    stop_event.set()
    collector_thread.join()
    processor_thread.join()
    predictor_thread.join()