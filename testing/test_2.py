import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, Raw
import requests
import json

# List to hold packet features
packet_features = []

def process_packet(packet):
    if IP in packet:
        feature_entry = {
            "srcip": packet[IP].src,
            "sport": packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None,
            "dstip": packet[IP].dst,
            "dsport": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None,
            "protocol_m": packet[IP].proto,
            "sttl": packet[IP].ttl,             # Source TTL
            "total_len": packet[IP].len,         # Total Length
            "payload": bytes(packet[Raw]).hex() if Raw in packet else None,  # Payload (Hex format for readability),
            "Timestamp" : packet.time
        }
        
        packet_features.append(feature_entry)

# Sniff packets for 5 seconds
sniff(prn=process_packet, timeout=10, store=False, iface="Wi-Fi")

'''# Convert to DataFrame
df = pd.DataFrame(packet_features)
print(df)'''

url = "http://localhost:5000/predict/payload"

# Payload
payload = {"data": packet_features}

# Headers
headers = {'Content-Type': 'application/json'}

# Send POST request
response = requests.post(url, json=payload, headers=headers)

if response.status_code == 200:
    print("Prediction Response:")
    print(json.dumps(response.json(), indent=4))
else:
    print(f"Error: {response.status_code}")
    print(response.text)