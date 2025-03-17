import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
import numpy as np
import requests
import json

""" flows = {}  # Dictionary to store flow statistics

def process_packet(packet):
    global flows

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        timestamp = packet.time
        packet_length = len(packet)

        # Identify transport layer details
        src_port, dst_port = None, None
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Flow ID (Unidirectional)
        flow_id = f"{src_ip}-{dst_ip}-{protocol}"
        reverse_flow_id = f"{dst_ip}-{src_ip}-{protocol}"

        # Determine flow direction
        if flow_id in flows:
            is_forward = True
            flow = flows[flow_id]
        elif reverse_flow_id in flows:
            is_forward = False
            flow = flows[reverse_flow_id]
        else:
            # Initialize new flow
            flows[flow_id] = {
                'Flow ID': flow_id, 'Src IP': src_ip, 'Dst IP': dst_ip,
                'Protocol': protocol, 'Src Port': src_port, 'Dst Port': dst_port,
                'Timestamp': [timestamp], 'Flow Duration': 0, 
                'Total Fwd Packet': 0, 'Total Bwd Packet': 0, 
                'Total Length of Fwd Packet': 0, 'Total Length of Bwd Packet': 0,
                'Fwd Packet Lengths': [], 'Bwd Packet Lengths': [],
                'Fwd IAT': [], 'Bwd IAT': [],
                'TCP Flags': {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'CWR': 0, 'ECE': 0},
                'Init Win Bytes Fwd': None, 'Init Win Bytes Bwd': None
            }
            is_forward = True
            flow = flows[flow_id]

        # Update flow statistics
        if is_forward:
            flow['Total Fwd Packet'] += 1
            flow['Total Length of Fwd Packet'] += packet_length
            flow['Fwd Packet Lengths'].append(packet_length)
            if len(flow['Timestamp']) > 1:
                flow['Fwd IAT'].append(timestamp - flow['Timestamp'][-1])
            if TCP in packet and flow['Init Win Bytes Fwd'] is None:
                flow['Init Win Bytes Fwd'] = packet[TCP].window
        else:
            flow['Total Bwd Packet'] += 1
            flow['Total Length of Bwd Packet'] += packet_length
            flow['Bwd Packet Lengths'].append(packet_length)
            if len(flow['Timestamp']) > 1:
                flow['Bwd IAT'].append(timestamp - flow['Timestamp'][-1])
            if TCP in packet and flow['Init Win Bytes Bwd'] is None:
                flow['Init Win Bytes Bwd'] = packet[TCP].window

        # Store timestamp for IAT calculations
        flow['Timestamp'].append(timestamp)

        # TCP Flags
        if TCP in packet:
            flags = packet[TCP].flags
            flow['TCP Flags']['FIN'] += (flags & 0x01) >> 0
            flow['TCP Flags']['SYN'] += (flags & 0x02) >> 1
            flow['TCP Flags']['RST'] += (flags & 0x04) >> 2
            flow['TCP Flags']['PSH'] += (flags & 0x08) >> 3
            flow['TCP Flags']['ACK'] += (flags & 0x10) >> 4
            flow['TCP Flags']['URG'] += (flags & 0x20) >> 5
            flow['TCP Flags']['CWR'] += (flags & 0x40) >> 6
            flow['TCP Flags']['ECE'] += (flags & 0x80) >> 7

# Capture packets for 5 seconds
sniff(prn=process_packet, timeout=5, store=False, iface="Wi-Fi")  # Change iface if needed

# Convert to DataFrame
flow_data = []
for flow_id, flow in flows.items():
    flow_duration = flow['Timestamp'][-1] - flow['Timestamp'][0] if len(flow['Timestamp']) > 1 else 0
    fwd_iat = np.array(flow['Fwd IAT'])
    bwd_iat = np.array(flow['Bwd IAT'])

    flow_data.append({
        'Flow ID': flow_id, 'Src IP': flow['Src IP'], 'Dst IP': flow['Dst IP'],
        'Protocol': flow['Protocol'], 'Src Port': flow['Src Port'], 'Dst Port': flow['Dst Port'],
        'Flow Duration': flow_duration,
        'Total Fwd Packet': flow['Total Fwd Packet'], 'Total Bwd Packet': flow['Total Bwd Packet'],
        'Total Length of Fwd Packet': flow['Total Length of Fwd Packet'], 
        'Total Length of Bwd Packet': flow['Total Length of Bwd Packet'],
        'Fwd Packet Length Max': max(flow['Fwd Packet Lengths']) if flow['Fwd Packet Lengths'] else 0,
        'Fwd Packet Length Min': min(flow['Fwd Packet Lengths']) if flow['Fwd Packet Lengths'] else 0,
        'Fwd Packet Length Mean': np.mean(flow['Fwd Packet Lengths']) if flow['Fwd Packet Lengths'] else 0,
        'Bwd Packet Length Max': max(flow['Bwd Packet Lengths']) if flow['Bwd Packet Lengths'] else 0,
        'Bwd Packet Length Min': min(flow['Bwd Packet Lengths']) if flow['Bwd Packet Lengths'] else 0,
        'Flow Bytes/s': (flow['Total Length of Fwd Packet'] + flow['Total Length of Bwd Packet']) / flow_duration if flow_duration > 0 else 0,
        'Flow Packets/s': (flow['Total Fwd Packet'] + flow['Total Bwd Packet']) / flow_duration if flow_duration > 0 else 0,
        'Fwd IAT Mean': np.mean(fwd_iat) if fwd_iat.size else 0,
        'Fwd IAT Std': np.std(fwd_iat) if fwd_iat.size else 0,
        'Bwd IAT Mean': np.mean(bwd_iat) if bwd_iat.size else 0,
        'Bwd IAT Std': np.std(bwd_iat) if bwd_iat.size else 0,
        'SYN Flag Count': flow['TCP Flags']['SYN'],
        'ACK Flag Count': flow['TCP Flags']['ACK'],
        'FWD Init Win Bytes': flow['Init Win Bytes Fwd'] if flow['Init Win Bytes Fwd'] is not None else 0,
        'Bwd Init Win Bytes': flow['Init Win Bytes Bwd'] if flow['Init Win Bytes Bwd'] is not None else 0,
    }) """

packet_data = []

def process_packet(packet):
    if IP in packet:
        packet_info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': packet[IP].proto
        }
        if TCP in packet:
            packet_info.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': str(packet[TCP].flags)
            })
        elif UDP in packet:
            packet_info.update({
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
        packet_data.append(packet_info)

sniff(prn=process_packet, timeout=5, store=False, iface="Wi-Fi")

url = "http://localhost:5000/predict/"

# Payload
payload = {"data": packet_data}

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