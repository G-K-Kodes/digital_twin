import time
import json
import threading
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, ARP, Ether, get_if_list, conf, srp
import requests

API_URL = "http://127.0.0.1:5000/network"

def send_topology():
    tracker.mark_offline()
    data = tracker.to_json()
    try:
        response = requests.post(f"{API_URL}/topology", json=json.loads(data), timeout=3)
        print("Topology sent:", response.status_code)
    except Exception as e:
        print("Failed to send topology:", e)

def send_packet_stats():
    with tracker.lock:
        stats = {
            mac: {
                "MAC": mac,
                "Packets_Sent": d["Packets_Sent"],
                "Bytes_Sent" : d["Bytes_Sent"],
                "Packets_Received": d["Packets_Received"],
                "Bytes_Received" : d["Bytes_Received"]
            }
            for mac, d in tracker.devices.items()
        }
    try:
        response = requests.post(f"{API_URL}/packet_stats", json=stats, timeout=2)
        print("Packet stats sent:", response.status_code)
    except Exception as e:
        print("Failed to send packet stats:", e)


# ================= Utility Functions ================= #
def get_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if response.status_code == 200:
            return response.text
    except Exception:
        pass
    return "Unknown"

def format_timestamp(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

def time_since(ts):
    return f"{int(time.time() - ts)}s ago"

def detect_interface():
    interfaces = get_if_list()
    for iface in interfaces:
        if "eth" in iface or "wlan" in iface:
            return iface
    return conf.iface

def is_special_mac(mac):
    mac = mac.lower()
    return mac.startswith("ff:ff") or mac.startswith("33:33") or mac.startswith("01:00") or mac == "00:00:00:00:00:00"

# ================= Device Tracker ================= #
class DeviceTracker:
    def __init__(self):
        self.devices = {}
        self.lock = threading.Lock()
        self.interface = detect_interface()

    def update_device(self, mac, ip=None, direction=None, packet=None):
        if is_special_mac(mac):
            return  # Ignore special MACs

        now = time.time()
        with self.lock:
            if mac not in self.devices:
                self.devices[mac] = {
                    "MAC": mac,
                    "Vendor": get_vendor(mac),
                    "First_Seen": now,
                    "Last_Seen": now,
                    "Current_IP": ip,
                    "Previous_IPs": set([ip]) if ip else set(),
                    "Packets_Sent": 0,
                    "Bytes_Sent" : 0,
                    "Packets_Received": 0,
                    "Bytes_Received": 0,
                    "Online": True,
                    "Suspicious": False,
                }
            device = self.devices[mac]
            device["Last_Seen"] = now

            packet_len = len(packet) if packet else 0

            if ip:
                device["Current_IP"] = ip
                device["Previous_IPs"].add(ip)
            if direction == "sent":
                device["Packets_Sent"] += 1
                device["Bytes_Sent"] += packet_len #Number of bytes sent
            elif direction == "received":
                device["Packets_Received"] += 1
                device["Bytes_Received"] += packet_len #Number of bytes received

            # Improved suspicious logic: allow at least 60 seconds of traffic before flagging
            no_response_time = now - device["First_Seen"] > 60
            device["Suspicious"] = no_response_time and device["Packets_Sent"] > 0 and device["Packets_Received"] == 0

    def mark_offline(self, timeout=300):
        now = time.time()
        with self.lock:
            for device in self.devices.values():
                if now - device["Last_Seen"] > timeout:
                    device["Online"] = False

    def to_json(self):
        with self.lock:
            return json.dumps({
                mac: {
                    **data,
                    "First_Seen": format_timestamp(data["First_Seen"]),
                    "Last_Seen": format_timestamp(data["Last_Seen"]),
                    "Time_Since_Last_Seen": time_since(data["Last_Seen"]),
                    "Previous_IPs": list(data["Previous_IPs"])
                }
                for mac, data in self.devices.items()
            }, indent=4)

    def reset_counters(self):
        with self.lock:
            for device in self.devices.values():
                device["Packets_Sent"] = 0
                device["Bytes_Sent"] = 0
                device["Packets_Received"] = 0
                device["Bytes_Received"] = 0

# ================= Packet Sniffer ================= #
def packet_handler(pkt):
    if Ether in pkt:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
        ip_layer = pkt.getlayer("IP")
        src_ip = ip_layer.src if ip_layer else None
        dst_ip = ip_layer.dst if ip_layer else None
        
        tracker.update_device(src_mac, ip=src_ip, direction="sent", packet=pkt)
        tracker.update_device(dst_mac, ip=dst_ip, direction="received", packet=pkt)

# ================= ARP Scanner ================= #
def arp_scan():
    iface = tracker.interface
    ip_range = conf.route.route("0.0.0.0")[1] + "/24"
    arp_req = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_req
    ans, _ = srp(packet, timeout=2, verbose=0, iface=iface)

    for _, rcv in ans:
        tracker.update_device(rcv[Ether].src, ip=rcv[ARP].psrc)

    # After ARP scan completes, mark offline & send topology
    tracker.mark_offline()
    send_topology()

# ================= Reporting Endpoint (Placeholder) ================= #
def generate_report():
    tracker.mark_offline()
    report = tracker.to_json()
    print("\n======= Device Report =======")
    print(report)
    tracker.reset_counters()
    return report

# ================= Main Threading Logic ================= #
def start_sniffing():
    sniff(prn=packet_handler, store=False, iface=tracker.interface)

def periodic_scanner():
    while True:
        arp_scan()
        time.sleep(60)

def periodic_packet_stats_report():
    while True:
        send_packet_stats()
        time.sleep(5)  # every 30 seconds

if __name__ == "__main__":
    tracker = DeviceTracker()

    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=periodic_scanner, daemon=True).start()  # Now sends topology inside
    threading.Thread(target=periodic_packet_stats_report, daemon=True).start()

    print(f"Started tracking on interface: {tracker.interface}")
    while True:
        time.sleep(1)

