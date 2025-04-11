from scapy.all import sniff, IP, TCP
import threading, time, random, subprocess
from collections import defaultdict, deque
import queue

# Constants
BANDWIDTH = 1_000_000  # 1 Mbps
PACKET_LOSS_PROB = 0.1
ACK_SIZE = 64

class Packet:
    def __init__(self, src, size, time_sent, is_ack=False):
        self.src = src
        self.size = size
        self.time_sent = time_sent
        self.is_ack = is_ack

class SimStats:
    def __init__(self):
        self.signal_strengths = defaultdict(lambda: 1.0)  # MAC -> signal (updated later)
        self.transmitted = defaultdict(int)
        self.dropped = defaultdict(int)
        self.bandwidth_log = deque(maxlen=100)
        self.time_log = deque(maxlen=100)
        self.start_time = time.time()
        self.device_stats = defaultdict(list)

class WirelessRouter:
    def __init__(self, stats):
        self.stats = stats
        self.packet_queue = queue.Queue()
        self.running = True
        threading.Thread(target=self.process_packets, daemon=True).start()

    def receive_packet(self, packet):
        self.packet_queue.put(packet)

    def process_packets(self):
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            mac = packet.src
            signal = self.stats.signal_strengths[mac]
            effective_loss_prob = PACKET_LOSS_PROB + (0.2 if signal < 0.5 else 0)

            if random.random() < effective_loss_prob:
                self.stats.dropped[mac] += 1
                continue

            signal_delay = (1.0 - signal) * 0.01
            transmission_delay = (packet.size * 8) / BANDWIDTH + signal_delay
            time.sleep(transmission_delay)

            self.stats.transmitted[mac] += 1

            # Bandwidth log
            now = time.time() - self.stats.start_time
            self.stats.bandwidth_log.append((packet.size * 8) / transmission_delay)
            self.stats.time_log.append(now)

            if not packet.is_ack:
                rtt = time.time() - packet.time_sent
                self.stats.device_stats[mac].append(rtt)

                # Simulated ACK (not actually sent)
                ack = Packet(src=mac, size=ACK_SIZE, time_sent=time.time(), is_ack=True)
                self.receive_packet(ack)

# ---------- Signal Strength Updater ----------
def get_signal_strength(interface='wlan0'):
    try:
        result = subprocess.check_output(["iwconfig", interface]).decode()
        for line in result.split("\n"):
            if "Signal level" in line:
                parts = line.strip().split("Signal level=")
                if len(parts) > 1:
                    level = int(parts[1].split()[0])
                    return max(0.1, min(1.0, (level + 100) / 50))  # Normalize
    except:
        return 1.0

def update_signal_strength(stats, interface='wlan0'):
    while True:
        strength = get_signal_strength(interface)
        if stats.signal_strengths:
            print(f"[{interface}] Signal strength updated: {strength:.2f}")
        for mac in stats.signal_strengths:
            stats.signal_strengths[mac] = strength
        time.sleep(2)

# ---------- Packet Handling ----------
def packet_handler(pkt, interface_name):
    if IP in pkt and TCP in pkt:
        src_mac = pkt.src
        dst_ip = pkt[IP].dst
        size = len(pkt)
        now = time.time()
        stats.signal_strengths[src_mac]  # Ensure entry
        sim_packet = Packet(src=src_mac, size=size, time_sent=now)
        router.receive_packet(sim_packet)
        print(f"[{interface_name}] Packet from {src_mac} to {dst_ip} | Size: {size}")


def sniff_interface(interface_name):
    sniff(prn=lambda pkt: packet_handler(pkt, interface_name),
          iface=interface_name, store=0)

# ---------- Setup ----------
stats = SimStats()
router = WirelessRouter(stats)

# Start sniffers
threading.Thread(target=sniff_interface, args=("Wi-Fi",), daemon=True).start()
#threading.Thread(target=sniff_interface, args=("eth0",), daemon=True).start()
#wlan0 and eth0 if Linux
# Start signal updater (for wlan0 only)
threading.Thread(target=update_signal_strength, args=(stats, "Wi-Fi"), daemon=True).start()

print("🚀 Real-time packet handler running... Press Ctrl+C to stop.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("🛑 Stopped.")
    router.running = False
