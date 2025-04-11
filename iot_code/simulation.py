import time
import threading
import subprocess
from scapy.all import sniff, Dot11

INTERFACE = 'Wi-Fi'

devices = {}
lock = threading.Lock()
total_packets = 0

def normalize_rssi(rssi_dbm):
    # Clamp and normalize between 0.0 (worst) and 1.0 (best)
    return max(0.0, min(1.0, (rssi_dbm + 100) / 70))

'''def get_signal_strengths():
    try:
        result = subprocess.run(['iw', 'dev', INTERFACE, 'station', 'dump'], capture_output=True, text=True, check=True)
        output = result.stdout
        signal_map = {}
        current_mac = None

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Station"):
                current_mac = line.split()[1].lower()
            elif "signal:" in line and current_mac:
                try:
                    rssi_dbm = int(line.split("signal:")[1].split()[0])
                    signal_map[current_mac] = normalize_rssi(rssi_dbm)
                except ValueError:
                    continue
        return signal_map
    except subprocess.CalledProcessError:
        return {}'''

def get_signal_strengths():
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'],
                                capture_output=True, text=True, check=True)
        output = result.stdout
        signal_strength = 0.0

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Signal"):
                # Format: Signal                   : 85%
                percent = int(line.split(":")[1].strip().replace("%", ""))
                signal_strength = percent / 100.0  # Normalize to 0.0 - 1.0
                break

        # Assign same signal to all devices (only one adapter)
        return {mac: signal_strength for mac in devices.keys()}

    except subprocess.CalledProcessError:
        return {}

def handle_packet(pkt):
    global total_packets
    if pkt.haslayer(Dot11) and pkt.type == 2:  # Data frame
        mac = pkt.addr2
        size = len(pkt)
        timestamp = time.time()

        with lock:
            total_packets += 1
            if mac not in devices:
                devices[mac] = {'total_bytes': 0, 'first_seen': timestamp, 'signal': 0.0}
            devices[mac]['total_bytes'] += size

        print(f"[Wi-Fi] Packet from {mac} to {pkt.addr1} | Size: {size}")

def print_stats():
    while True:
        time.sleep(5)
        with lock:
            now = time.time()
            signal_strengths = get_signal_strengths()

            print(f"\n📡 Devices: {len(devices)}")
            print(f"📦 Total packets: {total_packets}")

            for mac, data in devices.items():
                time_active = now - data['first_seen']
                bandwidth = data['total_bytes'] / time_active if time_active > 0 else 0
                signal = signal_strengths.get(mac, 0.0)
                data['signal'] = signal  # update cache

                print(f" - {mac} | Bandwidth: {bandwidth:.2f} B/s | Signal: {signal:.2f}")

def main():
    print(f"[*] Starting packet sniffing on {INTERFACE}...")
    threading.Thread(target=print_stats, daemon=True).start()
    sniff(iface=INTERFACE, prn=handle_packet, store=False)

if __name__ == "__main__":
    main()

