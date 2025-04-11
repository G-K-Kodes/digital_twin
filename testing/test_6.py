import simpy
import random
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import threading
import time
from collections import defaultdict, deque

# Constants
BANDWIDTH = 1_000_000  # 1 Mbps
SIM_DURATION = 20
PACKET_SIZE_RANGE = (500, 1500)
INTER_ARRIVAL_TIME = (0.5, 2)
NUM_DEVICES = 3
PACKET_LOSS_PROB = 0.1
ACK_SIZE = 64
ani = None

class Packet:
    def __init__(self, src, size, time_sent, is_ack=False):
        self.src = src
        self.size = size
        self.time_sent = time_sent
        self.is_ack = is_ack

class SimStats:
    def __init__(self):
        self.signal_strengths = {i: random.uniform(0.4, 1.0) for i in range(1, NUM_DEVICES+1)}
        self.transmitted = defaultdict(int)
        self.dropped = defaultdict(int)
        self.bandwidth_log = deque(maxlen=100)
        self.time_log = deque(maxlen=100)
        self.start_time = time.time()

class WirelessRouter:
    def __init__(self, env, bandwidth, stats):
        self.env = env
        self.bandwidth = bandwidth
        self.store = simpy.Store(env)
        self.stats = stats
        self.device_stats = defaultdict(list)
        self.action = env.process(self.run())

    def run(self):
        while True:
            packet = yield self.store.get()
            signal = self.stats.signal_strengths[packet.src]
            effective_loss_prob = PACKET_LOSS_PROB + (0.2 if signal < 0.5 else 0)

            if random.random() < effective_loss_prob:
                self.stats.dropped[packet.src] += 1
                continue

            signal_delay = (1.0 - signal) * 0.01
            transmission_delay = (packet.size * 8) / self.bandwidth + signal_delay

            yield self.env.timeout(transmission_delay)
            self.stats.transmitted[packet.src] += 1

            # Track bandwidth over time
            now = time.time() - self.stats.start_time
            self.stats.bandwidth_log.append((packet.size * 8) / transmission_delay)
            self.stats.time_log.append(now)

            if not packet.is_ack:
                rtt = self.env.now - packet.time_sent
                self.device_stats[packet.src].append(rtt)

                # Send ACK
                ack = Packet(src=packet.src, size=ACK_SIZE, time_sent=self.env.now, is_ack=True)
                yield self.env.timeout((ACK_SIZE * 8) / self.bandwidth)

    def receive_packet(self, packet):
        return self.store.put(packet)

def device(env, device_id, router):
    while True:
        yield env.timeout(random.uniform(*INTER_ARRIVAL_TIME))
        packet_size = random.randint(*PACKET_SIZE_RANGE)
        packet = Packet(src=device_id, size=packet_size, time_sent=env.now)
        yield router.receive_packet(packet)

def update_signal_strengths(stats, interval=1.0):
    while True:
        time.sleep(interval)
        for device_id in stats.signal_strengths:
            delta = random.uniform(-0.05, 0.05)
            new_strength = stats.signal_strengths[device_id] + delta
            stats.signal_strengths[device_id] = max(0.0, min(1.0, new_strength))

# ---------------------- Visualization Setup ----------------------

def animate(i, stats, ax1, ax2, ax3):

    ax1.clear()
    ax2.clear()
    ax3.clear()

    devices = range(1, NUM_DEVICES+1)

    # Bar plot: Signal Strength
    strengths = [stats.signal_strengths[d] for d in devices]
    ax1.bar([f"Dev {d}" for d in devices], strengths, color='skyblue')
    ax1.set_ylim(0, 1.2)
    ax1.set_title("Signal Strength")

    # Bar plot: Packets Sent vs Dropped
    sent = [stats.transmitted[d] for d in devices]
    dropped = [stats.dropped[d] for d in devices]
    ax2.bar([f"Dev {d}" for d in devices], sent, label='Sent', color='green')
    ax2.bar([f"Dev {d}" for d in devices], dropped, bottom=sent, label='Dropped', color='red')
    ax2.set_title("Packets Sent/Dropped")
    ax2.legend()

    # Line plot: Bandwidth usage
    if stats.time_log and stats.bandwidth_log:
        ax3.plot(list(stats.time_log), list(stats.bandwidth_log), color='purple')
        ax3.set_title("Bandwidth Usage (bps)")
        ax3.set_ylim(0, BANDWIDTH * 1.2)


# ---------------------- Run Threads ----------------------

def run_simulation(stats):
    env = simpy.Environment()
    router = WirelessRouter(env, BANDWIDTH, stats)

    for i in range(1, NUM_DEVICES + 1):
        env.process(device(env, i, router))

    env.run(until=SIM_DURATION)

def start_visualization(stats):
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(8, 10))
    
    # Assign to global variable to prevent garbage collection
    global ani  
    ani = animation.FuncAnimation(
        fig, animate, fargs=(stats, ax1, ax2, ax3), interval=500, cache_frame_data=False
    )
    
    plt.tight_layout()
    plt.show()  # <-- THIS is essential


    # Keep updating while simulation thread is alive
    def keep_open():
        while sim_thread.is_alive():
            plt.pause(0.1)
        plt.close()

    keep_open()


# ---------------------- Entry Point ----------------------

if __name__ == "__main__":
    stats = SimStats()
    
    # Start sim in background
    sim_thread = threading.Thread(target=run_simulation, args=(stats,))
    sim_thread.daemon = True
    sim_thread.start()

    # Start signal strength updater
    signal_thread = threading.Thread(target=update_signal_strengths, args=(stats,))
    signal_thread.daemon = True
    signal_thread.start()

    # Start animation (on main thread)
    start_visualization(stats)

    # Optional join (only if needed)
    sim_thread.join()