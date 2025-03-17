from flask import Blueprint, request, jsonify
import psutil
import socket
from mac_vendor_lookup import MacLookup
from scapy.all import arping
from flask_socketio import SocketIO, emit
from threading import Thread
import time

network_bp = Blueprint('network_bp', __name__)
socketio = SocketIO(cors_allowed_origins="*")

# ===============================
# 🔥 Real-time Topology Updates
# ===============================
def emit_live_topology():
    while True:
        time.sleep(5)  # Emit updates every 5 seconds
        devices = []
        ans, _ = arping("192.168.1.0/24")

        mac_lookup = MacLookup()
        for _, received in ans:
            device_type = mac_lookup.lookup(received.hwsrc).split()[0]  # Extract brand
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'device_type': device_type
            })

        socketio.emit('network_topology_update', {'network_topology': devices})

@socketio.on('connect')
def handle_connect():
    Thread(target=emit_live_topology).start()

# ===============================
# 📶 Bandwidth Monitoring (Live)
# ===============================
def monitor_bandwidth():
    prev_stats = psutil.net_io_counters()
    while True:
        time.sleep(2)
        current_stats = psutil.net_io_counters()

        data = {
            'bytes_sent': current_stats.bytes_sent - prev_stats.bytes_sent,
            'bytes_received': current_stats.bytes_recv - prev_stats.bytes_recv
        }

        prev_stats = current_stats
        socketio.emit('network_bandwidth', data)

@socketio.on('connect')
def handle_bandwidth_connect():
    Thread(target=monitor_bandwidth).start()

# ===============================
# 🌐 Network Topology Endpoint
# ===============================

def get_gateway_ip():
    """Retrieve the router's IP dynamically."""
    gateways = psutil.net_if_addrs()
    for interface, addresses in gateways.items():
        for addr in addresses:
            if addr.address.startswith("192.168.1.1"):
                return addr.address
    return '192.168.1.1'  # Default if detection fails

def format_topology_data(devices):
    services = []

    # Router/Gateway
    router_service = {
        'id': 'router',
        'name': 'Router',
        'status': 'active',
        'connections': [],
        'nodes': [{'status': 'running', 'count': 1}],
        'instancesActive': True,
        'instancesHealthy': {'total': 1, 'healthy': 1},
        'transitionalStatus': False,
        'reversed': False
    }

    # Build services from devices
    for device in devices:
        service = {
            'id': device['ip'],
            'name': device['device_type'] if device['device_type'] else 'Unknown Device',
            'status': 'active',
            'connections': ['router'],
            'nodes': [{'status': 'running', 'count': 1}],
            'instancesActive': True,
            'instancesHealthy': {'total': 1, 'healthy': 1},
            'transitionalStatus': False,
            'reversed': False
        }
        services.append(service)
        router_service['connections'].append(service['id'])

    services.append(router_service)

    return services

@network_bp.route('/topology', methods=['GET'])
def network_topology():
    devices = []
    router_ip = get_gateway_ip()

    ans, _ = arping("192.168.1.0/24")

    mac_lookup = MacLookup()
    for _, received in ans:
        try:
            device_type = mac_lookup.lookup(received.hwsrc).split()[0]
        except Exception:
            device_type = "Unknown Device"

        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'device_type': device_type
        })

    devices.append({
        'ip': router_ip,
        'mac': "Router_MAC",
        'device_type': "Router"
    })

    # Correct structure for frontend compatibility
    return jsonify({'network_topology': format_topology_data(devices)})

# ===============================
# ✅ Status Endpoint (For Health Check)
# ===============================
@network_bp.route('/status', methods=['GET'])
def server_status():
    return {"status": "Server is running"}

@network_bp.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Network Anomaly Detection API is Running!"})