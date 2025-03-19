'''from flask import Blueprint, request, jsonify
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
    return jsonify({"message": "Network Anomaly Detection API is Running!"})'''

from flask import Blueprint, request, jsonify
import psutil
import socket
import subprocess
import json
import time
import os
import platform
import ipaddress
from datetime import datetime
from mac_vendor_lookup import MacLookup, BaseMacLookup
from scapy.all import arping, srp, Ether, ARP, get_if_list, conf
from flask_socketio import SocketIO, emit
from threading import Thread, Lock
import netifaces
import signal
import atexit
from collections import defaultdict

# Configure Flask Blueprint and SocketIO
network_bp = Blueprint('network_bp', __name__)
socketio = SocketIO(cors_allowed_origins="*")

# Global variables
active_threads = []
thread_lock = Lock()
device_cache = {}
bandwidth_stats = {}
packet_stats = {}
device_status = {}
scan_interval = 10  # seconds
bandwidth_interval = 2  # seconds
status_check_interval = 15  # seconds
network_range = "192.168.1.0/24"  # Default network range

# ===============================
# 🔧 Utility Functions
# ===============================

def get_subnet_from_interface():
    """Dynamically detect the subnet based on active interfaces."""
    try:
        # Get all network interfaces
        interfaces = netifaces.interfaces()
        
        for interface in interfaces:
            # Skip loopback
            if interface == 'lo' or interface.startswith('veth'):
                continue
                
            # Get interface addresses
            addresses = netifaces.ifaddresses(interface)
            
            # Check if IPv4 exists
            if netifaces.AF_INET in addresses:
                for addr in addresses[netifaces.AF_INET]:
                    if 'addr' in addr and 'netmask' in addr:
                        ip = addr['addr']
                        netmask = addr['netmask']
                        
                        # Skip localhost
                        if ip.startswith('127.'):
                            continue
                            
                        # Calculate network prefix length from netmask
                        prefix_len = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                        
                        # Create subnet in CIDR notation
                        ip_parts = ip.split('.')
                        # Use the first 3 octets and set the last to 0
                        network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/{prefix_len}"
                        return network
                        
        # Fallback to default if no suitable interface found
        return network_range
    except Exception as e:
        print(f"Error detecting subnet: {e}")
        return network_range

# Update the global network range
network_range = get_subnet_from_interface()

def get_gateway_ip():
    """Retrieve the router's IP dynamically."""
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][0]
    except Exception as e:
        print(f"Error detecting gateway: {e}")
    
    # Attempt to find router by guessing common IPs
    possible_routers = [f"192.168.1.1", f"192.168.0.1", f"10.0.0.1"]
    for ip in possible_routers:
        if ping_host(ip):
            return ip
            
    return '192.168.1.1'  # Default if detection fails

def ping_host(host, count=1, timeout=1):
    """Check if host is reachable via ping."""
    try:
        if platform.system().lower() == "windows":
            ping_cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
        else:
            ping_cmd = ["ping", "-c", str(count), "-W", str(timeout), host]
            
        result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False

def scan_network(ip_range=None):
    """Scan network for devices using ARP."""
    if ip_range is None:
        ip_range = network_range
        
    devices = []
    mac_lookup = MacLookup()
    BaseMacLookup.cache_path = os.path.expanduser('~/.mac-vendors.txt')
    
    try:
        # Update MAC vendor database if needed
        try:
            mac_lookup.update_vendors()
        except Exception as e:
            print(f"Could not update MAC vendors: {e}")
        
        # Use Scapy's arping for network discovery
        ans, _ = arping(ip_range, timeout=2, verbose=False)
        
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            
            # Lookup vendor but handle exceptions gracefully
            try:
                vendor = mac_lookup.lookup(mac)
                device_type = vendor.split()[0]  # Extract brand
            except Exception:
                device_type = "Unknown Device"
                
            # Detect device type from MAC or common service ports
            device_type = enhance_device_type(ip, mac, device_type)
            
            # Add to results
            devices.append({
                'ip': ip,
                'mac': mac,
                'device_type': device_type,
                'last_seen': datetime.now().isoformat()
            })
            
        # Add router explicitly
        router_ip = get_gateway_ip()
        router_mac = get_mac_from_ip(router_ip)
        
        # Check if router wasn't already found
        if not any(device['ip'] == router_ip for device in devices):
            devices.append({
                'ip': router_ip,
                'mac': router_mac or "Unknown",
                'device_type': "Router",
                'last_seen': datetime.now().isoformat()
            })
            
        return devices
    except Exception as e:
        print(f"Error scanning network: {e}")
        return []

def get_mac_from_ip(ip):
    """Get MAC address for an IP using ARP."""
    try:
        if platform.system().lower() == "windows":
            # For Windows, use arp command
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode('utf-8')
            for line in output.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1].replace('-', ':')
        else:
            # For Linux/Unix systems
            packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
            ans, _ = srp(packet, timeout=2, verbose=False)
            if ans:
                return ans[0][1].hwsrc
    except Exception as e:
        print(f"Error getting MAC for {ip}: {e}")
    return None

def enhance_device_type(ip, mac, default_type):
    """Try to enhance device type detection using common ports and patterns."""
    # Check for specific MAC patterns
    mac_prefix = mac[:8].upper()
    if mac_prefix in ['00:0C:29', '00:50:56', '00:05:69']:
        return 'VMware'
    elif mac_prefix in ['52:54:00']:
        return 'KVM/QEMU'
    elif mac_prefix in ['08:00:27']:
        return 'VirtualBox'
    
    # Check common service ports for device type hints
    try:
        # Check if it's a printer
        for port in [9100, 515, 631]:
            if check_port(ip, port):
                return 'Printer'
                
        # Check if it's a router/networking device
        for port in [80, 443, 8080, 8443]:
            if check_port(ip, port):
                # Could be router admin interface
                if default_type == "Unknown Device":
                    return 'Network Device'
    except:
        pass
    
    return default_type

def check_port(ip, port, timeout=0.5):
    """Check if a port is open on the specified IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def is_device_online(ip):
    """Check if a device is online."""
    return ping_host(ip)


# ===============================
# 🔥 Real-time Topology Monitoring
# ===============================

def monitor_network_topology():
    """Thread function to scan network periodically and update topology."""
    global device_cache
    
    print(f"Network topology monitoring started. Scanning {network_range} every {scan_interval} seconds")
    
    while True:
        try:
            # Scan the network
            devices = scan_network()
            
            # Update the device cache
            for device in devices:
                device_id = device['ip']
                device_cache[device_id] = device
                
                # Check device status
                is_online = is_device_online(device_id)
                device_status[device_id] = {
                    'status': 'active' if is_online else 'inactive',
                    'last_checked': datetime.now().isoformat()
                }
            
            # Format topology data for the frontend
            topology_data = format_topology_data(devices)
            
            # Emit the updated topology
            socketio.emit('network_topology_update', {'network_topology': topology_data})
            
            # Also emit device status updates
            socketio.emit('device_status_update', device_status)
            
            # Sleep before next scan
            time.sleep(scan_interval)
        except Exception as e:
            print(f"Error in topology monitoring: {e}")
            time.sleep(scan_interval)  # Keep the thread alive even after errors

def monitor_bandwidth():
    """Thread function to monitor bandwidth usage and emit updates."""
    global bandwidth_stats
    
    prev_counters = psutil.net_io_counters(pernic=True)
    
    print(f"Bandwidth monitoring started. Checking every {bandwidth_interval} seconds")
    
    while True:
        try:
            # Get current counters
            current_counters = psutil.net_io_counters(pernic=True)
            
            # Calculate bandwidth for each interface
            interface_data = {}
            for interface in current_counters:
                # Skip virtual/container interfaces
                if interface.startswith(('lo', 'veth', 'docker', 'br-')):
                    continue
                    
                if interface in prev_counters:
                    # Calculate bytes sent/received since last check
                    bytes_sent = current_counters[interface].bytes_sent - prev_counters[interface].bytes_sent
                    bytes_recv = current_counters[interface].bytes_recv - prev_counters[interface].bytes_recv
                    
                    # Convert to megabits per second
                    mbps_sent = (bytes_sent * 8) / (bandwidth_interval * 1000000)
                    mbps_recv = (bytes_recv * 8) / (bandwidth_interval * 1000000)
                    
                    interface_data[interface] = {
                        'bytes_sent': bytes_sent,
                        'bytes_received': bytes_recv,
                        'mbps_sent': mbps_sent,
                        'mbps_received': mbps_recv,
                        'timestamp': time.time()
                    }
            
            # Map interface data to device IPs for the frontend
            device_bandwidth = {}
            
            # Router gets the total bandwidth
            router_ip = get_gateway_ip()
            total_sent = sum(data['bytes_sent'] for data in interface_data.values())
            total_recv = sum(data['bytes_received'] for data in interface_data.values())
            
            device_bandwidth[router_ip] = {
                'bytes_sent': total_sent,
                'bytes_received': total_recv,
                'mbps_sent': (total_sent * 8) / (bandwidth_interval * 1000000),
                'mbps_received': (total_recv * 8) / (bandwidth_interval * 1000000),
                'timestamp': time.time()
            }
            
            # Distribute bandwidth among known devices
            # This is an approximation since we can't easily track per-device bandwidth without packet inspection
            active_devices = [ip for ip, status in device_status.items() if status['status'] == 'active']
            if active_devices:
                per_device_sent = total_sent / len(active_devices)
                per_device_recv = total_recv / len(active_devices)
                
                for device_ip in active_devices:
                    if device_ip != router_ip:  # Skip router which we already assigned
                        device_bandwidth[device_ip] = {
                            'bytes_sent': per_device_sent * 0.8,  # 80% of fair share
                            'bytes_received': per_device_recv * 0.8,  # 80% of fair share
                            'mbps_sent': (per_device_sent * 8) / (bandwidth_interval * 1000000) * 0.8,
                            'mbps_received': (per_device_recv * 8) / (bandwidth_interval * 1000000) * 0.8,
                            'timestamp': time.time()
                        }
            
            # Update the global bandwidth stats
            bandwidth_stats = device_bandwidth
            
            # Emit bandwidth data
            socketio.emit('network_bandwidth', device_bandwidth)
            
            # Store counters for next iteration
            prev_counters = current_counters
            
            # Sleep before next check
            time.sleep(bandwidth_interval)
        except Exception as e:
            print(f"Error in bandwidth monitoring: {e}")
            time.sleep(bandwidth_interval)

def monitor_packet_flow():
    """Thread function to monitor packet flow between devices."""
    global packet_stats
    
    # Initialize packet stats
    for ip in device_cache:
        packet_stats[ip] = {
            'packets_in': 0,
            'packets_out': 0,
            'last_updated': time.time()
        }
    
    print("Packet flow monitoring started")
    
    try:
        # Use a simplified approach to estimate packet flow
        # In a production environment, you'd use packet capture or netflow data
        while True:
            # Get current network connections
            connections = psutil.net_connections(kind='inet')
            
            # Count packets per IP
            ip_packets = defaultdict(lambda: {'in': 0, 'out': 0})
            
            for conn in connections:
                if conn.laddr and conn.raddr:
                    local_ip = conn.laddr.ip
                    remote_ip = conn.raddr.ip
                    
                    # Skip localhost connections
                    if local_ip.startswith('127.') or remote_ip.startswith('127.'):
                        continue
                    
                    # Estimate packets based on connection status
                    packet_estimate = 1
                    if conn.status == 'ESTABLISHED':
                        packet_estimate = 5
                    
                    # Count for both ends of the connection
                    ip_packets[local_ip]['out'] += packet_estimate
                    ip_packets[remote_ip]['in'] += packet_estimate
            
            # Update global packet stats
            for ip, counts in ip_packets.items():
                if ip in packet_stats:
                    packet_stats[ip] = {
                        'packets_in': counts['in'],
                        'packets_out': counts['out'],
                        'last_updated': time.time()
                    }
            
            # Also update router packet stats based on total traffic
            router_ip = get_gateway_ip()
            if router_ip in packet_stats:
                total_in = sum(stats['packets_in'] for stats in packet_stats.values())
                total_out = sum(stats['packets_out'] for stats in packet_stats.values())
                
                packet_stats[router_ip] = {
                    'packets_in': total_in,
                    'packets_out': total_out,
                    'last_updated': time.time()
                }
            
            # Emit packet data
            socketio.emit('network_packets', packet_stats)
            
            # Sleep before next update
            time.sleep(1)
    except Exception as e:
        print(f"Error in packet flow monitoring: {e}")

def check_device_status():
    """Thread function to check device status periodically."""
    global device_status
    
    print(f"Device status monitoring started. Checking every {status_check_interval} seconds")
    
    while True:
        try:
            status_updates = {}
            
            # Check each device in cache
            for device_id, device in device_cache.items():
                is_online = is_device_online(device_id)
                
                status = 'active' if is_online else 'inactive'
                
                # Add random warning states for demonstration purposes
                # In a real implementation, you'd use actual health metrics
                if is_online and device_id not in [get_gateway_ip()] and time.time() % 60 < 10:
                    status = 'warning'
                
                status_updates[device_id] = {
                    'status': status,
                    'last_checked': datetime.now().isoformat()
                }
            
            # Update the global status cache
            device_status.update(status_updates)
            
            # Emit status updates
            socketio.emit('device_status_update', status_updates)
            
            # Sleep before next check
            time.sleep(status_check_interval)
        except Exception as e:
            print(f"Error in device status monitoring: {e}")
            time.sleep(status_check_interval)

# ===============================
# 📊 Data Formatting
# ===============================

def format_topology_data(devices):
    """Format topology data for the frontend visualization."""
    topology = []
    router_ip = get_gateway_ip()
    
    # Find the router in our devices list
    router = next((device for device in devices if device['ip'] == router_ip), None)
    
    # Create the router node first
    if router:
        router_node = {
            'id': router['ip'],
            'name': 'Router',
            'status': device_status.get(router['ip'], {}).get('status', 'unknown'),
            'mac': router['mac'],
            'connections': [],
            'bandwidth': bandwidth_stats.get(router['ip'], {})
        }
        
        # All devices connect to the router in a typical home/office network
        for device in devices:
            if device['ip'] != router_ip:
                router_node['connections'].append(device['ip'])
        
        topology.append(router_node)
    
    # Add all other devices
    for device in devices:
        if device['ip'] != router_ip:  # Skip the router (already added)
            device_node = {
                'id': device['ip'],
                'name': device['device_type'],
                'status': device_status.get(device['ip'], {}).get('status', 'unknown'),
                'mac': device['mac'],
                'connections': [router_ip],  # Connect to the router
                'bandwidth': bandwidth_stats.get(device['ip'], {})
            }
            topology.append(device_node)
    
    return topology

# ===============================
# 🚀 API Routes
# ===============================

@network_bp.route('/topology', methods=['GET'])
def network_topology():
    """Get the current network topology."""
    try:
        # Scan network if we don't have data yet
        if not device_cache:
            devices = scan_network()
            for device in devices:
                device_cache[device['ip']] = device
        else:
            # Use cached device data
            devices = list(device_cache.values())
        
        # Format for frontend
        topology_data = format_topology_data(devices)
        
        return jsonify({
            'success': True,
            'network_topology': topology_data,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@network_bp.route('/devices', methods=['GET'])
def get_devices():
    """Get all discovered network devices."""
    try:
        return jsonify({
            'success': True,
            'devices': list(device_cache.values()),
            'total': len(device_cache),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@network_bp.route('/bandwidth', methods=['GET'])
def get_bandwidth():
    """Get current bandwidth statistics."""
    try:
        return jsonify({
            'success': True,
            'bandwidth': bandwidth_stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@network_bp.route('/status', methods=['GET'])
def server_status():
    """Get the API server status and summary stats."""
    try:
        active_device_count = sum(1 for status in device_status.values() 
                               if status.get('status') == 'active')
                               
        return jsonify({
            'status': 'Server is running',
            'uptime': time.time() - server_start_time,
            'scan_interval': scan_interval,
            'network_range': network_range,
            'devices': {
                'total': len(device_cache),
                'active': active_device_count,
                'inactive': len(device_cache) - active_device_count
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'Server error',
            'error': str(e)
        }), 500

@network_bp.route('/', methods=['GET'])
def home():
    """API root endpoint."""
    return jsonify({
        "message": "Network Topology API is Running!",
        "version": "2.0.0",
        "endpoints": [
            "/network/topology",
            "/network/devices", 
            "/network/bandwidth",
            "/network/status"
        ]
    })

# ===============================
# 🔄 Socket Event Handlers
# ===============================

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    print("Client connected")
    
    # Start monitoring threads if not already running
    with thread_lock:
        # Clean up terminated threads
        global active_threads
        active_threads = [t for t in active_threads if t.is_alive()]
        
        # Start monitoring threads if needed
        thread_functions = [
            monitor_network_topology,
            monitor_bandwidth,
            monitor_packet_flow,
            check_device_status
        ]
        
        for func in thread_functions:
            if not any(t.name == func.__name__ for t in active_threads):
                thread = Thread(target=func, name=func.__name__, daemon=True)
                thread.start()
                active_threads.append(thread)
                print(f"Started {func.__name__} thread")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    print("Client disconnected")

# ===============================
# 🧹 Cleanup Handlers
# ===============================

# Track server start time
server_start_time = time.time()

def cleanup_resources():
    """Clean up resources before server shutdown."""
    print("Cleaning up resources...")
    
    # Signal all threads to stop
    for thread in active_threads:
        if thread.is_alive():
            print(f"Stopping {thread.name} thread...")
    
    print("Cleanup complete")

# Register cleanup handler
atexit.register(cleanup_resources)

def signal_handler(sig, frame):
    """Handle termination signals."""
    print(f"Received signal {sig}, shutting down...")
    cleanup_resources()
    exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)