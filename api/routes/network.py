from flask import Blueprint, request, jsonify

network_bp = Blueprint("network", __name__)

# In-memory storage
latest_topology = {}
latest_packet_stats = {}

@network_bp.route("/topology", methods=["POST", "GET"])
def handle_topology():
    global latest_topology
    if request.method == "POST":
        latest_topology = request.get_json()
        return jsonify({"status": "Topology received"}), 200
    elif request.method == "GET":
        return jsonify(latest_topology), 200

@network_bp.route("/packet_stats", methods=["POST", "GET"])
def handle_packet_stats():
    global latest_packet_stats
    if request.method == "POST":
        latest_packet_stats = request.get_json()
        return jsonify({"status": "Packet stats received"}), 200
    elif request.method == "GET":
        return jsonify(latest_packet_stats), 200