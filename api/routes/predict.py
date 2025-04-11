from flask import Blueprint, request, jsonify
from db.schemas import Netflow, Payload
from db.connection import SessionLocal
from sqlalchemy.orm import Session

predict_bp = Blueprint('predict_bp', __name__)

# In-memory latest records
latest_netflows = {}
latest_payloads = {}

# Constants
ANOMALY_PREDICTION = "Anomaly"
POTENTIAL_ANOMALY = "Ping Sweep (Potential Anomaly)"

# --------------------- DB Insert Helpers ---------------------

def insert_netflow(db: Session, flow_data: dict):
    netflow = Netflow(
        flow_id=flow_data["Flow ID"],
        flow_duration=flow_data["Flow Duration"],
        total_fwd_packet=flow_data["Total Fwd Packet"],
        total_bwd_packets=flow_data["Total Bwd packets"],
        fwd_packet_length_mean=flow_data["Fwd Packet Length Mean"],
        fwd_packet_length_std=flow_data["Fwd Packet Length Std"],
        bwd_packet_length_mean=flow_data["Bwd Packet Length Mean"],
        bwd_packet_length_std=flow_data["Bwd Packet Length Std"],
        flow_bytes_per_s=flow_data["Flow Bytes/s"],
        flow_packets_per_s=flow_data["Flow Packets/s"],
        flow_iat_mean=flow_data["Flow IAT Mean"],
        flow_iat_std=flow_data["Flow IAT Std"],
        fwd_iat_mean=flow_data["Fwd IAT Mean"],
        fwd_iat_std=flow_data["Fwd IAT Std"],
        bwd_iat_total=flow_data["Bwd IAT Total"],
        bwd_iat_mean=flow_data["Bwd IAT Mean"],
        bwd_iat_std=flow_data["Bwd IAT Std"],
        fwd_packets_per_s=flow_data["Fwd Packets/s"],
        bwd_packets_per_s=flow_data["Bwd Packets/s"],
        packet_length_mean=flow_data["Packet Length Mean"],
        packet_length_std=flow_data["Packet Length Std"],
        fin_flag_count=flow_data["FIN Flag Count"],
        syn_flag_count=flow_data["SYN Flag Count"],
        rst_flag_count=flow_data["RST Flag Count"],
        psh_flag_count=flow_data["PSH Flag Count"],
        ack_flag_count=flow_data["ACK Flag Count"],
        urg_flag_count=flow_data["URG Flag Count"],
        cwr_flag_count=flow_data["CWR Flag Count"],
        ece_flag_count=flow_data["ECE Flag Count"],
        down_up_ratio=flow_data["Down/Up Ratio"],
        subflow_fwd_packets=flow_data["Subflow Fwd Packets"],
        subflow_fwd_bytes=flow_data["Subflow Fwd Bytes"],
        subflow_bwd_packets=flow_data["Subflow Bwd Packets"],
        subflow_bwd_bytes=flow_data["Subflow Bwd Bytes"],
        active_mean=flow_data["Active Mean"],
        active_std=flow_data["Active Std"],
        idle_mean=flow_data["Idle Mean"],
        idle_std=flow_data["Idle Std"],
        prediction=flow_data["Prediction"]
    )
    db.add(netflow)
    db.commit()
    db.refresh(netflow)
    return netflow

def insert_payload(db: Session, payload_data: dict):
    payload = Payload(
        flow_id=payload_data["Flow ID"],
        stime=payload_data["Stime"],
        timestamp=payload_data["Timestamp"],
        prediction=payload_data["Prediction"]
    )
    db.add(payload)
    db.commit()
    db.refresh(payload)
    return payload

# --------------------- Routes ---------------------

@predict_bp.route('/netflow', methods=["POST", "GET"])
def save_netflow():
    if request.method == "POST":
        flow_data = request.get_json()
        flow_id = flow_data.get("Flow ID")

        if not flow_id:
            return jsonify({"error": "Missing Flow ID"}), 400

        # Save in memory
        latest_netflows[flow_id] = flow_data
        print(f"[Netflow] Received: {flow_id}")

        # Save to DB only for Anomalies
        if flow_data.get("Prediction") in [ANOMALY_PREDICTION, POTENTIAL_ANOMALY]:
            try:
                with SessionLocal() as session:
                    insert_netflow(session, flow_data)
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        return jsonify({"status": "Netflow received", "flow_id": flow_id}), 200

    elif request.method == "GET":
        return jsonify(latest_netflows), 200

@predict_bp.route('/netflow/<flow_id>', methods=["GET"])
def get_specific_netflow(flow_id):
    flow_data = latest_netflows.get(flow_id)
    if flow_data:
        return jsonify(flow_data), 200
    else:
        return jsonify({"error": f"Flow ID '{flow_id}' not found"}), 404

@predict_bp.route('/payload', methods=["POST", "GET"])
def save_payload():
    if request.method == "POST":
        payload_data = request.get_json()
        flow_id = payload_data.get("Flow ID")

        if not flow_id:
            return jsonify({"error": "Missing Flow ID"}), 400

        # Save in memory
        latest_payloads[flow_id] = payload_data

        # Save to DB if not Benign
        if payload_data.get("Prediction") != "Benign":
            try:
                with SessionLocal() as session:
                    insert_payload(session, payload_data)
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        return jsonify({"status": "Payload received", "flow_id": flow_id}), 200

    elif request.method == "GET":
        return jsonify(latest_payloads), 200

@predict_bp.route('/payload/<flow_id>', methods=["GET"])
def get_specific_payload(flow_id):
    payload_data = latest_payloads.get(flow_id)
    if payload_data:
        return jsonify(payload_data), 200
    else:
        return jsonify({"error": f"Payload for Flow ID '{flow_id}' not found"}), 404

# --------------------- Routes ---------------------

@predict_bp.route('/netflow/all', methods=["GET"])
def get_all_netflows():
    try:
        with SessionLocal() as session:
            netflows = session.query(Netflow).all()
            netflow_list = [netflow.to_dict() for netflow in netflows]
        return jsonify(netflow_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@predict_bp.route('/payload/all', methods=["GET"])
def get_all_payloads():
    try:
        with SessionLocal() as session:
            # Fetch all records from the Payload table
            payloads = session.query(Payload).all()
            # Convert them to dictionaries (optional: use schema serialization)
            payload_list = [payload.to_dict() for payload in payloads]
        return jsonify(payload_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
