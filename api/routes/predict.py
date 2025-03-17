from flask import Blueprint, request, jsonify
import pandas as pd
import numpy as np
import joblib
from scapy.all import TCP, UDP, IP


predict_bp = Blueprint('predict_bp', __name__)

# Load Models and Scalers
model = joblib.load('C:/Users/gokul/digital_twin/models/network_anomaly_model_netflow.pkl')
scaler = joblib.load('C:/Users/gokul/digital_twin/models/scaler_netflow.pkl')
label_mapping = joblib.load('C:/Users/gokul/digital_twin/models/label_mapping_netflow.pkl')

model_2 = joblib.load('C:/Users/gokul/digital_twin/models/network_anomaly_model_payload.pkl')
scaler_2 = joblib.load('C:/Users/gokul/digital_twin/models/scaler_payload.pkl')
label_mapping_2 = joblib.load('C:/Users/gokul/digital_twin/models/label_mapping_payload.pkl')

# Feature Sets for Each Model
MODEL_1_FEATURES = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol',
       'Timestamp', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
       'Total Length of Fwd Packet', 'Total Length of Bwd Packet',
       'Fwd Packet Length Max', 'Fwd Packet Length Min',
       'Fwd Packet Length Mean', 'Fwd Packet Length Std',
       'Bwd Packet Length Max', 'Bwd Packet Length Min',
       'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
       'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
       'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
       'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
       'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
       'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
       'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
       'Packet Length Min', 'Packet Length Max', 'Packet Length Mean',
       'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
       'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
       'URG Flag Count', 'CWR Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
       'Average Packet Size', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg',
       'Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg',
       'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg',
       'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
       'Subflow Bwd Bytes', 'FWD Init Win Bytes', 'Bwd Init Win Bytes',
       'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std',
       'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max',
       'Idle Min', 'Connection Type']

MODEL_2_FEATURES = [
    'sttl', 'total_len', 'payload'
]

COMMON_FEATURES = [
    'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp'
]

@predict_bp.route('/payload', methods=['POST'])
def predict_payload():
    try:
        data = request.json['data']
        df = pd.DataFrame(data)

        '''df.rename(columns={
            "Src IP" : "srcip",
            "Src Port" : "sport",
            "Dst IP" : "dstip",
            "Protocol" : "protocol_m",
            "Dst Port" : "dsport"
        }, inplace=True)'''

        encoding_map = {}
        for col in df.select_dtypes(include=['object']).columns:
            df[col], unique_values = pd.factorize(df[col])
            encoding_map[col] = dict(enumerate(unique_values))
        
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(df.max(), inplace=True)
        data_scaled = scaler_2.transform(df)

        predictions = model_2.predict(data_scaled)
        result = [label_mapping[pred] for pred in predictions]

        return jsonify({
            "payload_result" : result
        })

    except Exception as e:
        return jsonify({'error': str(e)})

@predict_bp.route('/netflow', methods=['POST'])
def predict_netflow():
    try:
        data = request.json['data']
        df = pd.DataFrame(data)

        encoding_map_1 = {}
        for col in df.select_dtypes(include=['object']).columns:
            df[col], unique_values = pd.factorize(df[col])
            encoding_map_1[col] = dict(enumerate(unique_values))
        
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(df.max(), inplace=True)
        data_scaled = scaler.transform(df)

        predictions = model.predict(data_scaled)
        result = [label_mapping[pred] for pred in predictions]

        return jsonify({
            "netflow_result" : result
        })

    except Exception as e:
        return jsonify({'error': str(e)})


@predict_bp.route('/', methods=['POST'])
def predict():
    try:
        data = request.json['data']
        return data
        '''df = pd.DataFrame(data)

        # Split data for each model
        df_model_1 = df[MODEL_1_FEATURES].copy().fillna(0)
        df_model_2 = df[COMMON_FEATURES + MODEL_2_FEATURES].copy().fillna('')

        df_model_2.rename(columns={
            "Src IP" : "srcip",
            "Src Port" : "sport",
            "Dst IP" : "dstip",
            "Protocol" : "protocol_m",
            "Dst Port" : "dsport"
        }, inplace=True)

        # Encoding categorical data for Model 1
        encoding_map_1 = {}
        for col in df_model_1.select_dtypes(include=['object']).columns:
            df_model_1[col], unique_values = pd.factorize(df_model_1[col])
            encoding_map_1[col] = dict(enumerate(unique_values))

        # Encoding categorical data for Model 2
        encoding_map_2 = {}
        for col in df_model_2.select_dtypes(include=['object']).columns:
            df_model_2[col], unique_values = pd.factorize(df_model_2[col])
            encoding_map_2[col] = dict(enumerate(unique_values))

        # Preprocess Data
        df_model_1.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_model_1.fillna(df_model_1.max(), inplace=True)
        data_scaled_1 = scaler.transform(df_model_1)

        df_model_2.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_model_2.fillna(df_model_2.max(), inplace=True)
        data_scaled_2 = scaler_2.transform(df_model_2)

        # Predictions
        predictions_1 = model.predict(data_scaled_1)
        result_1 = [label_mapping[pred] for pred in predictions_1]

        predictions_2 = model_2.predict(data_scaled_2)
        result_2 = [label_mapping_2[pred] for pred in predictions_2]

        return jsonify({
            'netflow_prediction': result_1,
            'payload_prediction': result_2
        })'''

    except Exception as e:
        return jsonify({'error': str(e)})

'''from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
import joblib

app = Flask(__name__)

# Load Models and Scalers
model = joblib.load('../models/network_anomaly_model_netflow.pkl')
scaler = joblib.load('../models/scaler_netflow.pkl')
label_mapping = joblib.load('../models/label_mapping_netflow.pkl')

model_2 = joblib.load('../models/network_anomaly_model_payload.pkl')
scaler_2 = joblib.load('../models/scaler_payload.pkl')
label_mapping_2 = joblib.load('../models/label_mapping_payload.pkl')

# Feature Sets for Each Model
MODEL_1_FEATURES = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol',
       'Timestamp', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
       'Total Length of Fwd Packet', 'Total Length of Bwd Packet',
       'Fwd Packet Length Max', 'Fwd Packet Length Min',
       'Fwd Packet Length Mean', 'Fwd Packet Length Std',
       'Bwd Packet Length Max', 'Bwd Packet Length Min',
       'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
       'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
       'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
       'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
       'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
       'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
       'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
       'Packet Length Min', 'Packet Length Max', 'Packet Length Mean',
       'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
       'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
       'URG Flag Count', 'CWR Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
       'Average Packet Size', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg',
       'Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg',
       'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg',
       'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
       'Subflow Bwd Bytes', 'FWD Init Win Bytes', 'Bwd Init Win Bytes',
       'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std',
       'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max',
       'Idle Min', 'Connection Type']

MODEL_2_FEATURES = ['sttl', 'total_len', 'payload', 'Timestamp']

COMMON_FEATURES = ['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol']

# Suspicious Flow Criteria (Trigger Conditions)
SUSPICIOUS_FLOW_CRITERIA = {
    'Packet Length Max': 800,      # Large packet sizes
    'SYN Flag Count': 2,           # Multiple SYN flags
    'Flow IAT Max': 5000,          # Unusually large IAT values
    'PSH Flag Count': 1            # PSH flag presence
}

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json['data']
        df = pd.DataFrame(data)

        # Split data for each model
        df_model_1 = df[MODEL_1_FEATURES].copy().fillna(0)
        df_model_2 = df[COMMON_FEATURES + MODEL_2_FEATURES].copy().fillna('')

        # Encoding categorical data
        for col in df_model_1.select_dtypes(include=['object']).columns:
            df_model_1[col], _ = pd.factorize(df_model_1[col])

        for col in df_model_2.select_dtypes(include=['object']).columns:
            df_model_2[col], _ = pd.factorize(df_model_2[col])

        # Preprocess Data
        df_model_1.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_model_1.fillna(df_model_1.max(), inplace=True)
        data_scaled_1 = scaler.transform(df_model_1)

        # Flow Analysis (Primary Check)
        predictions_1 = model.predict(data_scaled_1)
        result_1 = [label_mapping[pred] for pred in predictions_1]

        # Identify Suspicious Flows
        suspicious_indices = df_model_1[
            (df_model_1['Packet Length Max'] >= SUSPICIOUS_FLOW_CRITERIA['Packet Length Max']) |
            (df_model_1['SYN Flag Count'] >= SUSPICIOUS_FLOW_CRITERIA['SYN Flag Count']) |
            (df_model_1['Flow IAT Max'] >= SUSPICIOUS_FLOW_CRITERIA['Flow IAT Max']) |
            (df_model_1['PSH Flag Count'] >= SUSPICIOUS_FLOW_CRITERIA['PSH Flag Count'])
        ].index

        # Payload Analysis (Only for Suspicious Flows)
        if not suspicious_indices.empty:
            df_model_2 = df_model_2.loc[suspicious_indices]

            df_model_2.replace([np.inf, -np.inf], np.nan, inplace=True)
            df_model_2.fillna(df_model_2.max(), inplace=True)
            data_scaled_2 = scaler_2.transform(df_model_2)

            predictions_2 = model_2.predict(data_scaled_2)
            result_2 = [label_mapping_2[pred] for pred in predictions_2]
        else:
            result_2 = ['No Suspicious Payloads Detected'] * len(df_model_1)

        return jsonify({
            'netflow_prediction': result_1,
            'payload_prediction': result_2
        })

    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Network Anomaly Detection API with Switching Logic is Running!"})'''