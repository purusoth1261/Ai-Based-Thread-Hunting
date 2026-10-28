import os
import socket
import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from flask import Flask, render_template, request, jsonify,send_from_directory
from flask_socketio import SocketIO, emit
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP,Raw 
import socket as py_socket
from datetime import datetime  # ✅ Add this line at the beginning
import time
import json
import hashlib
import subprocess

app = Flask(__name__)
socketio = SocketIO(app)
# Define model and label encoder file paths
MODEL_DIR = "E:\\Major project final\\models\\"

MODEL1_PATH = os.path.join(MODEL_DIR, "modeladvlatest.pkl")
LABEL_ENCODER1_PATH = os.path.join(MODEL_DIR, "label_encoderlatest.pkl")

MODEL2_PATH = os.path.join(MODEL_DIR, "final_model2normal.pkl")
LABEL_ENCODER2_PATH = os.path.join(MODEL_DIR, "label_encoder21normal.pkl")

def check_and_train_models():
    """
    Check if models and their respective label encoders exist. 
    If missing, run the respective training scripts.
    """
    model1_exists = os.path.exists(MODEL1_PATH) and os.path.exists(LABEL_ENCODER1_PATH)
    model2_exists = os.path.exists(MODEL2_PATH) and os.path.exists(LABEL_ENCODER2_PATH)

    if not model1_exists:
        print("Model1 or label encoder missing. Training Model1...")
        subprocess.run(["python", "train_model_high1.py"])  # Train first model
    else:
        print("Model1 and label encoder found. Skipping training.")

    if not model2_exists:
        print("Model2 or label encoder missing. Training Model2...")
        subprocess.run(["python", "train_model2.py"])  # Train second model
    else:
        print("Model2 and label encoder found. Skipping training.")

# Run model check and training before starting the application
check_and_train_models()

# Load models and label encoders
#model1 = tf.keras.models.load_model("E:\\Major project final\\models\\modeladvlatest.pkl")
model1 = joblib.load("E:\\Major project final\\models\\modeladvlatest.pkl")
model2 = joblib.load("E:\\Major project final\\models\\final_model2normal.pkl")
label_encoder1 = joblib.load("E:\\Major project final\\models\\label_encoderlatest.pkl")
label_encoder2 = joblib.load("E:\\Major project final\\models\\label_encoder21normal.pkl")

# Updated Required Features for Model 1 (CNN-LSTM, TensorFlow)
required_features_1 = [
    'id', 'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
    'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
    'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean', 'dmean',
    'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]


# Updated Required Features for Model 2 (Random Forest/SVM, Joblib)
required_features_2 = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]


#capturing = False
#blocked_ips = {"temporary": set(), "permanent": set()}  # Store blocked IPs
temporary_blocked_ips = []  # Stores temporarily blocked IPs
permanent_blocked_ips = []  # Stores permanently blocked IPs

def check_internet_connection():
    """Check if the system has an internet connection."""
    try:
        py_socket.create_connection(("8.8.8.8", 53), timeout=5)
        return True
    except py_socket.error:
        return False
    
if check_internet_connection():
    print("✅ Internet is available. Starting network traffic monitoring...")
else:
    print("❌ No internet connection. Check your network settings.")
    
    


def preprocess_packet(packet, required_features):

    
    try:
        if not packet.haslayer(IP):
            return None

        features = {}

        # Protocol extraction
        proto = packet[IP].proto if IP in packet else 0

        # ✅ Logging Traffic Types
        if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
            http_payload = packet[Raw].load.decode(errors="ignore")
            print(f"📡 Captured HTTP Traffic: \n{http_payload}\n")

        if packet.haslayer(TCP) and packet[TCP].dport == 443:
            print(f"🔒 Captured HTTPS Packet: {packet[IP].src} → {packet[IP].dst}")

        if packet.haslayer(ICMP):
            print(f"📡 Captured ICMP Packet: {packet[IP].src} → {packet[IP].dst} (Type: {packet[ICMP].type})")

        if packet.haslayer(ARP):
            print(f"🔍 Captured ARP Packet: {packet[ARP].psrc} is asking about {packet[ARP].pdst}")

        if packet.haslayer(UDP):
            print(f"📦 UDP Packet: {packet[IP].src} → {packet[IP].dst}, Dst Port: {packet[UDP].dport}")


        if packet.haslayer(Raw) and b"POST /dvwa/login.php" in packet[Raw].load:
            print("🚨 Possible Brute-force Login Attempt Detected")

        if packet.haslayer(TCP) and packet[TCP].flags & 0x04:
            print(f"🚨 TCP RST Detected: {packet[IP].src} → {packet[IP].dst} (RST)")
        
        # ✅ New: UDP and QUIC Handling
        if packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport

            if sport == 443 or dport == 443:
                print(f"🚀 QUIC Detected (UDP over port 443): {packet[IP].src} → {packet[IP].dst}")
            else:
                print(f"📦 General UDP Packet: {packet[IP].src}:{sport} → {packet[IP].dst}:{dport}")
        # ✅ FTP Analysis
        if packet.haslayer(Raw):
            raw_payload = bytes(packet[Raw].load).decode(errors="ignore")
            ftp_commands = ["USER", "PASS", "CWD", "QUIT", "RETR", "STOR"]
            found_cmds = [cmd for cmd in ftp_commands if cmd in raw_payload]
            if found_cmds:
                features["is_ftp_login"] = 1.0
                features["ct_ftp_cmd"] = float(ftp_commands.index(found_cmds[0]) + 1)
            else:
                features["is_ftp_login"] = 0.0
                features["ct_ftp_cmd"] = 0.0
        else:
            features["is_ftp_login"] = 0.0
            features["ct_ftp_cmd"] = 0.0

        # ✅ Basic Packet Attributes
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = packet.time
        packet_length = len(packet)

        src_port = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else 0
        dst_port = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else 0
        payload_length = len(packet[TCP].payload) if packet.haslayer(TCP) else (
            len(packet[UDP].payload) if packet.haslayer(UDP) else 0)

        swin = packet[TCP].window if packet.haslayer(TCP) else 0
        dwin = swin

        sttl = packet[IP].ttl
        dttl = sttl

        syn_flag = 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x02 else 0
        ack_flag = 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x10 else 0
        rst_flag = 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x04 else 0
        psh_flag = 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x08 else 0
        urg_flag = 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x20 else 0
        fin_flag = 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x01 else 0

        flow_bytes_per_sec = packet_length / timestamp if timestamp > 0 else 0
        flow_packets_per_sec = 1 / timestamp if timestamp > 0 else 0

        packet_id = int(hashlib.sha1(f"{src_ip}{dst_ip}{src_port}{dst_port}{timestamp}".encode()).hexdigest(), 16) % (10 ** 8)
        dur = timestamp

        # ✅ Encoded Services
        service = 'http' if dst_port == 80 else 'https' if dst_port == 443 else 'dns' if dst_port == 53 else 'other'
        service_map = {'http': 1, 'https': 2, 'dns': 3, 'other': 0}
        service_encoded = service_map.get(service, 0)

        # ✅ Encoded States
        state = 'CON' if syn_flag and ack_flag else 'INT' if rst_flag else 'OTH'
        state_map = {'CON': 1, 'INT': 2, 'OTH': 0}
        state_encoded = state_map.get(state, 0)

        # ✅ Flow Features
        sload = payload_length / timestamp if timestamp > 0 else 0
        dload = sload
        sloss = 0
        dloss = 0
        sinpkt = 1
        dinpkt = 1
        sjit = 0
        djit = 0
        stcpb = packet[TCP].seq if packet.haslayer(TCP) else 0
        dtcpb = packet[TCP].ack if packet.haslayer(TCP) else 0
        tcprtt = dtcpb - stcpb if dtcpb >= stcpb else 0
        synack = 1 if syn_flag and ack_flag else 0
        ackdat = 1 if ack_flag and payload_length > 0 else 0
        trans_depth = 0
        response_body_len = payload_length
        ct_srv_src = 1
        ct_state_ttl = sttl + dttl
        ct_dst_ltm = 0
        ct_src_dport_ltm = 0
        ct_dst_sport_ltm = 0
        ct_dst_src_ltm = 0
        ct_flw_http_mthd = 1 if packet.haslayer(Raw) and any(x in packet[Raw].load for x in [b"GET", b"POST", b"PUT", b"DELETE"]) else 0
        ct_src_ltm = 0
        ct_srv_dst = 0
        is_sm_ips_ports = 1 if src_ip == dst_ip and src_port == dst_port else 0

        # ✅ Final Feature Dictionary
        features.update({
            "id": packet_id,
            "dur": dur,
            "proto": proto,
            "service": service_encoded,
            "state": state_encoded,
            "spkts": 1,
            "dpkts": 1,
            "sbytes": payload_length,
            "dbytes": payload_length,
            "rate": flow_packets_per_sec,
            "sttl": sttl,
            "dttl": dttl,
            "sload": sload,
            "dload": dload,
            "sloss": sloss,
            "dloss": dloss,
            "sinpkt": sinpkt,
            "dinpkt": dinpkt,
            "sjit": sjit,
            "djit": djit,
            "swin": swin,
            "stcpb": stcpb,
            "dtcpb": dtcpb,
            "dwin": dwin,
            "tcprtt": tcprtt,
            "synack": synack,
            "ackdat": ackdat,
            "smean": payload_length,
            "dmean": payload_length,
            "trans_depth": trans_depth,
            "response_body_len": response_body_len,
            "ct_srv_src": ct_srv_src,
            "ct_state_ttl": ct_state_ttl,
            "ct_dst_ltm": ct_dst_ltm,
            "ct_src_dport_ltm": ct_src_dport_ltm,
            "ct_dst_sport_ltm": ct_dst_sport_ltm,
            "ct_dst_src_ltm": ct_dst_src_ltm,
            "ct_flw_http_mthd": ct_flw_http_mthd,
            "ct_src_ltm": ct_src_ltm,
            "ct_srv_dst": ct_srv_dst,
            "is_sm_ips_ports": is_sm_ips_ports
        })

        # ✅ Fill missing features with 0.0
        for feat in required_features:
            if feat not in features:
                features[feat] = 0.0

        # ✅ Convert to Model Input
        extracted_features = [features[feat] for feat in required_features]

        if len(extracted_features) != len(required_features):
            print(f"⚠ Warning: Feature length mismatch ({len(extracted_features)} != {len(required_features)})")
            return None

        final_array = np.array(extracted_features, dtype=np.float32).reshape(1, -1)
        return final_array

    except Exception as e:
        print(f"⚠ Error processing packet: {e}")
        return None


def predict_traffic(packet):
    """Predicts attack type using both models and applies blocking logic."""
    
    processed_data1 = preprocess_packet(packet, required_features_1)
    processed_data2 = preprocess_packet(packet, required_features_2)

    if processed_data1 is None or processed_data2 is None:
        return "Error", "Error"

    # Ensure processed_data1 and processed_data2 are NumPy arrays and have the correct shape
    processed_data1 = np.array(processed_data1, dtype=np.float32)
    processed_data2 = np.array(processed_data2, dtype=np.float32)

    if processed_data1.ndim == 1:
        processed_data1 = processed_data1.reshape(1, -1)  # Reshape for model1

    if processed_data2.ndim == 1:
        processed_data2 = processed_data2.reshape(1, -1)  # Reshape for model2

    try:
        attack_type1 = "Benign"
        attack_type2 = "Benign"

        # Model1 Prediction (CNN-LSTM)
        try:
            prediction1 = model1.predict(processed_data1)  # Get class predictions
            
            # If the model outputs probabilities, use np.argmax to get the predicted class
            if prediction1.ndim == 1:
                predicted_index1 = np.argmax(prediction1)
            else:
                predicted_index1 = np.argmax(prediction1, axis=1)[0]

            attack_type1 = label_encoder1.inverse_transform([predicted_index1])[0]
            print("Model1 Prediction:", attack_type1)

            # If Model1 predicts "Benign", "Normal", or "Analysis", run Model2
            if attack_type1.strip().lower() in ["benign", "normal", "analysis"]:
                try:
                    # Convert processed_data2 to a DataFrame for model2 prediction
                    X_df = pd.DataFrame(processed_data2, columns=required_features_2)
                    prediction2 = model2.predict(X_df)  # Direct class predictions

                    # If model2 returns probabilities, extract the predicted class
                    if prediction2.ndim == 1:
                        attack_type2 = label_encoder2.inverse_transform([prediction2[0]])[0]
                    else:
                        attack_type2 = label_encoder2.inverse_transform(prediction2)[0]

                    print("Model2 Prediction:", attack_type2)

                except Exception as e:
                    print(f"Error with Model2 prediction: {e}")
                    attack_type2 = "Error"
            else:
                attack_type2 = attack_type1  # If attack detected by Model1, use Model1's result

        except Exception as e:
            print(f"Error with Model1 prediction: {e}")
            attack_type1 = "Error"
            attack_type2 = "Error"

        # Use Model2 prediction only if Model1 predicts benign or other non-attack labels
        final_attack_type = attack_type1 if attack_type1 not in ["Benign", "Normal", "Analysis"] else attack_type2

        # Severity mapping for known attack types
        severity = {
            "Fuzzers": "Medium",
            "Analysis": "Safe",
            "Backdoor": "Critical",
            "DoS": "High",
            "Exploits": "Low",
            "Generic": "Medium",
            "Reconnaissance": "Medium",
            "Shellcode": "Severe",
            "Worm": "High",
            "Benign": "Safe",
            "BENIGN": "Safe"
        }.get(final_attack_type, "Unknown")

        return final_attack_type, severity

    except Exception as e:
        print(f"Error during prediction: {e}")
        return "Error", "Error"


# ✅ Store blocked IPs with their status
blocked_ips = {
    "temporary": {},  # Temporarily blocked IPs
    "permanent": set()  # Permanently blocked IPs
}
# ✅ Keep track of IPs that have already been sent to the frontend
sent_ips_to_frontend = set()  # 🌐 Set to store emitted IPs

def handle_packet(packet):
    """Processes only incoming packets for ML prediction."""
    global capturing, sent_ips_to_frontend

    if capturing and IP in packet and packet[IP].dst == get_local_ip():
        if not check_internet_connection():
            return
        
        # ✅ Ensure packet uniqueness using IP ID
        packet_id = f"{packet.time:.6f}_{packet[IP].src}_{packet[IP].dst}_{packet[IP].len}_{packet[IP].ttl}_{packet[IP].id}"

        
        # ✅ Mark this packet as processed with timestamp
        #seen_packets[packet_id] = time.time()

        # ✅ Extract IP safely before checking blocked status
        ip = packet[IP].src  # Define `ip` before using it

        # ✅ Ignore temporarily blocked IPs until unblocked
        if ip in blocked_ips["temporary"]:
            print(f"⚠️ IP {ip} is already temporarily blocked. Attack count: {blocked_ips['temporary'][ip]['count']}")
            return
        if ip in blocked_ips["permanent"]:
            print(f"🚫 IP {ip} is permanently blocked. Ignoring packet.")
            return


        # ✅ Detect SYN Flood Attack
        #if packet.haslayer(TCP) and (packet[TCP].flags & 0x02) and packet[IP].dst == get_local_ip():
         #   attack_type, severity = "DoS - SYN Flood", "High"
        #else:
        attack_type, severity = predict_traffic(packet)  # ✅ Call only once

        detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if attack_type and severity:  # Ensure both values exist
            attack_type = attack_type.strip() if attack_type else "" # Normalize case and remove spaces
            severity = severity.strip() if severity else ""
            
            if  attack_type not in {"benign", "normal"} and severity not in {"unknown", "normal"}:  # Fixed comparison
                protocol_name = get_protocol_name(packet.proto)

                socketio.emit('alert', {'Time': detection_time,'type': attack_type, 'severity': severity, 'source_ip': ip})
                socketio.emit('update', {'source': ip, 'destination': packet[IP].dst,'protocol': protocol_name})
                
                # ✅ Define severity levels that trigger blocking
                severity_thresholds = ["Critical", "Severe", "Medium", "High", "Low"]

                if severity in severity_thresholds:
                    # ✅ Trigger automatic temporary blocking based on severity
                    temporarily_block_ip(ip, attack_type)

                    # ✅ Prevent duplicate entries before emitting to frontend
                    if ip not in sent_ips_to_frontend:  # Check if already sent
                        # ✅ Emit blocking update to frontend (Traffic Blocking Section)
                        socketio.emit('traffic_blocking_update', {
                            'Time': detection_time,  # 🕒 Time of detection
                            'source_ip': ip,  # 🌐 Attacker's IP
                            'problem': attack_type,  # ⚠️ Type of attack
                            'severity': severity,  # 🔥 Severity level
                            'status': 'Temporarily Blocked',  
                            'action': 'permanent_block_button'
                        })
                        # ✅ Mark IP as sent
                        sent_ips_to_frontend.add(ip)

def get_protocol_name(proto_id):
    # ✅ Detect SYN Flood Attack
        
    """Maps protocol numbers to names."""
    protocol_map = {
        1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6', 80: 'HTTP', 443: 'HTTPS',
        2: 'IGMP',132: 'SCTP',123: 'NTP', 137: 'NetBIOS', 161: 'SNMP'
    }
    return protocol_map.get(proto_id, f"Unknown ({proto_id})")



# In-memory storage for blocked IPs
blocked_ips = {
    "temporary": {},  # Dictionary to track IP and count
    "permanent": {},
}

TEMP_BLOCK_LIMIT = 3  # Number of times an IP can be blocked before permanent blocking
UNBLOCK_TIME = 300  # Time (seconds) after which an IP is unblocked

def emit_blocked_ips():
    """Emit the latest blocked IPs to the frontend"""
    socketio.emit("update_blocked_ips", {
        "temporary": list(blocked_ips["temporary"].values()),
        "permanent": list(blocked_ips["permanent"].values()),
    })
# Global dictionary to store attack counts even after unblocking
# Global dictionary to store attack counts even after unblocking
ip_attack_counts = {}

def temporarily_block_ip(ip, final_attack_type):
    """Temporarily blocks an IP and ensures count increases correctly after unblocking."""
    try:
        # ✅ Ensure IP count is tracked properly
        if ip not in ip_attack_counts:
            ip_attack_counts[ip] = 0  # Initialize count if new IP

        # ✅ If IP is already temporarily blocked, just increase count
        if ip in blocked_ips["temporary"]:
            blocked_ips["temporary"][ip]["count"] += 1
            print(f"⚠️ IP {ip} is already temporarily blocked. Attack count: {blocked_ips['temporary'][ip]['count']}")
            return False  # Exit function without blocking again

        # ✅ Increase attack count
        ip_attack_counts[ip] += 1  

        # ✅ Block IP using firewall rules
        if os.name == "nt":
            os.system(f'netsh advfirewall firewall delete rule name="TempBlock {ip}"')
            os.system(f'netsh advfirewall firewall add rule name="TempBlock {ip}" dir=in action=block remoteip={ip} enable=yes')
        else:
            os.system(f'sudo iptables -D INPUT -s {ip} -j DROP')
            os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')

        print(f"✅ Temporarily Blocked IP: {ip} (Attack Count: {ip_attack_counts[ip]})")

        # ✅ Add IP to temporary block list with updated attack count
        blocked_ips["temporary"][ip] = {
            "ip": ip,
            "time": time.strftime('%Y-%m-%d %H:%M:%S'),
            "reason": final_attack_type,
            "count": ip_attack_counts[ip]  # Store attack count from global dict
        }

        # ✅ If attack count reaches threshold, permanently block IP
        if ip_attack_counts[ip] >= TEMP_BLOCK_LIMIT:
            permanently_block_ip(ip, final_attack_type)
            if ip in blocked_ips["temporary"]:
                del blocked_ips["temporary"][ip]
            
            emit_blocked_ips()  # ✅ Ensure frontend updates correctly
            return True
        else:
            # ✅ Start auto-unblock process in background
            socketio.start_background_task(auto_unblock_ip, ip, UNBLOCK_TIME)

        emit_blocked_ips()  # Update frontend
        return True

    except Exception as e:
        print(f"❌ Error blocking IP {ip}: {e}")
        return False


def permanently_block_ip(ip, final_attack_type):
    """Permanently blocks an IP."""
    try:
        if os.name == "nt":
            os.system(f'netsh advfirewall firewall add rule name="PermanentBlock {ip}" dir=in action=block remoteip={ip} enable=yes')
        else:
            os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')
        
        print(f"✅ Permanently Blocked IP: {ip}")
        
        blocked_ips["permanent"][ip] = {
            "ip": ip,
            "time": time.strftime('%Y-%m-%d %H:%M:%S'),
            "reason": final_attack_type,
            "count": TEMP_BLOCK_LIMIT
        }
        
        emit_blocked_ips()
        return True
    except Exception as e:
        print(f"❌ Error blocking IP {ip}: {e}")
        return False

def auto_unblock_ip(ip, delay):
    """Automatically unblocks an IP after a delay."""
    time.sleep(delay)
    unblock_ip(ip, "temporary")

def unblock_ip(ip, block_type):
    """Unblocks an IP and removes it from the list."""
    try:
        if os.name == "nt":
            os.system(f'netsh advfirewall firewall delete rule name="TempBlock {ip}"')
            os.system(f'netsh advfirewall firewall delete rule name="PermanentBlock {ip}"')
        else:
            os.system(f'sudo iptables -D INPUT -s {ip} -j DROP')
        
        if block_type == "temporary" and ip in blocked_ips["temporary"]:
            del blocked_ips["temporary"][ip]
        elif block_type == "permanent" and ip in blocked_ips["permanent"]:
            del blocked_ips["permanent"][ip]
        
        emit_blocked_ips()
        return True
    except Exception as e:
        print(f"❌ Error unblocking IP {ip}: {e}")
        return False

@app.route('/temporary_block', methods=['POST'])
def temporary_block():
    data = request.json
    ip = data.get('ip')
    reason = data.get('final_attack_type')
    
    if not ip:
        return jsonify({'status': 'error', 'message': 'IP not provided'}), 400
    
    if temporarily_block_ip(ip, reason):
        return jsonify({'status': 'success', 'message': f'IP {ip} temporarily blocked'})
    
    return jsonify({'status': 'error', 'message': 'Failed to temporarily block IP'}), 500

@app.route('/permanent_block', methods=['POST'])
def permanent_block():
    data = request.json
    ip = data.get('ip')
    reason = data.get('final_attack_type')
    
    if not ip:
        return jsonify({'status': 'error', 'message': 'IP not provided'}), 400
    
    if permanently_block_ip(ip, reason):
        return jsonify({'status': 'success', 'message': f'IP {ip} permanently blocked'})
    
    return jsonify({'status': 'error', 'message': 'Failed to permanently block IP'}), 500

@app.route('/unblock_ip', methods=['POST'])
def unblock():
    data = request.json
    ip = data.get('ip')
    type_ = data.get('type')
    
    if unblock_ip(ip, type_):
        return jsonify({'status': 'success', 'message': f'IP {ip} unblocked successfully'})
    
    return jsonify({'status': 'error', 'message': 'Failed to unblock IP'}), 500

@app.route('/blocked_ips', methods=['GET'])
def get_blocked_ips():
    return jsonify({
        "temporary": list(blocked_ips["temporary"].values()),
        "permanent": list(blocked_ips["permanent"].values()),
    })



def get_local_ip():
    """Returns the local IP address of the machine."""
    return py_socket.gethostbyname(py_socket.gethostname())


@app.route('/')
def index():
    return render_template('index.html', system_name=socket.gethostname())

@app.route("/check_network", methods=["GET"])
def check_network():
    return ({"status": "Connected" if check_internet_connection() else "Disconnected"}), 200

@socketio.on('start_capture')
def start_capture(data=None):
    global capturing
    if not check_internet_connection():
        return
    capturing = True
    #sniff(prn=handle_packet, store=0)
    #sniff(prn=handle_packet, store=False, promisc=True)

    sniff(prn=handle_packet, store=0, promisc=True)
    #sniff(filter="ip or arp", prn=handle_packet, store=0, promisc=True)

@socketio.on('stop_capture')                             
def stop_capture(data=None):
    global capturing
    capturing = False
    
@app.route('/test-features', methods=['POST'])
def test_features():
    try:
        data = request.get_json()
        print("Received JSON:", data)  # 🔍 Add this for debugging

        if not data:
            raise ValueError("No data received.")

        features1 = np.array([data["model1_features"]], dtype=np.float32)

        prediction1 = model1.predict(features1)
        label1 = label_encoder1.inverse_transform([np.argmax(prediction1)])

        return jsonify({
            "Model1 Prediction": label1[0],
            "status": "✅ Prediction Successful"
        })

    except Exception as e:
        print("❌ Exception:", str(e))  # 🔍 Add this to show error in terminal
        return jsonify({"status": "Error", "message": str(e)}), 400

    
'''@app.route('/test-features', methods=['POST'])
def test_features():
    data = request.get_json()

    try:
        if not data:
            raise ValueError("No data received.")

        # Handle model input directly
        features1 = np.array([data["model1_features"]], dtype=np.float32)
        #features2 = np.array([data["model2_features"]], dtype=np.float32)

        prediction1 = model1.predict(features1)
        #prediction2 = model2.predict(features2)

        label1 = label_encoder1.inverse_transform([np.argmax(prediction1)])
        #label2 = label_encoder2.inverse_transform([prediction2[0]])

        return jsonify({
            "Model1 Prediction": label1[0],
            #"Model2 Prediction": label2[0],
            "status": "✅ Prediction Successful"
        })

    except Exception as e:
        return jsonify({"status": "Error", "message": str(e)}), 400

@app.route('/test-features', methods=['POST'])
def test_features():
    data = request.get_json()

    try:
        if not data:
            raise ValueError("No data received.")

        predict_traffic(data)

        return jsonify({"status": "Sent to live pipeline ✅"})

    except Exception as e:
        return jsonify({"status": "Error", "message": str(e)}), 400

'''

'''@app.route('/test-features', methods=['POST'])
def test_features():
    data = request.get_json()

    try:
        if not data:
            raise ValueError("No features received.")

        # ➖ Remove non-numeric data like "Source IP"
        features_only = {k: v for k, v in data.items() if k != "Source IP"}

        # Format as DataFrame
        feature_df = pd.DataFrame([features_only])

        # Run prediction with model2
        prediction = model1.predict(feature_df)[0]
        attack_type = label_encoder1.inverse_transform([prediction])[0]
        severity = "Safe" if attack_type.lower() == "benign" else "High"

        # Emit alert only if it's an attack
        if attack_type.lower() != "benign":
            detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            source_ip = data.get("Source IP", "TestClient")

            socketio.emit('alert', {
                'Time': detection_time,
                'type': attack_type,
                'severity': severity,
                'source_ip': source_ip
            })

        return jsonify({
            "status": "Processed",
            "attack_type": attack_type,
            "severity": severity
        })

    except Exception as e:
        return jsonify({"status": "Error", "message": str(e)}), 400

'''
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, use_reloader=False)
