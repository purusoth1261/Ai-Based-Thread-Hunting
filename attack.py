'''import pandas as pd
import requests
import time
from sklearn.preprocessing import LabelEncoder

# 🛠️ Configurations
FEATURE_DATA_PATH = 'E:\\New Project\\data\\network_traffic Model1.xlsx'
ATTACK_TYPE = "Fuzzers"  # Change to test others: Fuzzers, Exploits, etc.
FLASK_URL = 'http://127.0.0.1:5000/test-features'
MAX_SAMPLES = 40

# 📥 Load dataset
df = pd.read_excel(FEATURE_DATA_PATH)

# 🔤 Encode categorical fields
label_encoder = LabelEncoder()
for column in ['proto', 'service', 'state']:
    if column in df.columns:
        df[column] = label_encoder.fit_transform(df[column].astype(str))

# 🧹 Select only attack data
df['attack_cat'] = df['attack_cat'].str.lower()
filtered_df = df[df['attack_cat'] == ATTACK_TYPE.lower()].head(MAX_SAMPLES)

# ✉️ Required feature columns for model2 (84 features)
columns_required = [
    'id', 'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
    'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
    'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean', 'dmean',
    'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]

print(f"\n🚀 Sending {len(filtered_df)} '{ATTACK_TYPE}' attack packets...\n")

for idx, row in filtered_df.iterrows():
    # Separate the IP for frontend, do not send to model
    feature_dict = row[columns_required].to_dict()
    source_ip = "192.168.75.132"

    try:
        response = requests.post(FLASK_URL, json={
            **feature_dict,
            "Source IP": source_ip  # Used only for frontend, ignored by model
        })
        if response.status_code == 200:
            print(f"[{idx + 1}] ✅ Sent - {response.json()}")
        else:
            print(f"[{idx + 1}] ❌ Failed: {response.text}")
    except Exception as e:
        print(f"[{idx + 1}] ❌ Exception: {e}")

    time.sleep(0.3)'''
import pandas as pd
import requests
import time
from sklearn.preprocessing import LabelEncoder

FEATURE_PATH = 'E:\\New Project\\data\\network_traffic Model1.xlsx'
FLASK_URL = 'http://127.0.0.1:5000/send-test-packet'
ATTACK = "Exploits"

df = pd.read_excel(FEATURE_PATH)

# Encode categorical fields
for col in ['proto', 'service', 'state']:
    df[col] = LabelEncoder().fit_transform(df[col].astype(str))

# Filter and send samples
attack_df = df[df['attack_cat'].str.lower() == ATTACK.lower()].head(20)

# Required feature columns
columns_required = [
    'id', 'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat',
    'smean', 'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl',
    'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst',
    'is_sm_ips_ports'
]

for i, row in attack_df.iterrows():
    packet = row[columns_required].to_dict()
    packet["Source IP"] = "192.168.75.132"

    try:
        res = requests.post(FLASK_URL, json=packet)
        print(f"[{i+1}] ✅ Sent: {res.json()}")
    except Exception as e:
        print(f"[{i+1}] ❌ Error: {e}")

    time.sleep(0.3)
