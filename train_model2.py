import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Define model save directory
model_dir = 'E:\\Major project final\\models\\'

# Ensure the directory exists
os.makedirs(model_dir, exist_ok=True)

# Load dataset
df = pd.read_csv("E:\\Major project final\\data\\network_data Model2.csv")


# ✅ Fix column names (Remove spaces)
df.columns = df.columns.str.strip()

# ✅ Updated feature selection
selected_features = [
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

# ✅ Ensure only existing columns are selected
existing_columns = [col for col in selected_features if col in df.columns]
#print(f"Existing columns in dataset: {existing_columns}")

# ✅ Check for missing features
missing_features = [feat for feat in selected_features if feat not in df.columns]
if missing_features:
    print(f"❌ Warning! Missing features in dataset: {missing_features}")
    exit(1)  # Stop execution if any feature is missing

# ✅ Extract Features & Target
X = df[existing_columns].copy()
y = df.iloc[:, -1]  # Assuming last column is the target label

# ✅ Convert to numeric & handle missing values
X = X.apply(pd.to_numeric, errors='coerce')  # Convert all columns to numeric
X.replace([np.inf, -np.inf], np.nan, inplace=True)  # Replace infinite values
X.fillna(X.median(), inplace=True)  # Fill NaN with median

# ✅ Encode target labels
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# ✅ Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.3, random_state=42)

# ✅ Confirm X_train has correct features
print(f"✅ X_train Shape: {X_train.shape}")
if X_train.shape[1] != len(existing_columns):
    print("❌ Error! Model is not using all features.")
    exit(1)

# ✅ Train the Random Forest Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ✅ Evaluate Model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred) * 100
print(f"✅ Model Accuracy: {accuracy}%")
print(classification_report(y_test, y_pred))
data=np.array([[80,583386,5,5,1044,11595,348,0,208.8,190.60745,7240,0,2319,3003.171157,21664.90111,17.14130953,64820.66667,95801.89091,212981,41,435979,108994.75,118440.9027,212981,1005,583037,145759.25,205320.592,435671,56,0,0,0,0,168,168,8.570654764,8.570654764,0,7240,1149,2209.209225,4880605.4,0,0,0,1,0,0,0,0,1,1263.9,208.8,2319,168,0,0,0,0,0,0,5,1044,5,11595,29200,235,3,32,0,0,0,0,0,0,0,0

]])

prediction=model.predict (data)
prediction1=label_encoder.inverse_transform(prediction)
print("prediction",prediction1)
# ✅ Save Model & Encoder
model_file_path = os.path.join(model_dir, 'final_model2normal.pkl')
label_encoder_file_path = os.path.join(model_dir, 'label_encoder21normal.pkl')

joblib.dump(model, model_file_path)
joblib.dump(label_encoder, label_encoder_file_path)

print(f"✅ Model saved at: {model_file_path}")
print(f"✅ Label Encoder saved at: {label_encoder_file_path}")
print(f"✅ Model expects {model.n_features_in_} features (should be {len(existing_columns)}).")
