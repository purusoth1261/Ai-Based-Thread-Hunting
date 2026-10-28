import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
import os

# Load dataset
df = pd.read_excel('E:\\Major project final\\data\\network_traffic Model1.xlsx')

# Encode categorical features
label_encoder = LabelEncoder()
for column in ['proto', 'service', 'state']:
    if column in df.columns:
        df[column] = label_encoder.fit_transform(df[column])

# Fill missing values
df.fillna(df.select_dtypes(include=['number']).mean(), inplace=True)

# Feature selection
columns_required = [
    'id', 'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
    'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
    'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean', 'dmean',
    'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports', 'attack_cat'
]
df = df[columns_required]

# Features and Target
X = df.drop(columns=['attack_cat']).values  # Features
y = df['attack_cat'].values  # Target

# Encode labels
y = label_encoder.fit_transform(y)

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=50)

# Build Random Forest Model
rf_model = RandomForestClassifier(n_estimators=100, random_state=50)

# Train the model
rf_model.fit(X_train, y_train)

# Make predictions
y_pred = rf_model.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print(f"Test Accuracy: {accuracy * 100:.2f}%")

# Make prediction on new input
# Converted input for prediction with 43 features (match the model's input features)
prediction_input = np.array([[97572, 0.953902, 6, -1, 1, 10, 8, 564, 354, 17.821537, 254, 252,
                             4260.395508, 2599.847656, 2, 1, 102.987222, 126.33443, 6796.110058,
                             171.586437, 255, 1706929043, 2955478191, 255, 0.132472, 0.069559,
                             0.062913, 56, 44, 0, 0, 2, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0]])


prediction_input = prediction_input.reshape(1, -1)  # Flatten for model prediction
raw_prediction = rf_model.predict(prediction_input)
prediction1 = label_encoder.inverse_transform(raw_prediction)
print("Prediction:", prediction1)
# Save the model
modeldir = 'E:\\Major project final\\models\\'
label_encoder_file_path = os.path.join(modeldir, 'label_encoderlatest.pkl')
joblib.dump(rf_model, modeldir + 'modeladvlatest.pkl')  # Save Random Forest Model
joblib.dump(label_encoder, label_encoder_file_path)  # Save Label Encoder

print("Model adv and encoder adv saved successfully.")

