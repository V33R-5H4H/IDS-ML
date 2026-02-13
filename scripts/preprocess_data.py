"""
Data Preprocessing Script for IDS-ML System
Loads NSL-KDD data, preprocesses, and saves for model training
FIXED: Handles unseen attack types in test set
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import pickle
import os

print("=" * 60)
print("IDS-ML DATA PREPROCESSING")
print("=" * 60)

# ==================== STEP 1: Load Data ====================
print("\n[1/7] Loading data...")

column_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'attack_type', 'difficulty_level'
]

df_train = pd.read_csv('C:/V33R/Programming/Projects/IDS_ML/IDS-ML_1.0/data/raw/KDDTrain+.txt', names=column_names)
df_test = pd.read_csv('C:/V33R/Programming/Projects/IDS_ML/IDS-ML_1.0/data/raw/KDDTest+.txt', names=column_names)

print(f"✅ Training data: {df_train.shape}")
print(f"✅ Test data: {df_test.shape}")

# ==================== STEP 2: Handle Unknown Attack Types ====================
print("\n[2/7] Checking for unknown attack types...")

train_attacks = set(df_train['attack_type'].unique())
test_attacks = set(df_test['attack_type'].unique())
unseen_attacks = test_attacks - train_attacks

if unseen_attacks:
    print(f"⚠️  Found {len(unseen_attacks)} unseen attack types in test set:")
    print(f"   {', '.join(unseen_attacks)}")
    
    # Map unseen attacks to 'unknown' or similar attack category
    # For now, we'll map them to the most similar attack type or remove them
    print(f"   Removing rows with unseen attacks from test set...")
    df_test = df_test[df_test['attack_type'].isin(train_attacks)]
    print(f"✅ Test data after filtering: {df_test.shape}")
else:
    print("✅ No unseen attack types")

# ==================== STEP 3: Feature Selection ====================
print("\n[3/7] Selecting features...")

# Select top 12 features based on correlation and domain knowledge
selected_features = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'logged_in', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'dst_host_srv_count'
]

X_train = df_train[selected_features].copy()
X_test = df_test[selected_features].copy()
y_train = df_train['attack_type'].copy()
y_test = df_test['attack_type'].copy()

print(f"✅ Selected {len(selected_features)} features")
print(f"   Features: {', '.join(selected_features)}")

# ==================== STEP 4: Encode Categorical Features ====================
print("\n[4/7] Encoding categorical features...")

categorical_features = ['protocol_type', 'service', 'flag']
label_encoders = {}

for feature in categorical_features:
    le = LabelEncoder()
    
    # Fit on training data
    X_train[feature] = le.fit_transform(X_train[feature])
    
    # Transform test data, handling unseen labels
    def safe_transform(le, data):
        """Transform data, mapping unseen labels to -1"""
        result = []
        for val in data:
            if val in le.classes_:
                result.append(le.transform([val])[0])
            else:
                result.append(-1)  # Unknown label
        return np.array(result)
    
    X_test[feature] = safe_transform(le, X_test[feature])
    label_encoders[feature] = le
    print(f"   ✅ Encoded {feature}: {len(le.classes_)} classes")

# ==================== STEP 5: Scale Numerical Features ====================
print("\n[5/7] Scaling numerical features...")

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(f"✅ Features scaled using StandardScaler")

# ==================== STEP 6: Encode Target Variable ====================
print("\n[6/7] Encoding target variable...")

label_encoder_target = LabelEncoder()
y_train_encoded = label_encoder_target.fit_transform(y_train)
y_test_encoded = label_encoder_target.transform(y_test)  # Now safe, we filtered test set

print(f"✅ Target encoded: {len(label_encoder_target.classes_)} attack types")
print(f"   Classes: {list(label_encoder_target.classes_[:10])}...")

# ==================== STEP 7: Save Preprocessed Data ====================
print("\n[7/7] Saving preprocessed data...")

# Create output directory
os.makedirs('C:/V33R/Programming/Projects/IDS_ML/IDS-ML_1.0/data/processed', exist_ok=True)

# Save preprocessed data
preprocessed_data = {
    'X_train': X_train_scaled,
    'X_test': X_test_scaled,
    'y_train': y_train,
    'y_test': y_test,
    'y_train_encoded': y_train_encoded,
    'y_test_encoded': y_test_encoded,
    'scaler': scaler,
    'label_encoders': label_encoders,
    'label_encoder_target': label_encoder_target,
    'feature_names': selected_features,
    'attack_types': list(label_encoder_target.classes_)
}

with open('C:/V33R/Programming/Projects/IDS_ML/IDS-ML_1.0/data/processed/preprocessed_data.pkl', 'wb') as f:
    pickle.dump(preprocessed_data, f)

print(f"✅ Saved to: data/processed/preprocessed_data.pkl")

# Save also as numpy arrays for easy access
np.savez('C:/V33R/Programming/Projects/IDS_ML/IDS-ML_1.0/data/processed/train_test_data.npz',
         X_train=X_train_scaled,
         X_test=X_test_scaled,
         y_train=y_train_encoded,
         y_test=y_test_encoded)

print(f"✅ Saved to: data/processed/train_test_data.npz")

# ==================== FINAL SUMMARY ====================
print("\n" + "=" * 60)
print("PREPROCESSING COMPLETE!")
print("=" * 60)
print(f"""
✅ Training samples: {X_train_scaled.shape[0]:,}
✅ Test samples: {X_test_scaled.shape[0]:,}
✅ Features: {X_train_scaled.shape[1]}
✅ Attack types: {len(label_encoder_target.classes_)}

📊 Attack type distribution (training):
""")

# Show attack distribution
attack_dist = pd.Series(y_train).value_counts().head(10)
for attack, count in attack_dist.items():
    print(f"   {attack:20s}: {count:6,} ({count/len(y_train)*100:5.2f}%)")

print(f"""
✅ Files saved:
   - preprocessed_data.pkl (complete data + encoders)
   - train_test_data.npz (numpy arrays only)

🎯 Data ready for model training!
Next step: Run scripts/train_model.py
""")
