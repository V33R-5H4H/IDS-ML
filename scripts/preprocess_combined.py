"""
Merge NSL-KDD + CICIDS2017 Preprocessed Data
Creates a unified training set with aligned features and combined labels.
"""

import pickle
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data" / "processed"

print("=" * 60)
print("COMBINED DATASET PREPROCESSING")
print("=" * 60)

# ==================== Load Both Datasets ====================
print("\n[1/3] Loading preprocessed datasets...")

nslkdd_path = DATA_DIR / "preprocessed_data.pkl"
cicids_path = DATA_DIR / "cicids2017_preprocessed.pkl"

# Load NSL-KDD
with open(nslkdd_path, "rb") as f:
    nsl = pickle.load(f)
print(f"  ✅ NSL-KDD: {nsl['X_train'].shape[0]:,} train + {nsl['X_test'].shape[0]:,} test")
print(f"     Attack types: {len(nsl['attack_types'])} — {nsl['attack_types'][:5]}...")

# Load CICIDS2017
with open(cicids_path, "rb") as f:
    cic = pickle.load(f)
print(f"  ✅ CICIDS2017: {cic['X_train'].shape[0]:,} train + {cic['X_test'].shape[0]:,} test")
print(f"     Attack types: {len(cic['attack_types'])} — {cic['attack_types'][:5]}...")

# ==================== Combine ====================
print("\n[2/3] Merging datasets...")

# Get original (unscaled) labels from both datasets
nsl_y_train_labels = nsl["y_train"]  # string labels
nsl_y_test_labels  = nsl["y_test"]
cic_y_train_labels = cic["y_train"]
cic_y_test_labels  = cic["y_test"]

# If labels are still encoded, decode them
if isinstance(nsl_y_train_labels[0], (int, np.integer)):
    nsl_y_train_labels = nsl["label_encoder_target"].inverse_transform(nsl_y_train_labels)
    nsl_y_test_labels  = nsl["label_encoder_target"].inverse_transform(nsl_y_test_labels)
if isinstance(cic_y_train_labels[0], (int, np.integer)):
    cic_y_train_labels = cic["label_encoder_target"].inverse_transform(cic_y_train_labels)
    cic_y_test_labels  = cic["label_encoder_target"].inverse_transform(cic_y_test_labels)

# Prefix CICIDS2017 labels to avoid confusion with NSL-KDD labels
# (both have "normal" which should stay the same)
def prefix_labels(labels, prefix="cic_"):
    return np.array([
        label if label == "normal" else f"{prefix}{label}"
        for label in labels
    ])

cic_y_train_labeled = prefix_labels(cic_y_train_labels)
cic_y_test_labeled  = prefix_labels(cic_y_test_labels)

# Concatenate features (both are already scaled with their own scalers)
# We need to re-scale the combined data together
X_train_raw = np.vstack([nsl["X_train"], cic["X_train"]])
X_test_raw  = np.vstack([nsl["X_test"],  cic["X_test"]])

# Concatenate labels (as strings)
y_train_labels = np.concatenate([nsl_y_train_labels, cic_y_train_labeled])
y_test_labels  = np.concatenate([nsl_y_test_labels,  cic_y_test_labeled])

print(f"  Combined training: {X_train_raw.shape[0]:,} samples")
print(f"  Combined test: {X_test_raw.shape[0]:,} samples")

# Re-scale combined data
print("  Re-scaling combined features...")
combined_scaler = StandardScaler()
X_train_scaled = combined_scaler.fit_transform(X_train_raw)
X_test_scaled  = combined_scaler.transform(X_test_raw)

# Unified label encoding
combined_label_encoder = LabelEncoder()
y_train_encoded = combined_label_encoder.fit_transform(y_train_labels)
y_test_encoded  = combined_label_encoder.transform(y_test_labels)

combined_attacks = list(combined_label_encoder.classes_)
print(f"  ✅ Unified attack types: {len(combined_attacks)}")
for i, attack in enumerate(combined_attacks):
    train_count = np.sum(y_train_labels == attack)
    print(f"    {i:2d} → {attack:25s} ({train_count:>8,})")

# ==================== Save ====================
print("\n[3/3] Saving combined preprocessed data...")

combined_data = {
    "X_train": X_train_scaled,
    "X_test": X_test_scaled,
    "y_train": y_train_labels,
    "y_test": y_test_labels,
    "y_train_encoded": y_train_encoded,
    "y_test_encoded": y_test_encoded,
    "scaler": combined_scaler,
    "label_encoders": nsl.get("label_encoders", {}),  # Use NSL-KDD's categorical encoders
    "label_encoder_target": combined_label_encoder,
    "feature_names": nsl.get("feature_names", [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "logged_in", "count", "srv_count", "serror_rate", "srv_serror_rate",
        "dst_host_srv_count"
    ]),
    "attack_types": combined_attacks,
    "dataset": "combined",
    "nslkdd_train_samples": nsl["X_train"].shape[0],
    "cicids_train_samples": cic["X_train"].shape[0],
}

out_path = DATA_DIR / "combined_preprocessed.pkl"
with open(out_path, "wb") as f:
    pickle.dump(combined_data, f)

print(f"  ✅ Saved to: {out_path}")

print(f"\n{'='*60}")
print("MERGE COMPLETE!")
print(f"{'='*60}")
print(f"""
✅ NSL-KDD:    {nsl['X_train'].shape[0]:>8,} train  |  {nsl['X_test'].shape[0]:>7,} test  |  {len(nsl['attack_types']):2d} attacks
✅ CICIDS2017:  {cic['X_train'].shape[0]:>8,} train  |  {cic['X_test'].shape[0]:>7,} test  |  {len(cic['attack_types']):2d} attacks
✅ Combined:   {X_train_scaled.shape[0]:>8,} train  |  {X_test_scaled.shape[0]:>7,} test  |  {len(combined_attacks):2d} attacks

🎯 Next: python scripts/train_all_models.py --dataset combined
""")
