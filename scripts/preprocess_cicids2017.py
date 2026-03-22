"""
Preprocess CICIDS2017 Dataset
Loads all CSV files, cleans data, aligns features with NSL-KDD schema,
and saves preprocessed data for model training.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import pickle
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

BASE_DIR = Path(__file__).resolve().parents[1]
RAW_DIR  = BASE_DIR / "data" / "raw" / "cicids2017"
OUT_DIR  = BASE_DIR / "data" / "processed"

print("=" * 60)
print("CICIDS2017 PREPROCESSING")
print("=" * 60)

# ==================== STEP 1: Load All CSVs ====================
print("\n[1/6] Loading CSV files...")

csv_files = sorted(RAW_DIR.glob("*.csv"))
if not csv_files:
    print(f"❌ No CSV files found in {RAW_DIR}")
    print("   Run scripts/download_cicids2017.py first.")
    exit(1)

dfs = []
for csv_file in csv_files:
    print(f"  Loading {csv_file.name}...", end="")
    try:
        df = pd.read_csv(csv_file, encoding="utf-8", low_memory=False)
        # Strip whitespace from column names
        df.columns = df.columns.str.strip()
        print(f" {len(df):,} rows, {len(df.columns)} cols")
        dfs.append(df)
    except Exception as e:
        print(f" ❌ Error: {e}")

df = pd.concat(dfs, ignore_index=True)
print(f"\n✅ Total: {len(df):,} rows, {len(df.columns)} columns")

# ==================== STEP 2: Clean Data ====================
print("\n[2/6] Cleaning data...")

# Strip whitespace from Label column
if "Label" in df.columns:
    label_col = "Label"
elif " Label" in df.columns:
    label_col = " Label"
    df.rename(columns={" Label": "Label"}, inplace=True)
    label_col = "Label"
else:
    print("❌ No 'Label' column found!")
    print(f"   Columns: {list(df.columns[:10])}...")
    exit(1)

df["Label"] = df["Label"].astype(str).str.strip()

# Show label distribution before cleaning
print("\n  Label distribution:")
label_counts = df["Label"].value_counts()
for label, count in label_counts.items():
    print(f"    {label:30s}: {count:>10,} ({count/len(df)*100:5.2f}%)")

# Replace infinity values with NaN, then drop NaN rows
numeric_cols = df.select_dtypes(include=[np.number]).columns
df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
rows_before = len(df)
df.dropna(inplace=True)
dropped = rows_before - len(df)
print(f"\n  Dropped {dropped:,} rows with NaN/Inf ({dropped/rows_before*100:.2f}%)")
print(f"  Remaining: {len(df):,} rows")

# ==================== STEP 3: Map Labels ====================
print("\n[3/6] Mapping attack labels...")

# Map CICIDS2017 labels to unified categories
LABEL_MAP = {
    "BENIGN":                      "normal",
    "Bot":                         "botnet",
    "DDoS":                        "ddos",
    "DoS Hulk":                    "dos_hulk",
    "DoS GoldenEye":               "dos_goldeneye",
    "DoS slowloris":               "dos_slowloris",
    "DoS Slowhttptest":            "dos_slowhttp",
    "FTP-Patator":                 "brute_force_ftp",
    "SSH-Patator":                 "brute_force_ssh",
    "Heartbleed":                  "heartbleed",
    "Infiltration":                "infiltration",
    "PortScan":                    "portscan",
    "Web Attack – Brute Force":    "web_brute_force",
    "Web Attack – XSS":            "web_xss",
    "Web Attack – Sql Injection":  "web_sql_injection",
    # Common alternative label names in some versions
    "Web Attack \x96 Brute Force": "web_brute_force",
    "Web Attack \x96 XSS":        "web_xss",
    "Web Attack \x96 Sql Injection": "web_sql_injection",
}

df["attack_type"] = df["Label"].map(LABEL_MAP)

# Handle any unmapped labels
unmapped = df[df["attack_type"].isna()]["Label"].unique()
if len(unmapped) > 0:
    print(f"  ⚠️  Unmapped labels: {list(unmapped)}")
    # Try to handle common variations
    for label in unmapped:
        lower = label.lower().strip()
        if "brute" in lower and "web" in lower:
            df.loc[df["Label"] == label, "attack_type"] = "web_brute_force"
        elif "xss" in lower:
            df.loc[df["Label"] == label, "attack_type"] = "web_xss"
        elif "sql" in lower:
            df.loc[df["Label"] == label, "attack_type"] = "web_sql_injection"
        elif "benign" in lower:
            df.loc[df["Label"] == label, "attack_type"] = "normal"
        else:
            df.loc[df["Label"] == label, "attack_type"] = label.lower().replace(" ", "_")

    # Drop any remaining NaN attack types
    still_unmapped = df["attack_type"].isna().sum()
    if still_unmapped > 0:
        df.dropna(subset=["attack_type"], inplace=True)
        print(f"  Dropped {still_unmapped} unmappable rows")

print("\n  Mapped label distribution:")
for attack, count in df["attack_type"].value_counts().items():
    print(f"    {attack:25s}: {count:>10,} ({count/len(df)*100:5.2f}%)")

# ==================== STEP 4: Feature Engineering (align with NSL-KDD 12 features) ====================
print("\n[4/6] Engineering features to match NSL-KDD schema...")

# Map CICIDS2017 columns → NSL-KDD 12-feature schema
# CICIDS2017 has 78 flow features; we select/derive the best matches

def safe_col(df, primary, fallback=None, default=0):
    """Get column with fallback."""
    if primary in df.columns:
        return df[primary].fillna(default).astype(float)
    if fallback and fallback in df.columns:
        return df[fallback].fillna(default).astype(float)
    return pd.Series(default, index=df.index, dtype=float)

# Total packets
fwd_pkts = safe_col(df, "Total Fwd Packets", "Tot Fwd Pkts")
bwd_pkts = safe_col(df, "Total Backward Packets", "Tot Bwd Pkts")
total_pkts = fwd_pkts + bwd_pkts
total_pkts = total_pkts.replace(0, 1)  # avoid division by zero

# Protocol encoding (CICIDS2017 uses numeric: 6=TCP, 17=UDP, 1=ICMP)
protocol_raw = safe_col(df, "Protocol")
proto_map_cic = {6: 0, 17: 1, 1: 2}  # TCP=0, UDP=1, ICMP=2
protocol_enc = protocol_raw.map(proto_map_cic).fillna(0).astype(int)

# Build the 12-feature aligned DataFrame
features = pd.DataFrame({
    # 1. duration (CICIDS2017 stores in microseconds)
    "duration": safe_col(df, "Flow Duration") / 1_000_000.0,  # μs → seconds

    # 2. protocol_type (encoded: TCP=0, UDP=1, ICMP=2)
    "protocol_type": protocol_enc,

    # 3. service (use destination port as proxy, encode to ~10 buckets)
    "service": safe_col(df, "Destination Port").clip(0, 65535).apply(
        lambda p: 0 if p == 80 else (1 if p == 443 else (2 if p == 22 else
                   (3 if p == 21 else (4 if p == 25 else (5 if p == 53 else
                   (6 if p == 110 else (7 if p < 1024 else 8)))))))
    ).astype(int),

    # 4. flag (use SYN/FIN/RST counts as proxy for TCP flag state)
    "flag": (
        safe_col(df, "SYN Flag Count").clip(0, 1) * 3 +    # SF-like if SYN present
        safe_col(df, "RST Flag Count").clip(0, 1) * 1 +    # REJ-like if RST present
        safe_col(df, "FIN Flag Count").clip(0, 1) * 2       # Normal if FIN present
    ).astype(int),

    # 5. src_bytes (forward bytes)
    "src_bytes": safe_col(df, "Total Length of Fwd Packets", "TotLen Fwd Pkts"),

    # 6. dst_bytes (backward bytes)
    "dst_bytes": safe_col(df, "Total Length of Bwd Packets", "TotLen Bwd Pkts"),

    # 7. logged_in (1 if bidirectional flow = established session)
    "logged_in": (bwd_pkts > 0).astype(float),

    # 8. count (total packets, capped at 511)
    "count": total_pkts.clip(upper=511),

    # 9. srv_count (flow packets/s as rate proxy)
    "srv_count": safe_col(df, "Flow Packets/s").clip(0, 511),

    # 10. serror_rate (SYN error rate proxy)
    "serror_rate": (safe_col(df, "SYN Flag Count") / total_pkts).clip(0, 1),

    # 11. srv_serror_rate (same as serror_rate for flow-level data)
    "srv_serror_rate": (safe_col(df, "SYN Flag Count") / total_pkts).clip(0, 1),

    # 12. dst_host_srv_count (unique destination port diversity, capped at 255)
    "dst_host_srv_count": safe_col(df, "Destination Port").clip(0, 255),
})

print(f"  ✅ Engineered 12 features: {list(features.columns)}")
print(f"  Shape: {features.shape}")

# ==================== STEP 5: Scale and Encode ====================
print("\n[5/6] Scaling and encoding...")

# Target encoding
label_encoder_target = LabelEncoder()
y_encoded = label_encoder_target.fit_transform(df["attack_type"])
attack_types = list(label_encoder_target.classes_)
print(f"  ✅ {len(attack_types)} attack types: {attack_types}")

# Train/test split (80/20)
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(
    features.values, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

# Scale
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(f"  ✅ Training: {X_train_scaled.shape[0]:,} samples")
print(f"  ✅ Test: {X_test_scaled.shape[0]:,} samples")

# ==================== STEP 6: Save ====================
print("\n[6/6] Saving preprocessed data...")

OUT_DIR.mkdir(parents=True, exist_ok=True)

# Build label encoders dict (for categorical features — already encoded numerically)
# For CICIDS2017 we encoded categoricals differently, so we save the mappings
label_encoders = {
    "protocol_type": LabelEncoder().fit(["tcp", "udp", "icmp"]),
    "service": LabelEncoder().fit(["http", "https", "ssh", "ftp", "smtp", "dns", "pop3", "system", "other"]),
    "flag": LabelEncoder().fit(["SF", "S0", "REJ", "SH", "RSTO", "OTH"]),
}

preprocessed = {
    "X_train": X_train_scaled,
    "X_test": X_test_scaled,
    "y_train_encoded": y_train,
    "y_test_encoded": y_test,
    "y_train": label_encoder_target.inverse_transform(y_train),
    "y_test": label_encoder_target.inverse_transform(y_test),
    "scaler": scaler,
    "label_encoders": label_encoders,
    "label_encoder_target": label_encoder_target,
    "feature_names": list(features.columns),
    "attack_types": attack_types,
    "dataset": "cicids2017",
    "total_samples": len(df),
}

out_path = OUT_DIR / "cicids2017_preprocessed.pkl"
with open(out_path, "wb") as f:
    pickle.dump(preprocessed, f)

print(f"  ✅ Saved to: {out_path}")

# ==================== SUMMARY ====================
print(f"\n{'='*60}")
print("PREPROCESSING COMPLETE!")
print(f"{'='*60}")
print(f"""
✅ Total samples: {len(df):,}
✅ Training: {X_train_scaled.shape[0]:,}
✅ Test: {X_test_scaled.shape[0]:,}
✅ Features: {X_train_scaled.shape[1]}
✅ Attack types: {len(attack_types)}
✅ Saved to: {out_path.name}

🎯 Next: python scripts/preprocess_combined.py
""")
