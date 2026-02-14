"""
Random Forest Model Training Script for IDS-ML System
Trains Random Forest classifier on preprocessed NSL-KDD data
"""

import pickle
import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pandas as pd

print("=" * 60)
print("IDS-ML MODEL TRAINING - Random Forest")
print("=" * 60)

# ==================== STEP 1: Load Preprocessed Data ====================
print("\n[1/5] Loading preprocessed data...")

BASE_DIR = Path(__file__).resolve().parents[1]
data_path = BASE_DIR / "data" / "processed" / "preprocessed_data.pkl"

with open(data_path, "rb") as f:
    data = pickle.load(f)

X_train = data["X_train"]
X_test = data["X_test"]
y_train = data["y_train_encoded"]
y_test = data["y_test_encoded"]
label_encoder_target = data["label_encoder_target"]
feature_names = data["feature_names"]

print(f"✅ Training samples: {X_train.shape[0]:,}")
print(f"✅ Test samples: {X_test.shape[0]:,}")
print(f"✅ Features: {X_train.shape[1]}")
print(f"✅ Attack types: {len(label_encoder_target.classes_)}")

# ==================== STEP 2: Train Random Forest ====================
print("\n[2/5] Training Random Forest model...")

model = RandomForestClassifier(
    n_estimators=300,           # Increased from 150
    max_depth=None,             # No depth limit (changed from 18)
    min_samples_split=4,        # Tuned
    min_samples_leaf=2,         # Tuned
    n_jobs=-1,                  # Use all CPU cores
    random_state=42,
    class_weight="balanced_subsample",  # Handle class imbalance
    verbose=1                   # Show progress
)

print("Training in progress...")
model.fit(X_train, y_train)
print("✅ Training complete!")

# ==================== STEP 3: Make Predictions ====================
print("\n[3/5] Making predictions on test set...")

y_pred = model.predict(X_test)
y_pred_proba = model.predict_proba(X_test)

# ==================== STEP 4: Evaluate Model ====================
print("\n[4/5] Evaluating model performance...")

accuracy = accuracy_score(y_test, y_pred)
print(f"\n{'='*60}")
print(f"OVERALL ACCURACY: {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"{'='*60}")

# Classification report with attack names
print("\nClassification Report (by label index):")
print(classification_report(y_test, y_pred, zero_division=0))

# Show label mapping
print("\n" + "="*60)
print("LABEL INDEX → ATTACK TYPE MAPPING")
print("="*60)
for idx, cls in enumerate(label_encoder_target.classes_):
    support = np.sum(y_test == idx)
    print(f"{idx:2d} → {cls:20s} (support: {support:5,})")

# Confusion matrix
print("\n" + "="*60)
print("CONFUSION MATRIX (first 10x10)")
print("="*60)
cm = confusion_matrix(y_test, y_pred)
print(cm[:10, :10])

# Feature importance
print("\n" + "="*60)
print("TOP 10 IMPORTANT FEATURES")
print("="*60)
feature_importance = pd.DataFrame({
    'feature': feature_names,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

for idx, row in feature_importance.head(10).iterrows():
    print(f"{row['feature']:25s}: {row['importance']:.4f}")

# ==================== STEP 5: Save Model ====================
print("\n[5/5] Saving trained model...")

models_dir = BASE_DIR / "models"
models_dir.mkdir(exist_ok=True)

model_path = models_dir / "random_forest_ids.pkl"
joblib.dump(model, model_path)
print(f"✅ Model saved to: {model_path}")

# Save model metadata
metadata = {
    "model_name": "Random Forest IDS v1.0",
    "model_type": "RandomForestClassifier",
    "accuracy": float(accuracy),
    "n_estimators": 300,
    "max_depth": None,
    "training_samples": X_train.shape[0],
    "test_samples": X_test.shape[0],
    "features": feature_names,
    "attack_types": list(label_encoder_target.classes_)
}

metadata_path = models_dir / "model_metadata.json"
import json
with open(metadata_path, 'w') as f:
    json.dump(metadata, f, indent=2)
print(f"✅ Metadata saved to: {metadata_path}")

# ==================== FINAL SUMMARY ====================
print("\n" + "="*60)
print("TRAINING COMPLETE!")
print("="*60)
print(f"""
✅ Model: Random Forest (300 trees)
✅ Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)
✅ Model saved to: {model_path.name}

📊 Next steps:
   1. Review classification report
   2. Check feature importance
   3. Test API integration
   4. Build FastAPI backend
""")
