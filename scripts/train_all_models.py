"""
Unified Model Training Script for IDS-ML System
Trains Random Forest, LSTM, and CNN models.

Memory-efficient: uses class weights instead of SMOTE for large datasets.

Usage:
    python scripts/train_all_models.py --dataset combined
    python scripts/train_all_models.py --dataset nslkdd --models rf lstm
    python scripts/train_all_models.py --dataset cicids2017
"""

import argparse
import json
import pickle
import time
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.utils.class_weight import compute_class_weight

# Suppress TF warnings & configure GPU
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

def setup_gpu():
    """Configure TensorFlow to use GPU with memory growth."""
    try:
        import tensorflow as tf
        gpus = tf.config.list_physical_devices("GPU")
        if gpus:
            for gpu in gpus:
                tf.config.experimental.set_memory_growth(gpu, True)
            print(f"  🖥️  GPU detected: {gpus[0].name}")
            print(f"     TensorFlow will use GPU for LSTM/CNN training")
        else:
            print(f"  ℹ️  No GPU detected — using CPU (training will be slower)")
    except Exception as e:
        print(f"  ⚠️  GPU setup: {e}")

setup_gpu()

BASE_DIR   = Path(__file__).resolve().parents[1]
DATA_DIR   = BASE_DIR / "data" / "processed"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

DATASET_FILES = {
    "nslkdd":    DATA_DIR / "preprocessed_data.pkl",
    "cicids2017": DATA_DIR / "cicids2017_preprocessed.pkl",
    "combined":  DATA_DIR / "combined_preprocessed.pkl",
}

# Max training samples to avoid OOM (subsample if larger)
MAX_TRAIN_SAMPLES = 500_000


def load_data(dataset: str):
    """Load preprocessed data."""
    path = DATASET_FILES[dataset]
    if not path.exists():
        print(f"❌ Dataset not found: {path}")
        print(f"   Run the appropriate preprocessing script first.")
        exit(1)
    
    with open(path, "rb") as f:
        data = pickle.load(f)
    
    return data


def subsample(X, y, max_samples, random_state=42):
    """Stratified subsample if dataset is too large."""
    if X.shape[0] <= max_samples:
        return X, y
    
    print(f"  ⚠️  Subsampling {X.shape[0]:,} → {max_samples:,} to save memory")
    rng = np.random.RandomState(random_state)
    
    unique, counts = np.unique(y, return_counts=True)
    # Keep proportions, but ensure at least 10 samples per class
    total = X.shape[0]
    indices = []
    for cls, cnt in zip(unique, counts):
        n_keep = max(10, int(cnt * max_samples / total))
        cls_idx = np.where(y == cls)[0]
        chosen = rng.choice(cls_idx, size=min(n_keep, len(cls_idx)), replace=False)
        indices.extend(chosen)
    
    indices = np.array(indices)
    rng.shuffle(indices)
    return X[indices], y[indices]


def get_class_weights(y_train, n_classes):
    """Compute class weights for imbalanced data."""
    classes = np.arange(n_classes)
    present = np.unique(y_train)
    weights = compute_class_weight("balanced", classes=present, y=y_train)
    weight_dict = {cls: w for cls, w in zip(present, weights)}
    # Fill missing classes with 1.0
    for c in classes:
        if c not in weight_dict:
            weight_dict[c] = 1.0
    return weight_dict


def train_random_forest(X_train, y_train, X_test, y_test, n_classes, dataset):
    """Train Random Forest classifier."""
    print("\n" + "─" * 50)
    print("TRAINING: Random Forest")
    print("─" * 50)
    
    # Use fewer trees for large datasets
    n_est = 100 if X_train.shape[0] > 200_000 else 300
    
    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=n_est,
        max_depth=30,          # Cap depth to limit memory
        min_samples_split=4,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced_subsample",  # Handles imbalance without SMOTE
        verbose=0,
    )
    model.fit(X_train, y_train)
    train_time = time.time() - t0
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"  ✅ Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  ⏱  Training time: {train_time:.1f}s")
    
    # Save model
    import joblib
    model_path = MODELS_DIR / f"rf_{dataset}.pkl"
    joblib.dump(model, model_path)
    print(f"  💾 Saved: {model_path.name}")
    
    # Save metadata
    metadata = {
        "model_name": f"Random Forest ({dataset})",
        "model_type": "RandomForestClassifier",
        "model_file": model_path.name,
        "accuracy": float(accuracy),
        "n_estimators": n_est,
        "training_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]),
        "n_classes": n_classes,
        "dataset": dataset,
        "training_time_seconds": round(train_time, 1),
    }
    meta_path = MODELS_DIR / f"rf_{dataset}_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    
    return accuracy, model


def train_lstm(X_train, y_train, X_test, y_test, n_classes, dataset):
    """Train LSTM model."""
    print("\n" + "─" * 50)
    print("TRAINING: LSTM")
    print("─" * 50)
    
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    
    # Reshape for LSTM: (samples, timesteps=1, features=12)
    X_train_lstm = X_train.reshape((X_train.shape[0], 1, X_train.shape[1]))
    X_test_lstm  = X_test.reshape((X_test.shape[0], 1, X_test.shape[1]))
    
    # One-hot encode targets
    y_train_cat = keras.utils.to_categorical(y_train, num_classes=n_classes)
    y_test_cat  = keras.utils.to_categorical(y_test, num_classes=n_classes)
    
    # Class weights for imbalanced data
    cw = get_class_weights(y_train, n_classes)
    
    # Build model
    model = keras.Sequential([
        layers.Input(shape=(1, X_train.shape[1])),
        layers.LSTM(64, return_sequences=True),
        layers.Dropout(0.3),
        layers.LSTM(32),
        layers.Dropout(0.3),
        layers.Dense(64, activation="relu"),
        layers.Dropout(0.2),
        layers.Dense(n_classes, activation="softmax"),
    ])
    
    model.compile(
        optimizer="adam",
        loss="categorical_crossentropy",
        metrics=["accuracy"],
    )
    
    print(f"  Model parameters: {model.count_params():,}")
    
    # Use larger batch for large datasets
    batch = 512 if X_train.shape[0] > 200_000 else 256
    
    # Train
    t0 = time.time()
    history = model.fit(
        X_train_lstm, y_train_cat,
        validation_data=(X_test_lstm, y_test_cat),
        epochs=20,
        batch_size=batch,
        verbose=1,
        class_weight=cw,
        callbacks=[
            keras.callbacks.EarlyStopping(
                patience=4, restore_best_weights=True, monitor="val_accuracy"
            ),
            keras.callbacks.ReduceLROnPlateau(
                factor=0.5, patience=2, monitor="val_loss"
            ),
        ],
    )
    train_time = time.time() - t0
    
    # Evaluate
    y_pred = np.argmax(model.predict(X_test_lstm, verbose=0), axis=1)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"  ✅ Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  ⏱  Training time: {train_time:.1f}s")
    
    # Save model
    model_path = MODELS_DIR / f"lstm_{dataset}.keras"
    model.save(model_path)
    print(f"  💾 Saved: {model_path.name}")
    
    # Save metadata
    metadata = {
        "model_name": f"LSTM ({dataset})",
        "model_type": "LSTM",
        "model_file": model_path.name,
        "accuracy": float(accuracy),
        "epochs_trained": len(history.history["loss"]),
        "training_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]),
        "n_classes": n_classes,
        "dataset": dataset,
        "training_time_seconds": round(train_time, 1),
        "parameters": int(model.count_params()),
    }
    meta_path = MODELS_DIR / f"lstm_{dataset}_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    
    return accuracy, model


def train_cnn(X_train, y_train, X_test, y_test, n_classes, dataset):
    """Train 1D CNN model."""
    print("\n" + "─" * 50)
    print("TRAINING: 1D CNN")
    print("─" * 50)
    
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    
    # Reshape for CNN: (samples, features=12, channels=1)
    X_train_cnn = X_train.reshape((X_train.shape[0], X_train.shape[1], 1))
    X_test_cnn  = X_test.reshape((X_test.shape[0], X_test.shape[1], 1))
    
    # One-hot encode targets
    y_train_cat = keras.utils.to_categorical(y_train, num_classes=n_classes)
    y_test_cat  = keras.utils.to_categorical(y_test, num_classes=n_classes)
    
    # Class weights
    cw = get_class_weights(y_train, n_classes)
    
    # Build model
    model = keras.Sequential([
        layers.Input(shape=(X_train.shape[1], 1)),
        layers.Conv1D(64, kernel_size=3, activation="relu", padding="same"),
        layers.BatchNormalization(),
        layers.Conv1D(64, kernel_size=3, activation="relu", padding="same"),
        layers.MaxPooling1D(pool_size=2),
        layers.Dropout(0.3),
        layers.Conv1D(32, kernel_size=3, activation="relu", padding="same"),
        layers.BatchNormalization(),
        layers.GlobalMaxPooling1D(),
        layers.Dense(64, activation="relu"),
        layers.Dropout(0.3),
        layers.Dense(n_classes, activation="softmax"),
    ])
    
    model.compile(
        optimizer="adam",
        loss="categorical_crossentropy",
        metrics=["accuracy"],
    )
    
    print(f"  Model parameters: {model.count_params():,}")
    
    batch = 512 if X_train.shape[0] > 200_000 else 256
    
    # Train
    t0 = time.time()
    history = model.fit(
        X_train_cnn, y_train_cat,
        validation_data=(X_test_cnn, y_test_cat),
        epochs=20,
        batch_size=batch,
        verbose=1,
        class_weight=cw,
        callbacks=[
            keras.callbacks.EarlyStopping(
                patience=4, restore_best_weights=True, monitor="val_accuracy"
            ),
            keras.callbacks.ReduceLROnPlateau(
                factor=0.5, patience=2, monitor="val_loss"
            ),
        ],
    )
    train_time = time.time() - t0
    
    # Evaluate
    y_pred = np.argmax(model.predict(X_test_cnn, verbose=0), axis=1)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"  ✅ Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  ⏱  Training time: {train_time:.1f}s")
    
    # Save model
    model_path = MODELS_DIR / f"cnn_{dataset}.keras"
    model.save(model_path)
    print(f"  💾 Saved: {model_path.name}")
    
    # Save metadata
    metadata = {
        "model_name": f"1D-CNN ({dataset})",
        "model_type": "CNN",
        "model_file": model_path.name,
        "accuracy": float(accuracy),
        "epochs_trained": len(history.history["loss"]),
        "training_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]),
        "n_classes": n_classes,
        "dataset": dataset,
        "training_time_seconds": round(train_time, 1),
        "parameters": int(model.count_params()),
    }
    meta_path = MODELS_DIR / f"cnn_{dataset}_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    
    return accuracy, model


def main():
    parser = argparse.ArgumentParser(description="Train IDS-ML models")
    parser.add_argument("--dataset", choices=["nslkdd", "cicids2017", "combined"],
                        default="combined", help="Dataset to train on")
    parser.add_argument("--models", nargs="+", choices=["rf", "lstm", "cnn"],
                        default=["rf", "lstm", "cnn"], help="Models to train")
    args = parser.parse_args()
    
    print("=" * 60)
    print(f"IDS-ML MODEL TRAINING — {args.dataset.upper()}")
    print("=" * 60)
    print(f"  Models: {', '.join(args.models)}")
    print(f"  Strategy: class_weight='balanced' (memory-efficient)")
    
    # Load data
    data = load_data(args.dataset)
    X_train = data["X_train"]
    X_test  = data["X_test"]
    y_train = data["y_train_encoded"]
    y_test  = data["y_test_encoded"]
    
    n_classes = len(data["attack_types"])
    
    print(f"\n  Training: {X_train.shape[0]:,} samples × {X_train.shape[1]} features")
    print(f"  Test:     {X_test.shape[0]:,} samples")
    print(f"  Classes:  {n_classes}")
    
    # Subsample if too large
    X_train, y_train = subsample(X_train, y_train, MAX_TRAIN_SAMPLES)
    
    # Show class distribution
    unique, counts = np.unique(y_train, return_counts=True)
    print(f"\n  Class distribution (top 5 + bottom 5):")
    sorted_idx = np.argsort(-counts)
    for i in list(sorted_idx[:5]) + list(sorted_idx[-5:]):
        print(f"    Class {unique[i]:2d}: {counts[i]:>8,}")
    
    # Train models
    results = {}
    
    TRAINERS = {
        "rf":   train_random_forest,
        "lstm": train_lstm,
        "cnn":  train_cnn,
    }
    
    for model_name in args.models:
        trainer = TRAINERS[model_name]
        accuracy, model = trainer(X_train, y_train, X_test, y_test,
                                  n_classes, args.dataset)
        results[model_name] = accuracy
    
    # ==================== Final Summary ====================
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE — RESULTS")
    print("=" * 60)
    print(f"\n  Dataset: {args.dataset}")
    print(f"  Classes: {n_classes}")
    print()
    
    for model_name, accuracy in sorted(results.items(), key=lambda x: -x[1]):
        bar_len = int(accuracy * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        print(f"  {model_name.upper():5s} [{bar}] {accuracy*100:6.2f}%")
    
    print(f"\n  Models saved in: {MODELS_DIR}")
    print(f"  Files:")
    for f in sorted(MODELS_DIR.glob(f"*_{args.dataset}*")):
        print(f"    • {f.name}")
    
    # Save overall summary
    summary = {
        "dataset": args.dataset,
        "n_classes": n_classes,
        "results": {k: float(v) for k, v in results.items()},
        "attack_types": data["attack_types"],
    }
    with open(MODELS_DIR / f"training_summary_{args.dataset}.json", "w") as f:
        json.dump(summary, f, indent=2)


if __name__ == "__main__":
    main()
