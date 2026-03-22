"""
Ensemble Model Training Script for IDS-ML System
Combines RF, XGBoost, LightGBM via Voting & Stacking classifiers.

Usage:
    python scripts/train_ensemble.py --dataset combined
    python scripts/train_ensemble.py --dataset nslkdd
"""

import argparse
import json
import pickle
import time
import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import (
    RandomForestClassifier,
    VotingClassifier,
    StackingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.utils.class_weight import compute_class_weight
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

BASE_DIR   = Path(__file__).resolve().parents[1]
DATA_DIR   = BASE_DIR / "data" / "processed"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

DATASET_FILES = {
    "nslkdd":    DATA_DIR / "preprocessed_data.pkl",
    "cicids2017": DATA_DIR / "cicids2017_preprocessed.pkl",
    "combined":  DATA_DIR / "combined_preprocessed.pkl",
}

MAX_TRAIN_SAMPLES = 500_000


def load_data(dataset: str):
    path = DATASET_FILES[dataset]
    if not path.exists():
        print(f"❌ Dataset not found: {path}")
        print(f"   Run the appropriate preprocessing script first.")
        exit(1)
    with open(path, "rb") as f:
        data = pickle.load(f)
    return data


def subsample(X, y, max_samples, random_state=42):
    if X.shape[0] <= max_samples:
        return X, y
    print(f"  ⚠️  Subsampling {X.shape[0]:,} → {max_samples:,}")
    rng = np.random.RandomState(random_state)
    unique, counts = np.unique(y, return_counts=True)
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


def main():
    parser = argparse.ArgumentParser(description="Train Ensemble IDS models")
    parser.add_argument(
        "--dataset",
        choices=["nslkdd", "cicids2017", "combined"],
        default="combined",
        help="Dataset to train on",
    )
    parser.add_argument(
        "--method",
        choices=["voting", "stacking", "both"],
        default="both",
        help="Ensemble method to use",
    )
    args = parser.parse_args()

    print("=" * 60)
    print(f"IDS-ML ENSEMBLE TRAINING — {args.dataset.upper()}")
    print("=" * 60)

    # ── Load data ──
    data = load_data(args.dataset)
    X_train = data["X_train"]
    X_test  = data["X_test"]
    y_train = data["y_train_encoded"]
    y_test  = data["y_test_encoded"]
    n_classes = len(data["attack_types"])
    attack_types = data["attack_types"]

    print(f"  Training: {X_train.shape[0]:,} × {X_train.shape[1]} features")
    print(f"  Test:     {X_test.shape[0]:,} samples")
    print(f"  Classes:  {n_classes}")

    X_train, y_train = subsample(X_train, y_train, MAX_TRAIN_SAMPLES)

    # ── Base estimators ──
    print("\n  Building base estimators …")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=30,
        min_samples_split=4,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced_subsample",
    )

    xgb = XGBClassifier(
        n_estimators=200,
        max_depth=10,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="mlogloss",
        n_jobs=-1,
        random_state=42,
        verbosity=0,
    )

    lgbm = LGBMClassifier(
        n_estimators=200,
        max_depth=15,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        n_jobs=-1,
        random_state=42,
        verbose=-1,
        class_weight="balanced",
    )

    estimators = [("rf", rf), ("xgb", xgb), ("lgbm", lgbm)]
    results = {}

    # ── Voting Classifier ──
    if args.method in ("voting", "both"):
        print("\n" + "─" * 50)
        print("TRAINING: Soft Voting Ensemble (RF + XGB + LightGBM)")
        print("─" * 50)

        voting = VotingClassifier(
            estimators=estimators,
            voting="soft",
            n_jobs=-1,
        )

        t0 = time.time()
        voting.fit(X_train, y_train)
        train_time = time.time() - t0

        y_pred = voting.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        print(f"  ✅ Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")
        print(f"  ⏱  Training time: {train_time:.1f}s")

        # Save
        model_path = MODELS_DIR / f"ensemble_voting_{args.dataset}.pkl"
        joblib.dump(voting, model_path)
        print(f"  💾 Saved: {model_path.name}")

        meta = {
            "model_name": f"Voting Ensemble ({args.dataset})",
            "model_type": "VotingClassifier",
            "model_file": model_path.name,
            "accuracy": float(accuracy),
            "training_samples": int(X_train.shape[0]),
            "test_samples": int(X_test.shape[0]),
            "n_classes": n_classes,
            "dataset": args.dataset,
            "training_time_seconds": round(train_time, 1),
            "base_models": ["RandomForest", "XGBoost", "LightGBM"],
            "attack_types": list(attack_types),
        }
        with open(MODELS_DIR / f"ensemble_voting_{args.dataset}_metadata.json", "w") as f:
            json.dump(meta, f, indent=2)

        results["voting"] = accuracy

    # ── Stacking Classifier ──
    if args.method in ("stacking", "both"):
        print("\n" + "─" * 50)
        print("TRAINING: Stacking Ensemble (RF + XGB + LightGBM → LR)")
        print("─" * 50)

        stacking = StackingClassifier(
            estimators=estimators,
            final_estimator=LogisticRegression(
                max_iter=1000, solver="lbfgs", multi_class="multinomial", n_jobs=-1
            ),
            cv=3,
            n_jobs=-1,
            passthrough=False,
        )

        t0 = time.time()
        stacking.fit(X_train, y_train)
        train_time = time.time() - t0

        y_pred = stacking.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        print(f"  ✅ Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")
        print(f"  ⏱  Training time: {train_time:.1f}s")

        # Save
        model_path = MODELS_DIR / f"ensemble_stacking_{args.dataset}.pkl"
        joblib.dump(stacking, model_path)
        print(f"  💾 Saved: {model_path.name}")

        meta = {
            "model_name": f"Stacking Ensemble ({args.dataset})",
            "model_type": "StackingClassifier",
            "model_file": model_path.name,
            "accuracy": float(accuracy),
            "training_samples": int(X_train.shape[0]),
            "test_samples": int(X_test.shape[0]),
            "n_classes": n_classes,
            "dataset": args.dataset,
            "training_time_seconds": round(train_time, 1),
            "base_models": ["RandomForest", "XGBoost", "LightGBM"],
            "meta_learner": "LogisticRegression",
            "attack_types": list(attack_types),
        }
        with open(MODELS_DIR / f"ensemble_stacking_{args.dataset}_metadata.json", "w") as f:
            json.dump(meta, f, indent=2)

        results["stacking"] = accuracy

    # ── Summary ──
    print("\n" + "=" * 60)
    print("ENSEMBLE TRAINING COMPLETE")
    print("=" * 60)
    for name, acc in sorted(results.items(), key=lambda x: -x[1]):
        bar_len = int(acc * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        print(f"  {name.upper():10s} [{bar}] {acc * 100:6.2f}%")
    print(f"\n  Models saved in: {MODELS_DIR}")


if __name__ == "__main__":
    main()
"""
Training Complete Ensemble Model for IDS-ML System
"""
