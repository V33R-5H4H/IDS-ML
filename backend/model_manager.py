# backend/model_manager.py
"""
Model Manager for IDS-ML v2.0
Manages multiple trained models (RF, LSTM, CNN) with runtime switching.
"""

import json
import logging
import numpy as np
import joblib
from pathlib import Path
from typing import Dict, Any, List, Optional

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR   = PROJECT_ROOT / "models"


class ModelManager:
    """Manages loading, switching, and inference across multiple IDS models."""

    def __init__(self):
        self._models: Dict[str, Any] = {}          # name → loaded model object
        self._metadata: Dict[str, Dict] = {}        # name → metadata dict
        self._active_model: Optional[str] = None
        self._scan_models()

    def _scan_models(self):
        """Scan models/ directory for available models and their metadata."""
        if not MODELS_DIR.exists():
            log.warning("Models directory not found: %s", MODELS_DIR)
            return

        # Find all metadata JSON files
        for meta_file in MODELS_DIR.glob("*_metadata.json"):
            try:
                with open(meta_file) as f:
                    meta = json.load(f)
                
                model_file = meta.get("model_file", "")
                model_path = MODELS_DIR / model_file
                
                if model_path.exists():
                    # Use a clean key: "rf_combined", "lstm_nslkdd", etc.
                    key = meta_file.stem.replace("_metadata", "")
                    self._metadata[key] = {
                        **meta,
                        "model_path": str(model_path),
                        "key": key,
                    }
                    log.info("Found model: %s (accuracy=%.4f)", key,
                             meta.get("accuracy", 0))
                else:
                    log.warning("Model file not found: %s", model_path)
            except Exception as e:
                log.warning("Failed to read metadata %s: %s", meta_file, e)

        # Also check for the legacy random_forest_ids.pkl
        legacy_rf = MODELS_DIR / "random_forest_ids.pkl"
        legacy_meta = MODELS_DIR / "model_metadata.json"
        if legacy_rf.exists() and "random_forest_ids" not in self._metadata:
            meta = {}
            if legacy_meta.exists():
                with open(legacy_meta) as f:
                    meta = json.load(f)
            self._metadata["random_forest_ids"] = {
                "model_name": meta.get("model_name", "Random Forest (legacy)"),
                "model_type": "RandomForestClassifier",
                "model_file": "random_forest_ids.pkl",
                "model_path": str(legacy_rf),
                "accuracy": meta.get("accuracy", 0),
                "dataset": "nslkdd",
                "key": "random_forest_ids",
                **{k: v for k, v in meta.items() if k not in ["model_name", "accuracy"]},
            }

        # Set active model (prefer combined RF, then legacy, then first available)
        if self._metadata:
            preference_order = [
                "rf_combined", "rf_nslkdd", "random_forest_ids",
                "lstm_combined", "lstm_nslkdd",
                "cnn_combined", "cnn_nslkdd",
            ]
            for pref in preference_order:
                if pref in self._metadata:
                    self._active_model = pref
                    break
            if not self._active_model:
                self._active_model = next(iter(self._metadata))
            
            log.info("Active model: %s", self._active_model)

    def _load_model(self, key: str):
        """Load a model into memory (lazy loading)."""
        if key in self._models:
            return self._models[key]

        meta = self._metadata.get(key)
        if not meta:
            raise ValueError(f"Unknown model: {key}")

        model_path = Path(meta["model_path"])
        model_type = meta.get("model_type", "")

        try:
            if model_path.suffix == ".pkl":
                model = joblib.load(model_path)
            elif model_path.suffix in (".keras", ".h5"):
                import tensorflow as tf
                model = tf.keras.models.load_model(model_path)
            else:
                raise ValueError(f"Unknown model format: {model_path.suffix}")

            self._models[key] = model
            log.info("Loaded model: %s", key)
            return model
        except Exception as e:
            log.error("Failed to load model %s: %s", key, e)
            raise

    def predict(self, X: np.ndarray, model_key: Optional[str] = None) -> np.ndarray:
        """
        Run inference with the specified (or active) model.
        
        Args:
            X: Feature array, shape (1, 12) — already scaled
            model_key: Model to use (default: active model)
        
        Returns:
            Probability array, shape (1, n_classes)
        """
        key = model_key or self._active_model
        if not key:
            raise RuntimeError("No model available")

        model = self._load_model(key)
        meta = self._metadata[key]
        model_type = meta.get("model_type", "")

        if model_type == "RandomForestClassifier":
            return model.predict_proba(X)
        elif model_type in ("LSTM", "CNN"):
            # Reshape for Keras models
            if model_type == "LSTM":
                X_in = X.reshape((X.shape[0], 1, X.shape[1]))
            else:  # CNN
                X_in = X.reshape((X.shape[0], X.shape[1], 1))
            return model.predict(X_in, verbose=0)
        else:
            # Fallback: try sklearn-like predict_proba
            if hasattr(model, "predict_proba"):
                return model.predict_proba(X)
            raise ValueError(f"Don't know how to predict with model type: {model_type}")

    def predict_class(self, X: np.ndarray, model_key: Optional[str] = None) -> int:
        """Returns predicted class index."""
        proba = self.predict(X, model_key)
        return int(np.argmax(proba[0]))

    def list_models(self) -> List[Dict[str, Any]]:
        """List all available models with metadata."""
        result = []
        for key, meta in self._metadata.items():
            result.append({
                "key": key,
                "name": meta.get("model_name", key),
                "type": meta.get("model_type", "unknown"),
                "accuracy": meta.get("accuracy", 0),
                "dataset": meta.get("dataset", "unknown"),
                "is_active": key == self._active_model,
                "training_samples": meta.get("training_samples", 0),
                "training_time": meta.get("training_time_seconds", 0),
            })
        return sorted(result, key=lambda x: -x["accuracy"])

    def get_active(self) -> Optional[str]:
        """Return the active model key."""
        return self._active_model

    def get_active_metadata(self) -> Dict[str, Any]:
        """Return metadata for the active model."""
        if self._active_model and self._active_model in self._metadata:
            meta = self._metadata[self._active_model].copy()
            meta["is_active"] = True
            return meta
        return {"key": None, "name": "none", "is_active": False}

    def set_active(self, key: str) -> Dict[str, Any]:
        """Switch the active model. Pre-loads it to verify it works."""
        if key not in self._metadata:
            available = list(self._metadata.keys())
            raise ValueError(f"Unknown model: {key}. Available: {available}")

        # Pre-load to ensure it works
        self._load_model(key)
        self._active_model = key
        log.info("Switched active model to: %s", key)
        return self.get_active_metadata()

    def get_n_classes(self, model_key: Optional[str] = None) -> int:
        """Get number of classes for a model."""
        key = model_key or self._active_model
        meta = self._metadata.get(key, {})
        return meta.get("n_classes", 23)  # default to NSL-KDD 23 classes

    def refresh(self):
        """Re-scan models directory for new models."""
        self._models.clear()
        self._metadata.clear()
        self._active_model = None
        self._scan_models()


# ── Singleton ────────────────────────────────────────────────────────────────
model_manager = ModelManager()
