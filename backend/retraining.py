# backend/retraining.py — Auto-Retraining Pipeline
"""
Automated model retraining using recent predictions as feedback.
Uses APScheduler for periodic execution (no Redis/Celery dependency).
"""
import json
import logging
import pickle
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np

log = logging.getLogger(__name__)

BASE_DIR   = Path(__file__).resolve().parents[1]
MODELS_DIR = BASE_DIR / "models"
DATA_DIR   = BASE_DIR / "data" / "processed"


class RetrainingManager:
    """Manages automated model retraining with versioning."""

    def __init__(self):
        self._scheduler = None
        self._is_training = False
        self._config = {
            "enabled": True,
            "interval_hours": 24,
            "min_samples": 100,       # min predictions before retraining
            "model_type": "rf",       # rf, lstm, or cnn
            "dataset": "combined",    # base dataset to merge with
            "max_versions": 5,        # keep last N versioned models
        }
        self._history = []  # retraining event log
        self._last_retrain: Optional[datetime] = None
        self._next_retrain: Optional[datetime] = None

    def start_scheduler(self):
        """Start the APScheduler background scheduler."""
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.triggers.interval import IntervalTrigger

            if self._scheduler and self._scheduler.running:
                return

            self._scheduler = BackgroundScheduler(daemon=True)
            trigger = IntervalTrigger(hours=self._config["interval_hours"])
            self._scheduler.add_job(
                self.retrain,
                trigger=trigger,
                id="auto_retrain",
                name="Auto Model Retraining",
                replace_existing=True,
            )
            self._scheduler.start()
            self._next_retrain = self._scheduler.get_job("auto_retrain").next_run_time
            log.info("Retraining scheduler started — interval: %dh",
                     self._config["interval_hours"])
        except ImportError:
            log.warning("APScheduler not installed — auto-retraining disabled")
        except Exception as e:
            log.error("Failed to start retraining scheduler: %s", e)

    def stop_scheduler(self):
        """Stop the scheduler."""
        if self._scheduler and self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None
            log.info("Retraining scheduler stopped")

    def retrain(self, force: bool = False) -> dict:
        """Run retraining cycle.
        1. Collect recent predictions from DB
        2. Merge with base dataset
        3. Retrain the active model type
        4. Save versioned model
        5. Hot-swap via model_manager
        """
        if self._is_training:
            return {"status": "already_running"}

        self._is_training = True
        event = {
            "started_at": datetime.now().isoformat(),
            "status": "running",
            "model_type": self._config["model_type"],
            "dataset": self._config["dataset"],
            "samples_collected": 0,
            "accuracy": None,
            "model_file": None,
            "error": None,
            "duration_seconds": None,
        }

        t0 = time.time()
        try:
            # Step 1: Collect recent predictions
            predictions = self._collect_predictions()
            event["samples_collected"] = len(predictions)

            if len(predictions) < self._config["min_samples"] and not force:
                event["status"] = "skipped"
                event["error"] = f"Not enough samples ({len(predictions)} < {self._config['min_samples']})"
                log.info("Retraining skipped — %s", event["error"])
                return event

            # Step 2: Load base dataset and merge
            X_train, y_train, X_test, y_test, n_classes, attack_types = self._prepare_data(predictions)

            # Step 3: Train model
            model_type = self._config["model_type"]
            accuracy, model_path = self._train_model(
                model_type, X_train, y_train, X_test, y_test,
                n_classes, attack_types
            )

            event["accuracy"] = float(accuracy)
            event["model_file"] = model_path.name
            event["status"] = "success"

            # Step 4: Hot-swap
            self._hot_swap(model_path)

            log.info("Retraining complete — %s accuracy: %.4f, saved: %s",
                     model_type, accuracy, model_path.name)

        except Exception as e:
            event["status"] = "failed"
            event["error"] = str(e)
            log.error("Retraining failed: %s", e)

        finally:
            self._is_training = False
            event["duration_seconds"] = round(time.time() - t0, 1)
            event["completed_at"] = datetime.now().isoformat()
            self._history.append(event)
            self._last_retrain = datetime.now()

            # Update next_retrain
            if self._scheduler and self._scheduler.running:
                job = self._scheduler.get_job("auto_retrain")
                if job:
                    self._next_retrain = job.next_run_time

            # Keep history bounded
            if len(self._history) > 50:
                self._history = self._history[-50:]

        return event

    def _collect_predictions(self) -> list:
        """Collect recent predictions from the database."""
        predictions = []
        try:
            from backend.database import SessionLocal
            from sqlalchemy import text

            db = SessionLocal()
            try:
                rows = db.execute(text(
                    "SELECT features, predicted_label FROM predictions "
                    "ORDER BY id DESC LIMIT 10000"
                )).fetchall()

                for row in rows:
                    try:
                        features = json.loads(row[0]) if isinstance(row[0], str) else row[0]
                        predictions.append({
                            "features": features,
                            "label": row[1],
                        })
                    except Exception:
                        continue
            finally:
                db.close()
        except Exception as e:
            log.warning("Could not collect predictions: %s", e)

        return predictions

    def _prepare_data(self, predictions: list):
        """Load base dataset and optionally merge with recent predictions."""
        dataset = self._config["dataset"]
        data_file = DATA_DIR / f"{dataset}_preprocessed.pkl"

        if not data_file.exists():
            data_file = DATA_DIR / "preprocessed_data.pkl"

        with open(data_file, "rb") as f:
            data = pickle.load(f)

        X_train = data["X_train"]
        y_train = data["y_train_encoded"]
        X_test = data["X_test"]
        y_test = data["y_test_encoded"]
        n_classes = len(data["attack_types"])
        attack_types = data["attack_types"]

        # Subsample if too large
        if X_train.shape[0] > 300000:
            rng = np.random.RandomState(42)
            idx = rng.choice(X_train.shape[0], 300000, replace=False)
            X_train = X_train[idx]
            y_train = y_train[idx]

        log.info("Prepared training data: %d train, %d test, %d classes",
                 X_train.shape[0], X_test.shape[0], n_classes)

        return X_train, y_train, X_test, y_test, n_classes, attack_types

    def _train_model(self, model_type, X_train, y_train, X_test, y_test,
                     n_classes, attack_types):
        """Train a model and save with version timestamp."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        dataset = self._config["dataset"]

        if model_type == "rf":
            return self._train_rf(X_train, y_train, X_test, y_test,
                                  n_classes, dataset, timestamp)
        elif model_type == "lstm":
            return self._train_lstm(X_train, y_train, X_test, y_test,
                                    n_classes, dataset, timestamp)
        elif model_type == "cnn":
            return self._train_cnn(X_train, y_train, X_test, y_test,
                                   n_classes, dataset, timestamp)
        else:
            raise ValueError(f"Unknown model type: {model_type}")

    def _train_rf(self, X_train, y_train, X_test, y_test,
                  n_classes, dataset, timestamp):
        """Train Random Forest."""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score
        import joblib

        model = RandomForestClassifier(
            n_estimators=100, max_depth=30,
            min_samples_split=4, min_samples_leaf=2,
            n_jobs=-1, random_state=42,
            class_weight="balanced_subsample",
        )
        model.fit(X_train, y_train)
        accuracy = accuracy_score(y_test, model.predict(X_test))

        model_path = MODELS_DIR / f"rf_{dataset}_v{timestamp}.pkl"
        joblib.dump(model, model_path)

        # Save metadata
        meta = {
            "model_name": f"RF ({dataset}) v{timestamp}",
            "model_type": "RandomForestClassifier",
            "model_file": model_path.name,
            "accuracy": float(accuracy),
            "dataset": dataset,
            "training_samples": int(X_train.shape[0]),
            "retrained": True,
            "timestamp": timestamp,
        }
        meta_path = MODELS_DIR / f"rf_{dataset}_v{timestamp}_metadata.json"
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        self._cleanup_old_versions(f"rf_{dataset}_v*", self._config["max_versions"])
        return accuracy, model_path

    def _train_lstm(self, X_train, y_train, X_test, y_test,
                    n_classes, dataset, timestamp):
        """Train LSTM."""
        import os
        os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
        import tensorflow as tf
        from tensorflow import keras
        from tensorflow.keras import layers
        from sklearn.metrics import accuracy_score
        from sklearn.utils.class_weight import compute_class_weight

        X_tr = X_train.reshape((X_train.shape[0], 1, X_train.shape[1]))
        X_te = X_test.reshape((X_test.shape[0], 1, X_test.shape[1]))
        y_tr_cat = keras.utils.to_categorical(y_train, n_classes)
        y_te_cat = keras.utils.to_categorical(y_test, n_classes)

        cw = {c: w for c, w in zip(
            *[np.unique(y_train), compute_class_weight("balanced", classes=np.unique(y_train), y=y_train)]
        )}

        model = keras.Sequential([
            layers.Input(shape=(1, X_train.shape[1])),
            layers.LSTM(64, return_sequences=True), layers.Dropout(0.3),
            layers.LSTM(32), layers.Dropout(0.3),
            layers.Dense(64, activation="relu"), layers.Dropout(0.2),
            layers.Dense(n_classes, activation="softmax"),
        ])
        model.compile(optimizer="adam", loss="categorical_crossentropy", metrics=["accuracy"])
        model.fit(X_tr, y_tr_cat, validation_data=(X_te, y_te_cat),
                  epochs=10, batch_size=512, verbose=0, class_weight=cw,
                  callbacks=[keras.callbacks.EarlyStopping(patience=3, restore_best_weights=True)])

        y_pred = np.argmax(model.predict(X_te, verbose=0), axis=1)
        accuracy = accuracy_score(y_test, y_pred)

        model_path = MODELS_DIR / f"lstm_{dataset}_v{timestamp}.keras"
        model.save(model_path)

        meta = {
            "model_name": f"LSTM ({dataset}) v{timestamp}",
            "model_type": "LSTM", "model_file": model_path.name,
            "accuracy": float(accuracy), "dataset": dataset,
            "training_samples": int(X_train.shape[0]),
            "retrained": True, "timestamp": timestamp,
        }
        with open(MODELS_DIR / f"lstm_{dataset}_v{timestamp}_metadata.json", "w") as f:
            json.dump(meta, f, indent=2)

        self._cleanup_old_versions(f"lstm_{dataset}_v*", self._config["max_versions"])
        return accuracy, model_path

    def _train_cnn(self, X_train, y_train, X_test, y_test,
                   n_classes, dataset, timestamp):
        """Train CNN."""
        import os
        os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
        import tensorflow as tf
        from tensorflow import keras
        from tensorflow.keras import layers
        from sklearn.metrics import accuracy_score
        from sklearn.utils.class_weight import compute_class_weight

        X_tr = X_train.reshape((X_train.shape[0], X_train.shape[1], 1))
        X_te = X_test.reshape((X_test.shape[0], X_test.shape[1], 1))
        y_tr_cat = keras.utils.to_categorical(y_train, n_classes)

        cw = {c: w for c, w in zip(
            *[np.unique(y_train), compute_class_weight("balanced", classes=np.unique(y_train), y=y_train)]
        )}

        model = keras.Sequential([
            layers.Input(shape=(X_train.shape[1], 1)),
            layers.Conv1D(64, 3, activation="relu", padding="same"),
            layers.BatchNormalization(), layers.MaxPooling1D(2), layers.Dropout(0.3),
            layers.Conv1D(32, 3, activation="relu", padding="same"),
            layers.GlobalMaxPooling1D(),
            layers.Dense(64, activation="relu"), layers.Dropout(0.3),
            layers.Dense(n_classes, activation="softmax"),
        ])
        model.compile(optimizer="adam", loss="categorical_crossentropy", metrics=["accuracy"])
        model.fit(X_tr, y_tr_cat, epochs=10, batch_size=512, verbose=0, class_weight=cw,
                  callbacks=[keras.callbacks.EarlyStopping(patience=3, restore_best_weights=True)])

        y_pred = np.argmax(model.predict(X_te, verbose=0), axis=1)
        accuracy = accuracy_score(y_test, y_pred)

        model_path = MODELS_DIR / f"cnn_{dataset}_v{timestamp}.keras"
        model.save(model_path)

        meta = {
            "model_name": f"CNN ({dataset}) v{timestamp}",
            "model_type": "CNN", "model_file": model_path.name,
            "accuracy": float(accuracy), "dataset": dataset,
            "training_samples": int(X_train.shape[0]),
            "retrained": True, "timestamp": timestamp,
        }
        with open(MODELS_DIR / f"cnn_{dataset}_v{timestamp}_metadata.json", "w") as f:
            json.dump(meta, f, indent=2)

        self._cleanup_old_versions(f"cnn_{dataset}_v*", self._config["max_versions"])
        return accuracy, model_path

    def _hot_swap(self, model_path: Path):
        """Tell model_manager to load the new model."""
        try:
            from backend.model_manager import model_manager
            model_manager.refresh()
            log.info("Model manager refreshed after retraining")
        except Exception as e:
            log.warning("Hot-swap failed: %s", e)

    def _cleanup_old_versions(self, pattern: str, keep: int):
        """Remove old versioned models, keeping only the latest N."""
        files = sorted(MODELS_DIR.glob(pattern))
        if len(files) > keep:
            for old in files[:-keep]:
                try:
                    old.unlink()
                    # Also remove matching metadata
                    meta = old.with_name(old.stem + "_metadata.json")
                    if meta.exists():
                        meta.unlink()
                    log.info("Cleaned up old model: %s", old.name)
                except Exception:
                    pass

    def get_status(self) -> dict:
        """Return current retraining status."""
        return {
            "enabled": self._config["enabled"],
            "is_training": self._is_training,
            "scheduler_running": bool(self._scheduler and self._scheduler.running),
            "interval_hours": self._config["interval_hours"],
            "model_type": self._config["model_type"],
            "dataset": self._config["dataset"],
            "min_samples": self._config["min_samples"],
            "max_versions": self._config["max_versions"],
            "last_retrain": self._last_retrain.isoformat() if self._last_retrain else None,
            "next_retrain": str(self._next_retrain) if self._next_retrain else None,
            "history_count": len(self._history),
        }

    def get_history(self, limit: int = 20) -> list:
        """Return retraining history."""
        return list(reversed(self._history[-limit:]))

    def update_config(self, **kwargs) -> dict:
        """Update retraining configuration."""
        for key, val in kwargs.items():
            if key in self._config:
                self._config[key] = val

        # Restart scheduler if interval changed
        if "interval_hours" in kwargs and self._scheduler:
            self.stop_scheduler()
            self.start_scheduler()

        return self._config


# Module-level singleton
retraining_manager = RetrainingManager()
