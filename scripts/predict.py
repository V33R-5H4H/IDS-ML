"""
Prediction script for IDS-ML System
Clean version - handles feature names properly
"""

import joblib
import pandas as pd
import numpy as np
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parents[1]))

class IDSPredictor:
    """IDS Model Predictor"""

    def __init__(self, model_path='../models/random_forest_ids.pkl',
                 preprocessor_path='../data/processed/preprocessed_data.pkl'):
        """Initialize predictor with model and preprocessor"""

        # Load model
        self.model = joblib.load(model_path)

        # Load preprocessor data
        with open(preprocessor_path, 'rb') as f:
            import pickle
            data = pickle.load(f)

        self.scaler = data['scaler']
        self.label_encoders = data['label_encoders']
        self.label_encoder_target = data['label_encoder_target']
        self.feature_names = data['feature_names']

        # Load metadata
        import json
        metadata_path = Path(model_path).parent / 'model_metadata.json'
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)

        print(f"✅ Model loaded: {self.metadata['model_name']}")
        print(f"   Accuracy: {self.metadata['accuracy']:.4f}")

    def preprocess_features(self, features_dict):
        """Preprocess features using same transformations as training"""

        # Create DataFrame with proper feature names
        df = pd.DataFrame([features_dict], columns=self.feature_names)

        # Encode categorical features
        categorical_features = ['protocol_type', 'service', 'flag']

        for feature in categorical_features:
            if feature in df.columns:
                le = self.label_encoders[feature]
                value = df[feature].iloc[0]

                # Handle unseen values
                if value not in le.classes_:
                    print(f"⚠️  Unknown {feature}: {value}, using default")
                    df[feature] = 0
                else:
                    df[feature] = le.transform([value])[0]

        # Scale features - now with proper feature names
        scaled = self.scaler.transform(df)

        return scaled

    def predict(self, features_dict):
        """Make prediction with full details"""

        # Preprocess
        X = self.preprocess_features(features_dict)

        # Predict
        prediction_encoded = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        confidence = probabilities.max()

        # Decode prediction
        prediction = self.label_encoder_target.inverse_transform([prediction_encoded])[0]

        # Determine if attack
        is_attack = prediction != 'normal'

        # Get top 5 predictions
        top_5_indices = probabilities.argsort()[-5:][::-1]
        top_5_predictions = []

        for idx in top_5_indices:
            attack_type = self.label_encoder_target.inverse_transform([idx])[0]
            prob = probabilities[idx]
            top_5_predictions.append({
                'attack_type': attack_type,
                'probability': prob
            })

        return {
            'prediction': prediction,
            'confidence': confidence,
            'is_attack': is_attack,
            'probabilities': top_5_predictions
        }

    def predict_raw(self, features_dict):
        """Simplified prediction for API"""

        X = self.preprocess_features(features_dict)

        prediction_encoded = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        confidence = probabilities.max()

        prediction = self.label_encoder_target.inverse_transform([prediction_encoded])[0]
        is_attack = prediction != 'normal'

        return {
            'prediction': prediction,
            'confidence': float(confidence),
            'is_attack': is_attack
        }


# Test prediction if run directly
if __name__ == "__main__":
    # Initialize predictor
    predictor = IDSPredictor()

    # Example normal traffic
    normal_traffic = {
        'duration': 0,
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'src_bytes': 181,
        'dst_bytes': 5450,
        'logged_in': 1,
        'count': 8,
        'srv_count': 8,
        'serror_rate': 0.0,
        'srv_serror_rate': 0.0,
        'dst_host_srv_count': 9
    }

    # Make prediction
    result = predictor.predict(normal_traffic)

    print("\n" + "=" * 60)
    print("PREDICTION RESULT")
    print("=" * 60)
    print(f"Prediction: {result['prediction']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Is Attack: {result['is_attack']}")

    print("\nTop 5 probabilities:")
    for pred in result['probabilities']:
        print(f"  {pred['attack_type']:20s}: {pred['probability']:.4f}")

    print("\n" + "=" * 60)
