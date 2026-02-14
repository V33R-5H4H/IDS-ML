"""
Prediction script for IDS-ML System
Loads trained model and makes predictions
"""

import joblib
import pickle
import numpy as np
from pathlib import Path
import json

class IDSPredictor:
    def __init__(self, model_path=None, preprocessor_path=None):
        """Initialize predictor with trained model and preprocessor"""
        base_dir = Path(__file__).resolve().parents[1]
        
        # Load model
        if model_path is None:
            model_path = base_dir / "models" / "random_forest_ids.pkl"
        self.model = joblib.load(model_path)
        
        # Load preprocessor data
        if preprocessor_path is None:
            preprocessor_path = base_dir / "data" / "processed" / "preprocessed_data.pkl"
        
        with open(preprocessor_path, 'rb') as f:
            data = pickle.load(f)
            self.scaler = data['scaler']
            self.label_encoders = data['label_encoders']
            self.label_encoder_target = data['label_encoder_target']
            self.feature_names = data['feature_names']
        
        # Load metadata
        metadata_path = model_path.parent / "model_metadata.json"
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)
        
        print(f"✅ Model loaded: {self.metadata['model_name']}")
        print(f"   Accuracy: {self.metadata['accuracy']:.4f}")
    
    def preprocess_features(self, raw_features):
        """
        Preprocess raw features (encode categorical, scale numerical)
        
        Args:
            raw_features: dict with feature names and raw values
                Example: {
                    'duration': 100,
                    'protocol_type': 'tcp',
                    'service': 'http',
                    'flag': 'SF',
                    'src_bytes': 5000,
                    'dst_bytes': 1000,
                    'logged_in': 1,
                    'count': 10,
                    'srv_count': 5,
                    'serror_rate': 0.0,
                    'srv_serror_rate': 0.0,
                    'dst_host_srv_count': 100
                }
        
        Returns:
            processed_features: numpy array ready for prediction
        """
        # Create feature array in correct order
        feature_values = []
        
        for feature in self.feature_names:
            value = raw_features.get(feature, 0)
            
            # Encode categorical features
            if feature in self.label_encoders:
                encoder = self.label_encoders[feature]
                if value in encoder.classes_:
                    value = encoder.transform([value])[0]
                else:
                    value = -1  # Unknown category
            
            feature_values.append(value)
        
        # Convert to numpy array and scale
        features_array = np.array(feature_values).reshape(1, -1)
        features_scaled = self.scaler.transform(features_array)
        
        return features_scaled
    
    def predict(self, features):
        """
        Make prediction on preprocessed features
        
        Args:
            features: numpy array of shape (n_samples, 12)
        
        Returns:
            predictions: array of predicted class indices
            probabilities: array of prediction probabilities
        """
        predictions = self.model.predict(features)
        probabilities = self.model.predict_proba(features)
        
        return predictions, probabilities
    
    def predict_raw(self, raw_features):
        """
        Make prediction on raw feature dictionary
        
        Args:
            raw_features: dict with feature names and raw values
        
        Returns:
            dict with prediction results
        """
        # Preprocess
        features = self.preprocess_features(raw_features)
        
        # Predict
        prediction_idx = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        confidence = probabilities[prediction_idx]
        
        # Decode prediction
        prediction_label = self.label_encoder_target.inverse_transform([prediction_idx])[0]
        
        return {
            'prediction': prediction_label,
            'prediction_index': int(prediction_idx),
            'confidence': float(confidence),
            'is_attack': prediction_label != 'normal',
            'all_probabilities': {
                self.label_encoder_target.inverse_transform([i])[0]: float(prob)
                for i, prob in enumerate(probabilities)
            }
        }

# Example usage
if __name__ == "__main__":
    # Test the predictor
    predictor = IDSPredictor()
    
    # Example raw features
    test_features = {
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
    
    result = predictor.predict_raw(test_features)
    
    print("\n" + "="*60)
    print("PREDICTION RESULT")
    print("="*60)
    print(f"Prediction: {result['prediction']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Is Attack: {result['is_attack']}")
    print(f"\nTop 5 probabilities:")
    sorted_probs = sorted(result['all_probabilities'].items(),
                         key=lambda x: x[1], reverse=True)
    for attack, prob in sorted_probs[:5]:
        print(f"  {attack:20s}: {prob:.4f}")
