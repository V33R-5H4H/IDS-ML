"""
FastAPI Main Application for IDS-ML System
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, List
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from backend.config import config
from scripts.predict import IDSPredictor

# Initialize FastAPI app
app = FastAPI(
    title=config.API_TITLE,
    version=config.API_VERSION,
    description=config.API_DESCRIPTION
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize predictor
predictor = None

@app.on_event("startup")
async def startup_event():
    """Load model on startup"""
    global predictor
    try:
        predictor = IDSPredictor(
            model_path=config.MODEL_PATH,
            preprocessor_path=config.PREPROCESSOR_PATH
        )
        print("✅ Model loaded successfully")
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        raise

# Pydantic models for request/response
class FlowFeatures(BaseModel):
    """Network flow features for prediction"""
    duration: int = Field(default=0, description="Duration of connection in seconds")
    protocol_type: str = Field(..., description="Protocol type (tcp, udp, icmp)")
    service: str = Field(..., description="Network service (http, ftp, etc.)")
    flag: str = Field(..., description="Connection flag (SF, S0, REJ, etc.)")
    src_bytes: int = Field(..., description="Bytes sent from source")
    dst_bytes: int = Field(..., description="Bytes sent to destination")
    logged_in: int = Field(default=0, description="1 if logged in, 0 otherwise")
    count: int = Field(..., description="Number of connections to same host")
    srv_count: int = Field(..., description="Number of connections to same service")
    serror_rate: float = Field(..., description="% of connections with SYN errors")
    srv_serror_rate: float = Field(..., description="% of connections with SYN errors (service)")
    dst_host_srv_count: int = Field(..., description="Count of connections to destination host")
    
    class Config:
        schema_extra = {
            "example": {
                "duration": 0,
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
                "src_bytes": 181,
                "dst_bytes": 5450,
                "logged_in": 1,
                "count": 8,
                "srv_count": 8,
                "serror_rate": 0.0,
                "srv_serror_rate": 0.0,
                "dst_host_srv_count": 9
            }
        }

class PredictionResponse(BaseModel):
    """Prediction response"""
    prediction: str
    confidence: float
    is_attack: bool
    severity: str
    model_version: str

class ModelInfo(BaseModel):
    """Model information"""
    model_name: str
    accuracy: float
    version: str
    features: List[str]

# API Endpoints
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "IDS-ML System API",
        "version": config.API_VERSION,
        "status": "running"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "model_loaded": predictor is not None
    }

@app.get("/model/info", response_model=ModelInfo)
async def get_model_info():
    """Get model information"""
    if predictor is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    return ModelInfo(
        model_name=predictor.metadata['model_name'],
        accuracy=predictor.metadata['accuracy'],
        version=config.API_VERSION,
        features=predictor.feature_names
    )

@app.post("/predict", response_model=PredictionResponse)
async def predict(features: FlowFeatures):
    """Make prediction on network flow"""
    if predictor is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        # Convert to dict
        feature_dict = features.dict()
        
        # Make prediction
        result = predictor.predict_raw(feature_dict)
        
        # Determine severity
        if not result['is_attack']:
            severity = "None"
        elif result['confidence'] >= 0.9:
            severity = "High"
        elif result['confidence'] >= 0.7:
            severity = "Medium"
        else:
            severity = "Low"
        
        return PredictionResponse(
            prediction=result['prediction'],
            confidence=result['confidence'],
            is_attack=result['is_attack'],
            severity=severity,
            model_version=config.API_VERSION
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

@app.get("/stats")
async def get_stats():
    """Get system statistics"""
    if predictor is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    return {
        "model_accuracy": predictor.metadata['accuracy'],
        "n_estimators": predictor.metadata.get('n_estimators', 'N/A'),
        "features_count": len(predictor.feature_names),
        "attack_types": len(predictor.label_encoder_target.classes_)
    }

# Run with: uvicorn backend.main:app --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.API_HOST, port=config.API_PORT)
