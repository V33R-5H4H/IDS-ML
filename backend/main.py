"""
FastAPI Main Application with Stats Tracking
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List
from contextlib import asynccontextmanager
import sys
from pathlib import Path
from datetime import datetime

sys.path.append(str(Path(__file__).resolve().parents[1]))

from backend.config import config
from scripts.predict import IDSPredictor

# Global variables
predictor = None
prediction_history = []
stats_counter = {
    "total_predictions": 0,
    "attacks_detected": 0,
    "normal_traffic": 0,
    "last_updated": None
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model on startup, cleanup on shutdown"""
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

    yield
    print("Shutting down API...")

app = FastAPI(
    title=config.API_TITLE,
    version=config.API_VERSION,
    description=config.API_DESCRIPTION,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

    model_config = {
        "json_schema_extra": {
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
    }

class PredictionResponse(BaseModel):
    """Prediction response"""
    prediction: str
    confidence: float
    is_attack: bool
    severity: str
    version: str
    timestamp: str = None

    model_config = {"protected_namespaces": ()}

class ModelInfo(BaseModel):
    """Model information"""
    name: str
    accuracy: float
    version: str
    features: List[str]
    model_config = {"protected_namespaces": ()}

class SystemStats(BaseModel):
    """System statistics"""
    total_predictions: int
    attacks_detected: int
    normal_traffic: int
    model_accuracy: float
    last_updated: str = None

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
        name=predictor.metadata['model_name'],
        accuracy=predictor.metadata['accuracy'],
        version=config.API_VERSION,
        features=predictor.feature_names
    )

@app.post("/predict", response_model=PredictionResponse)
async def predict(features: FlowFeatures):
    """Make prediction on network flow"""
    global prediction_history, stats_counter

    if predictor is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        feature_dict = features.model_dump()
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

        # Create response
        response = PredictionResponse(
            prediction=result['prediction'],
            confidence=result['confidence'],
            is_attack=result['is_attack'],
            severity=severity,
            version=config.API_VERSION,
            timestamp=datetime.now().isoformat()
        )

        # Update stats
        stats_counter["total_predictions"] += 1
        if result['is_attack']:
            stats_counter["attacks_detected"] += 1
        else:
            stats_counter["normal_traffic"] += 1
        stats_counter["last_updated"] = datetime.now().isoformat()

        # Add to history (keep last 50)
        prediction_history.append({
            "timestamp": response.timestamp,
            "prediction": response.prediction,
            "confidence": response.confidence,
            "is_attack": response.is_attack,
            "severity": severity
        })
        if len(prediction_history) > 50:
            prediction_history = prediction_history[-50:]

        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

@app.get("/stats", response_model=SystemStats)
async def get_stats():
    """Get system statistics with prediction counts"""
    if predictor is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    return SystemStats(
        total_predictions=stats_counter["total_predictions"],
        attacks_detected=stats_counter["attacks_detected"],
        normal_traffic=stats_counter["normal_traffic"],
        model_accuracy=predictor.metadata['accuracy'],
        last_updated=stats_counter["last_updated"]
    )

@app.get("/history")
async def get_history():
    """Get recent prediction history"""
    return {
        "count": len(prediction_history),
        "predictions": prediction_history[-20:]  # Last 20
    }

@app.post("/reset-stats")
async def reset_stats():
    """Reset statistics (for testing)"""
    global stats_counter, prediction_history
    stats_counter = {
        "total_predictions": 0,
        "attacks_detected": 0,
        "normal_traffic": 0,
        "last_updated": datetime.now().isoformat()
    }
    prediction_history = []
    return {"message": "Stats reset successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.API_HOST, port=config.API_PORT)
