"""
Configuration file for IDS-ML Backend
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
	"""Application configuration"""
	
	# Base directories
	BASE_DIR = Path(__file__).resolve().parent.parent
	MODEL_DIR = BASE_DIR / "models"
	DATA_DIR = BASE_DIR / "data"
	
	# Model paths
	MODEL_PATH = MODEL_DIR / "random_forest_ids.pkl"
	PREPROCESSOR_PATH = DATA_DIR / "processed" / "preprocessed_data.pkl"
	METADATA_PATH = MODEL_DIR / "model_metadata.json"
	
	# API Configuration
	API_TITLE = "IDS-ML System API"
	API_VERSION = "1.0.0"
	API_DESCRIPTION = "Intrusion Detection System using Machine Learning"
	API_HOST = os.getenv("API_HOST", "0.0.0.0")
	API_PORT = int(os.getenv("API_PORT", 8000))
	
	# CORS
	CORS_ORIGINS = [
		"http://localhost",
		"http://localhost:3000",
		"http://localhost:8000",
	]
	
	# Logging
	LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
	LOG_FILE = BASE_DIR / "logs" / "app.log"
	
	# Model settings
	CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", 0.7))
	
	# Database (for future use)
	DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ids_ml.db")


config = Config()
