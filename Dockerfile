# Use official lightweight Python image
FROM python:3.10-slim

# Install system dependencies required for ML & PCAP processing
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside the container
WORKDIR /app

# Copy requirements first to leverage Docker layer caching
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code, scripts, and model metadata
# We copy them into the exact paths expected by the python environment
COPY backend/ /app/backend/
COPY models/ /app/models/
COPY scripts/ /app/scripts/

# Set environment variables for FastAPI to locate the app context
ENV PYTHONPATH=/app
ENV HOST=0.0.0.0
ENV PORT=8000

# Expose the API port
EXPOSE 8000

# Run Uvicorn server production mode
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
