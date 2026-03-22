# backend/Dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Set work directory
WORKDIR /app

# Install system dependencies (needed for scapy/pcap)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    gcc \
    python3-dev \
    libpq-dev \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .

# Install explicitly the newly added deps (aiohttp, aiosmtplib) + others
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install aiohttp aiosmtplib gunicorn uvicorn psycopg2-binary

# Copy project
COPY . /app/backend/

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
