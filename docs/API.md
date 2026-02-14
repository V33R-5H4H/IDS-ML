# API Documentation - IDS-ML v1.0

## Base URL
```
http://localhost:8000
```

## Endpoints

### 1. Health Check
**GET** `/health`

**Response:**
```json
{
  "status": "healthy",
  "model_loaded": true
}
```

---

### 2. Root
**GET** `/`

**Response:**
```json
{
  "message": "IDS-ML System API",
  "version": "1.0.0",
  "status": "running"
}
```

---

### 3. Model Information
**GET** `/model/info`

**Response:**
```json
{
  "model_name": "Random Forest IDS v1.0",
  "accuracy": 0.8591,
  "version": "1.0.0",
  "features": [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "logged_in",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "dst_host_srv_count"
  ]
}
```

---

### 4. Make Prediction
**POST** `/predict`

**Request Body:**
```json
{
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
```

**Response:**
```json
{
  "prediction": "normal",
  "confidence": 0.9234,
  "is_attack": false,
  "severity": "None",
  "model_version": "1.0.0"
}
```

**Attack Detection Response:**
```json
{
  "prediction": "neptune",
  "confidence": 0.9876,
  "is_attack": true,
  "severity": "High",
  "model_version": "1.0.0"
}
```

---

### 5. System Statistics
**GET** `/stats`

**Response:**
```json
{
  "model_accuracy": 0.8591,
  "n_estimators": 300,
  "features_count": 12,
  "attack_types": 23
}
```

---

## Interactive API Docs

FastAPI provides automatic interactive documentation:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

---

## Example Usage

### Python
```python
import requests

url = "http://localhost:8000/predict"
data = {
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

response = requests.post(url, json=data)
result = response.json()

print(f"Prediction: {result['prediction']}")
print(f"Is Attack: {result['is_attack']}")
print(f"Confidence: {result['confidence']:.2%}")
print(f"Severity: {result['severity']}")
```

### cURL
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
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
  }'
```

### JavaScript (Fetch API)
```javascript
const predictTraffic = async (features) => {
  const response = await fetch('http://localhost:8000/predict', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(features)
  });

  const result = await response.json();
  return result;
};

// Usage
const features = {
  duration: 0,
  protocol_type: "tcp",
  service: "http",
  flag: "SF",
  src_bytes: 181,
  dst_bytes: 5450,
  logged_in: 1,
  count: 8,
  srv_count: 8,
  serror_rate: 0.0,
  srv_serror_rate: 0.0,
  dst_host_srv_count: 9
};

predictTraffic(features).then(result => {
  console.log(result);
});
```

---

## Feature Descriptions

| Feature | Type | Description | Example |
|---------|------|-------------|---------|
| duration | int | Length of connection (seconds) | 0 |
| protocol_type | string | Protocol used (tcp, udp, icmp) | "tcp" |
| service | string | Network service | "http" |
| flag | string | Connection flag | "SF" |
| src_bytes | int | Bytes sent from source | 181 |
| dst_bytes | int | Bytes sent to destination | 5450 |
| logged_in | int | 1 if logged in, 0 otherwise | 1 |
| count | int | Connections to same host | 8 |
| srv_count | int | Connections to same service | 8 |
| serror_rate | float | % of connections with SYN errors | 0.0 |
| srv_serror_rate | float | % service connections with SYN errors | 0.0 |
| dst_host_srv_count | int | Connections to destination host | 9 |

---

## Response Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 422 | Validation Error (invalid input) |
| 500 | Server Error |
| 503 | Service Unavailable (model not loaded) |

---

## Error Handling

**Invalid Input Example:**
```json
{
  "detail": [
    {
      "loc": ["body", "protocol_type"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

**Server Error Example:**
```json
{
  "detail": "Prediction error: Model not loaded"
}
```

---

## Rate Limiting

Currently no rate limiting is implemented. For production deployment, consider:
- API Gateway (AWS API Gateway, Kong)
- Rate limiting middleware
- Authentication tokens

---

## Security Considerations

**v1.0 (Current):**
- ✅ CORS enabled for local development
- ⚠️ No authentication required
- ⚠️ No rate limiting
- ⚠️ No input validation beyond Pydantic

**v2.0 (Planned):**
- 🔐 JWT authentication
- 🔒 API key management
- 🚦 Rate limiting
- 🛡️ Enhanced input validation
- 📊 Request logging

---

## Testing

Use the built-in Swagger UI for interactive testing:

1. Start the backend: `python backend/main.py`
2. Open browser: http://localhost:8000/docs
3. Click "Try it out" on any endpoint
4. Fill in parameters and execute

---

## Contact & Support

For issues or questions:
- Check logs in `logs/app.log`
- Review error messages in terminal
- Test with `/health` endpoint first
