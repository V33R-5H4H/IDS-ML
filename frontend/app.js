// IDS-ML Dashboard JavaScript
const API_URL = 'http://localhost:8000';

let totalPredictions = 0;
let attacksDetected = 0;
let recentPredictions = [];

// Load model info on page load
async function loadModelInfo() {
    try {
        const response = await fetch(`${API_URL}/model/info`);
        const data = await response.json();

        document.getElementById('model-accuracy').textContent = 
            (data.accuracy * 100).toFixed(2) + '%';
        document.getElementById('model-version').textContent = data.version;
        document.getElementById('model-info').textContent = 
            `${data.name} - Accuracy: ${(data.accuracy * 100).toFixed(2)}%`;

        // Display features
        const featuresList = document.getElementById('features-list');
        featuresList.innerHTML = data.features.map(f => `<li>${f}</li>`).join('');
    } catch (error) {
        console.error('Error loading model info:', error);
        document.getElementById('model-info').textContent = 'Error loading model information';
        document.getElementById('model-accuracy').textContent = 'N/A';
        document.getElementById('model-version').textContent = 'N/A';
    }
}

// Handle prediction form submission
document.getElementById('prediction-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(e.target);
    const features = {
        duration: parseInt(formData.get('duration')),
        protocol_type: formData.get('protocol_type'),
        service: formData.get('service'),
        flag: formData.get('flag'),
        src_bytes: parseInt(formData.get('src_bytes')),
        dst_bytes: parseInt(formData.get('dst_bytes')),
        logged_in: parseInt(formData.get('logged_in')),
        count: parseInt(formData.get('count')),
        srv_count: parseInt(formData.get('srv_count')),
        serror_rate: parseFloat(formData.get('serror_rate')),
        srv_serror_rate: parseFloat(formData.get('srv_serror_rate')),
        dst_host_srv_count: parseInt(formData.get('dst_host_srv_count'))
    };

    try {
        const response = await fetch(`${API_URL}/predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(features)
        });

        if (!response.ok) {
            throw new Error('Prediction failed');
        }

        const result = await response.json();

        // Update stats
        totalPredictions++;
        if (result.is_attack) attacksDetected++;

        document.getElementById('total-predictions').textContent = totalPredictions;
        document.getElementById('attacks-detected').textContent = attacksDetected;

        // Display result
        displayPredictionResult(result);

        // Add to recent predictions
        addRecentPrediction(result);

    } catch (error) {
        console.error('Prediction error:', error);
        alert('Error making prediction. Make sure the API is running on ' + API_URL);
    }
});

function displayPredictionResult(result) {
    const resultBox = document.getElementById('prediction-result');
    resultBox.style.display = 'block';
    resultBox.className = result.is_attack ? 'result-box result-attack' : 'result-box result-normal';

    const icon = result.is_attack ? '⚠️' : '✅';
    const status = result.is_attack ? 'ATTACK DETECTED' : 'NORMAL TRAFFIC';
    const severityColor = getSeverityColor(result.severity);

    resultBox.innerHTML = `
        <h5>${icon} ${status}</h5>
        <p><strong>Prediction:</strong> ${result.prediction}</p>
        <p><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(2)}%</p>
        <p><strong>Severity:</strong> <span style="color: ${severityColor}; font-weight: 600;">${result.severity}</span></p>
        <p class="mb-0 small text-muted">Model Version: ${result.version}</p>
    `;
}

function getSeverityColor(severity) {
    switch(severity) {
        case 'High': return '#dc3545';
        case 'Medium': return '#ffc107';
        case 'Low': return '#fd7e14';
        default: return '#28a745';
    }
}

function addRecentPrediction(result) {
    const now = new Date().toLocaleTimeString();
    recentPredictions.unshift({
        time: now,
        prediction: result.prediction,
        confidence: result.confidence,
        is_attack: result.is_attack
    });

    // Keep only last 5
    if (recentPredictions.length > 5) {
        recentPredictions = recentPredictions.slice(0, 5);
    }

    // Update display
    const container = document.getElementById('recent-predictions');
    container.innerHTML = recentPredictions.map(p => `
        <div class="mb-2 p-2 ${p.is_attack ? 'bg-danger-subtle' : 'bg-success-subtle'} rounded">
            <small>
                <strong>${p.time}</strong> - ${p.prediction} 
                (${(p.confidence * 100).toFixed(1)}%)
            </small>
        </div>
    `).join('');
}

// Load model info when page loads
window.addEventListener('DOMContentLoaded', () => {
    loadModelInfo();
    console.log('IDS-ML Dashboard loaded');
    console.log('API URL:', API_URL);
});