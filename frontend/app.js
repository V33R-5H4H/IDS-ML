// IDS-ML Dashboard with Live Stats Polling
const API_URL = 'http://localhost:8000';
let pollInterval = null;

// Poll stats every 2 seconds
function startPolling() {
    // Initial load
    loadModelInfo();
    updateStats();
    updateHistory();

    // Poll every 2 seconds
    pollInterval = setInterval(() => {
        updateStats();
        updateHistory();
    }, 2000);
}

// Stop polling
function stopPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
}

// Load model info (once)
async function loadModelInfo() {
    try {
        const response = await fetch(`${API_URL}/model/info`);
        const data = await response.json();

        document.getElementById('model-accuracy').textContent =
            (data.accuracy * 100).toFixed(2) + '%';
        document.getElementById('model-version').textContent = data.version;
        document.getElementById('model-info').textContent =
            `${data.name} - Accuracy: ${(data.accuracy * 100).toFixed(2)}%`;

        const featuresList = document.getElementById('features-list');
        featuresList.innerHTML = data.features.map(f => `<li>${f}</li>`).join('');
    } catch (error) {
        console.error('Error loading model info:', error);
        document.getElementById('model-info').textContent = 'Error loading model information';
    }
}

// Update stats from backend
async function updateStats() {
    try {
        const response = await fetch(`${API_URL}/stats`);
        const data = await response.json();

        // Update counters
        document.getElementById('total-predictions').textContent = data.total_predictions;
        document.getElementById('attacks-detected').textContent = data.attacks_detected;

        // Update accuracy if changed
        if (data.model_accuracy) {
            document.getElementById('model-accuracy').textContent =
                (data.model_accuracy * 100).toFixed(2) + '%';
        }
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

// Update prediction history
async function updateHistory() {
    try {
        const response = await fetch(`${API_URL}/history`);
        const data = await response.json();

        if (data.predictions && data.predictions.length > 0) {
            displayHistory(data.predictions);
        }
    } catch (error) {
        console.error('Error loading history:', error);
    }
}

// Display prediction history
function displayHistory(predictions) {
    const container = document.getElementById('recent-predictions');

    if (!predictions || predictions.length === 0) {
        container.innerHTML = '<p class="text-muted">No predictions yet. Use the form to analyze traffic.</p>';
        return;
    }

    // Show last 10, most recent first
    const recent = predictions.slice(-10).reverse();

    container.innerHTML = recent.map(p => {
        const time = new Date(p.timestamp).toLocaleTimeString();
        const bgClass = p.is_attack ? 'bg-danger-subtle' : 'bg-success-subtle';
        const icon = p.is_attack ? '🔴' : '🟢';

        return `
            <div class="mb-2 p-2 ${bgClass} rounded">
                <small>
                    ${icon} <strong>${time}</strong> - ${p.prediction} 
                    (${(p.confidence * 100).toFixed(1)}%)
                </small>
            </div>
        `;
    }).join('');
}

// Handle form submission
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

        // Display result
        displayPredictionResult(result);

        // Stats will auto-update from polling

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

    resultBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function getSeverityColor(severity) {
    switch(severity) {
        case 'High': return '#dc3545';
        case 'Medium': return '#ffc107';
        case 'Low': return '#fd7e14';
        default: return '#28a745';
    }
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
    startPolling();
    console.log('IDS-ML Dashboard loaded');
    console.log('Auto-refresh: Every 2 seconds');
    console.log('API URL:', API_URL);
});

// Stop polling when page unloads
window.addEventListener('beforeunload', () => {
    stopPolling();
});

// Handle visibility change (pause when tab is hidden)
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        stopPolling();
        console.log('Polling paused (tab hidden)');
    } else {
        startPolling();
        console.log('Polling resumed (tab visible)');
    }
});
