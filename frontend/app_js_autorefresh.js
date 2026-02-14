// IDS-ML Dashboard JavaScript with Auto-Refresh
const API_URL = 'http://localhost:8000';

let totalPredictions = 0;
let attacksDetected = 0;
let recentPredictions = [];
let autoRefreshInterval = null;

// Auto-refresh stats every 2 seconds
function startAutoRefresh() {
    // Initial load
    loadModelInfo();
    loadStats();

    // Refresh every 2 seconds
    autoRefreshInterval = setInterval(() => {
        loadStats();
    }, 2000);
}

// Load model info (once on startup)
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

// Load stats from API
async function loadStats() {
    try {
        const response = await fetch(`${API_URL}/stats`);
        const data = await response.json();

        // Note: API doesn't track predictions, so we keep our local count
        // Just update accuracy in case it changes
        document.getElementById('model-accuracy').textContent = 
            (data.model_accuracy * 100).toFixed(2) + '%';
    } catch (error) {
        console.error('Error loading stats:', error);
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

    // Scroll to result
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

function addRecentPrediction(result) {
    const now = new Date().toLocaleTimeString();
    recentPredictions.unshift({
        time: now,
        prediction: result.prediction,
        confidence: result.confidence,
        is_attack: result.is_attack
    });

    // Keep only last 10
    if (recentPredictions.length > 10) {
        recentPredictions = recentPredictions.slice(0, 10);
    }

    // Update display
    updateRecentPredictions();
}

function updateRecentPredictions() {
    const container = document.getElementById('recent-predictions');

    if (recentPredictions.length === 0) {
        container.innerHTML = '<p class="text-muted">No predictions yet. Use the form to analyze traffic.</p>';
        return;
    }

    container.innerHTML = recentPredictions.map(p => `
        <div class="mb-2 p-2 ${p.is_attack ? 'bg-danger-subtle' : 'bg-success-subtle'} rounded">
            <small>
                <strong>${p.time}</strong> - ${p.prediction} 
                (${(p.confidence * 100).toFixed(1)}%)
            </small>
        </div>
    `).join('');
}

// Periodically check for new predictions from backend (polling)
async function pollForUpdates() {
    // This function would check if there are new predictions
    // For now, we just update the counters based on localStorage

    const storedTotal = localStorage.getItem('totalPredictions');
    const storedAttacks = localStorage.getItem('attacksDetected');

    if (storedTotal !== null) {
        totalPredictions = parseInt(storedTotal);
        document.getElementById('total-predictions').textContent = totalPredictions;
    }

    if (storedAttacks !== null) {
        attacksDetected = parseInt(storedAttacks);
        document.getElementById('attacks-detected').textContent = attacksDetected;
    }
}

// Save stats to localStorage
function saveStats() {
    localStorage.setItem('totalPredictions', totalPredictions);
    localStorage.setItem('attacksDetected', attacksDetected);
}

// Listen for storage changes (when simulator runs in another tab/window)
window.addEventListener('storage', (e) => {
    if (e.key === 'totalPredictions' || e.key === 'attacksDetected') {
        pollForUpdates();
    }
});

// Intercept fetch requests to count predictions
const originalFetch = window.fetch;
window.fetch = async function(...args) {
    const response = await originalFetch(...args);

    // If this is a prediction request
    if (args[0].includes('/predict') && args[1]?.method === 'POST') {
        const clonedResponse = response.clone();
        try {
            const result = await clonedResponse.json();

            // Update counters
            totalPredictions++;
            if (result.is_attack) attacksDetected++;

            document.getElementById('total-predictions').textContent = totalPredictions;
            document.getElementById('attacks-detected').textContent = attacksDetected;

            // Add to recent predictions
            addRecentPrediction(result);

            // Save to localStorage
            saveStats();
        } catch (e) {
            // Ignore parsing errors
        }
    }

    return response;
};

// Load stats on startup
window.addEventListener('DOMContentLoaded', () => {
    // Load model info
    startAutoRefresh();

    // Restore previous stats
    pollForUpdates();

    console.log('IDS-ML Dashboard loaded with auto-refresh');
    console.log('API URL:', API_URL);
    console.log('Stats refresh interval: 2 seconds');
});

// Save stats before page unload
window.addEventListener('beforeunload', () => {
    saveStats();
});
