// Configuration for IDS-ML v2.0
// Local development uses localhost:9001, Production uses Render.com
const isLocal = location.hostname === "localhost" || location.hostname === "127.0.0.1";

window.API_BASE = isLocal 
    ? "http://localhost:9001" 
    : "https://ids-ml-backend.onrender.com";

console.log(`[Config] API Base: ${window.API_BASE} (${isLocal ? 'Local' : 'Production'})`);
