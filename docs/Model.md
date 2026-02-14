## Model Performance (v1.0)

### Random Forest Classifier
- **Overall Accuracy:** 85.91%
- **Weighted F1-Score:** 0.81
- **Training Samples:** 125,973
- **Test Samples:** 18,794
- **Features Used:** 12 selected features
- **Model Complexity:** 300 decision trees

### Attack Detection Performance

**Excellent Detection (>90% recall):**
- Normal traffic: 97%
- DoS attacks (neptune, smurf, back): 99-100%
- Probe attacks (satan, nmap): 96-100%

**Good Detection (70-90% recall):**
- Portsweep (Probe): 88%
- Ipsweep (Probe): 96%

**Poor Detection (<50% recall):**
- R2L attacks (guess_passwd, warezmaster): 0-2%
- U2R attacks (rootkit, multihop): 0%

**Root Cause:** Severe class imbalance - R2L/U2R attacks have <100 samples 
each compared to 14,000+ DoS samples, making them difficult to learn.

### Most Important Features
1. src_bytes (20.4%) - Data volume sent
2. dst_bytes (14.0%) - Data volume received
3. dst_host_srv_count (12.2%) - Connection patterns
4. service (11.3%) - Network service type
5. count (8.0%) - Connection count

### Conclusion
The model achieves **strong performance on common attack types** (DoS, Probe) 
which represent >80% of network attacks in practice. Performance on rare 
attacks (R2L, U2R) can be improved in future versions using:
- SMOTE/oversampling for minority classes
- Ensemble methods (XGBoost)
- Deep learning (Neural Networks)
