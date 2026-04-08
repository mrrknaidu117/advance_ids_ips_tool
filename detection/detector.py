# detection/detector.py
import joblib
import numpy as np
import pandas as pd
import os
import yaml
import socket
from backend.virustotal import check_ip
from backend.logger import log_info, log_error

# Load config
with open(os.path.join(os.path.dirname(__file__), "..", "config.yaml"), 'r') as f:
    cfg = yaml.safe_load(f)

MODEL_PATH = os.path.join(cfg["MODEL_PATH"], "model.pkl")
SCALER_PATH = os.path.join(cfg["MODEL_PATH"], "scaler.pkl")

# Load model and scaler once
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

def detect_from_dataframe(df, check_vt=False):
    """Preprocess input DataFrame and detect anomalies
    
    Args:
        df: DataFrame with features
        check_vt: Whether to check VirusTotal for IPs
        
    Returns:
        tuple: (predictions, details) where details contains additional info
    """
    df = df.select_dtypes(include=['float64', 'int64']).fillna(0)
    X_scaled = scaler.transform(df)
    ml_predictions = model.predict(X_scaled)
    
    results = []
    details = []
    
    # Check if we need to extract IPs and check VirusTotal
    if check_vt and 'src_ip' in df.columns:
        for i, pred in enumerate(ml_predictions):
            ip = df.iloc[i]['src_ip']
            vt_result = check_ip(ip)
            vt_malicious = vt_result.get('is_malicious', False)
            
            # Decision logic based on ML and VirusTotal
            if vt_malicious:
                # VirusTotal says malicious - block IP (99% accuracy)
                final_prediction = "Attack"
                action = "block"
            elif pred == "Attack":
                # ML says attack but VT says clean - alert only
                final_prediction = "Attack"
                action = "alert"
            else:
                # Both say clean
                final_prediction = "Normal"
                action = "allow"
            
            results.append(final_prediction)
            details.append({
                "ip": ip,
                "ml_prediction": pred,
                "vt_prediction": "Malicious" if vt_malicious else "Clean",
                "vt_details": vt_result.get('details', {}),
                "action": action
            })
    else:
        # Just return ML predictions if no VirusTotal check
        results = ml_predictions
        details = [{'ml_prediction': p} for p in ml_predictions]
    
    return results, details

def detect_from_features(features, ip=None):
    """Detect single instance (list of raw features)
    
    Args:
        features: List of feature values
        ip: Optional IP address to check with VirusTotal
        
    Returns:
        tuple: (prediction, details) with detection results
    """
    X = np.array(features).reshape(1, -1)
    X_scaled = scaler.transform(X)
    ml_prediction = model.predict(X_scaled)[0]
    
    details = {
        "ml_prediction": ml_prediction,
        "vt_prediction": None,
        "action": "alert" if ml_prediction == "Attack" else "allow"
    }
    
    # Check VirusTotal if IP is provided
    if ip:
        try:
            vt_result = check_ip(ip)
            vt_malicious = vt_result.get('is_malicious', False)
            details["vt_prediction"] = "Malicious" if vt_malicious else "Clean"
            details["vt_details"] = vt_result.get('details', {})
            
            # Decision logic based on ML and VirusTotal
            if vt_malicious:
                # VirusTotal says malicious - block IP (99% accuracy)
                final_prediction = "Attack"
                details["action"] = "block"
            elif ml_prediction == "Attack":
                # ML says attack but VT says clean - alert only
                final_prediction = "Attack"
                details["action"] = "alert"
            else:
                # Both say clean
                final_prediction = "Normal"
                details["action"] = "allow"
                
            return final_prediction, details
        except Exception as e:
            log_error(f"Error checking IP with VirusTotal: {str(e)}")
    
    # Return ML prediction if no VirusTotal check or it failed
    return ml_prediction, details

def extract_ip_from_packet(packet_dict):
    """Extract IP address from packet dictionary"""
    try:
        if 'IP' in packet_dict and 'src' in packet_dict['IP']:
            return packet_dict['IP']['src']
    except Exception:
        pass
    return None
