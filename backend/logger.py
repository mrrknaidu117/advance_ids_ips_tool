# File: backend/logger.py

import logging
import os
import mysql.connector
from datetime import datetime
import yaml
import warnings
import platform

# Suppress pywin32 warnings on Windows
if platform.system() == "Windows":
    try:
        import win32api
    except ImportError:
        # Suppress the warning about pywin32 not being available
        warnings.filterwarnings("ignore", message=".*pywin32.*")

# ---------------------
# Logging Setup
# ---------------------

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "system.log")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------------
# Load MySQL Config
# ---------------------

try:
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
        mysql_cfg = config.get("mysql", {})
except Exception as e:
    logging.error(f"Failed to load config.yaml: {e}")
    mysql_cfg = {}

# ---------------------
# File Log Wrappers
# ---------------------

def log_alert(message):
    logging.warning(message)

def log_info(message):
    logging.info(message)

def log_error(message):
    logging.error(message)

# ---------------------
# DB Helper
# ---------------------

def _log_to_db(query, params):
    try:
        conn = mysql.connector.connect(
            host=mysql_cfg['host'],
            user=mysql_cfg['user'],
            password=mysql_cfg['password'],
            database=mysql_cfg['database']
        )
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        conn.close()
    except mysql.connector.Error as err:
        log_error(f"MySQL logging failed: {err}")

# ---------------------
# Detection Event Logging
# ---------------------

def log_detection(ip_src, ip_dst, prediction, user_id=None):
    timestamp = datetime.now()

    if prediction.lower() == "attack":
        log_alert(f"Intrusion detected: {ip_src} -> {ip_dst}")
    else:
        log_info(f"Normal traffic: {ip_src} -> {ip_dst}")

    # Convert IP addresses to strings to avoid MySQL conversion issues
    query = """
        INSERT INTO detections (user_id, src_ip, dst_ip, label, timestamp)
        VALUES (%s, %s, %s, %s, %s)
    """
    _log_to_db(query, (user_id, str(ip_src), str(ip_dst), str(prediction), timestamp))

def log_vt_detection(ip, is_malicious, user_id=None):
    """Log VirusTotal detection results"""
    timestamp = datetime.now()
    
    if is_malicious:
        log_error(f"VirusTotal detected malicious IP: {ip} for user_id={user_id}")
    else:
        log_info(f"VirusTotal checked IP: {ip} (not malicious) for user_id={user_id}")

def log_ml_detection(ip, prediction, user_id=None):
    """Log ML model detection results"""
    timestamp = datetime.now()
    
    if prediction.lower() == "attack":
        log_alert(f"ML model detected attack from IP: {ip} for user_id={user_id}")
    else:
        log_info(f"ML model checked IP: {ip} (normal traffic) for user_id={user_id}")

def log_combined_detection(ip, ml_prediction, vt_malicious, action, user_id=None):
    """Log combined detection results from ML and VirusTotal"""
    timestamp = datetime.now()
    
    if action == "block":
        log_error(f"Automatically blocked IP: {ip} based on combined detection for user_id={user_id}")
    elif ml_prediction.lower() == "attack" and not vt_malicious:
        log_alert(f"Suspicious activity from IP: {ip} - ML detected attack but VirusTotal reports clean for user_id={user_id}")
    else:
        log_info(f"Checked IP: {ip} - ML: {ml_prediction}, VirusTotal: {'Malicious' if vt_malicious else 'Clean'} for user_id={user_id}")

# ---------------------
# Firewall Event Logging
# ---------------------

def log_block_event(ip, user_id, action):
    timestamp = datetime.now()
    log_info(f"{action.title()} IP: {ip} by user {user_id}")

    query = """
        INSERT INTO firewall_logs (user_id, ip_address, action, timestamp)
        VALUES (%s, %s, %s, %s)
    """
    _log_to_db(query, (user_id, ip, action, timestamp))


def log_login_attempt(username, success):
    status = "success" if success else "failure"
    timestamp = datetime.now()
    log_info(f"Login {status} for user '{username}'")

    query = """
        INSERT INTO login_attempts (username, status, timestamp)
        VALUES (%s, %s, %s)
    """
    _log_to_db(query, (username, status, timestamp))
