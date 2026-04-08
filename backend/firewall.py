# File: backend/firewall.py

import subprocess
import platform
import socket
from backend.logger import log_info, log_error
from backend.auth import get_db_connection
from backend.virustotal import check_ip, get_formatted_report

def log_audit(user_id, action):
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                action TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        cursor.execute(
            "INSERT INTO audit_logs (user_id, action) VALUES (%s, %s)",
            (user_id, action)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log_error(f"Audit logging failed: {e}")

def block_ip_manual(ip, user_id):
    try:
        if platform.system() == "Linux":
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        else:  # Windows
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=BlockIP", "dir=in", "action=block", f"remoteip={ip}"
            ], check=True)

        log_info(f"Blocked IP: {ip} by user {user_id}")
        log_audit(user_id, f"Blocked IP: {ip}")

        # Save to DB
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                ip_address VARCHAR(45),
                status VARCHAR(10),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute(
            "INSERT INTO blocked_ips (user_id, ip_address, status) VALUES (%s, %s, %s)",
            (user_id, ip, "blocked")
        )
        conn.commit()
        conn.close()

    except subprocess.CalledProcessError as e:
        log_error(f"Failed to block IP {ip}: {e}")

def unblock_ip_manual(ip, user_id):
    try:
        if platform.system() == "Linux":
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        else:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=BlockIP", f"remoteip={ip}"
            ], check=True)

        log_info(f"Unblocked IP: {ip} by user {user_id}")
        log_audit(user_id, f"Unblocked IP: {ip}")

        # Update DB
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO blocked_ips (user_id, ip_address, status)
            VALUES (%s, %s, %s)
        """, (user_id, ip, "unblocked"))
        conn.commit()
        conn.close()

    except subprocess.CalledProcessError as e:
        log_error(f"Failed to unblock IP {ip}: {e}")

def auto_block_ip(ip, reason, detection_details=None):
    """
    Automatically block an IP based on detection results
    
    Args:
        ip: IP address to block
        reason: Reason for blocking (ml, virustotal, or combined)
        detection_details: Optional dictionary with detection details
    
    Returns:
        bool: True if blocked successfully, False otherwise
    """

def process_detection_result(ip, detection_result, user_id=None):
    """
    Process detection results and take appropriate action
    
    Args:
        ip: IP address detected
        detection_result: Dictionary with detection details
        user_id: Optional user ID for logging
        
    Returns:
        dict: Action taken and details
    """
    action = detection_result.get("action", "alert")
    ml_prediction = detection_result.get("ml_prediction", "Unknown")
    vt_prediction = detection_result.get("vt_prediction", "Unknown")
    vt_malicious = vt_prediction == "Malicious"
    
    result = {
        "ip": ip,
        "action_taken": action,
        "blocked": False,
        "alert": False,
        "ml_prediction": ml_prediction,
        "vt_prediction": vt_prediction
    }
    
    # Log ML detection results
    from backend.logger import log_ml_detection, log_vt_detection, log_combined_detection
    
    # Log individual detection results
    log_ml_detection(ip, ml_prediction, user_id)
    if vt_prediction != "Unknown":
        log_vt_detection(ip, vt_malicious, user_id)
    
    # Log combined detection and take action
    log_combined_detection(ip, ml_prediction, vt_malicious, action, user_id)
    
    # Determine action based on detection results
    if action == "block":
        # VirusTotal detected as malicious - block IP
        reason = "VirusTotal detected as malicious"
        if vt_malicious:
            result["blocked"] = auto_block_ip(ip, reason, detection_result)
            result["alert"] = True
            result["message"] = f"IP {ip} automatically blocked: {reason}"
    
    elif action == "alert" and ml_prediction == "Attack":
        # ML detected as attack but VirusTotal didn't - just alert
        result["alert"] = True
        result["message"] = f"Suspicious activity detected from IP {ip}: ML detected as attack but VirusTotal reports clean"
    
    return result
    try:
        # Use system admin user ID (1) for automatic blocks
        user_id = 1
        
        # Check if IP is valid
        try:
            socket.inet_aton(ip)
        except socket.error:
            log_error(f"Invalid IP address format: {ip}")
            return False
        
        # Block the IP
        if platform.system() == "Linux":
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        else:  # Windows
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=BlockIP", "dir=in", "action=block", f"remoteip={ip}"
            ], check=True)

        # Format detailed reason
        detailed_reason = f"Auto-blocked IP: {ip} - Reason: {reason}"
        if detection_details:
            if 'ml_prediction' in detection_details:
                detailed_reason += f" - ML: {detection_details['ml_prediction']}"
            if 'vt_prediction' in detection_details:
                detailed_reason += f" - VT: {detection_details['vt_prediction']}"
        
        log_info(detailed_reason)
        log_audit(user_id, detailed_reason)

        # Save to DB
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                ip_address VARCHAR(45),
                status VARCHAR(10),
                reason VARCHAR(255),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute(
            "INSERT INTO blocked_ips (user_id, ip_address, status, reason) VALUES (%s, %s, %s, %s)",
            (user_id, ip, "blocked", reason)
        )
        conn.commit()
        conn.close()
        
        return True

    except subprocess.CalledProcessError as e:
        log_error(f"Failed to auto-block IP {ip}: {e}")
        return False
    except Exception as e:
        log_error(f"Error in auto_block_ip for {ip}: {str(e)}")
        return False
