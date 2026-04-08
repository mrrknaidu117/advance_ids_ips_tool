
import yaml
import joblib
import numpy as np
import pandas as pd
import threading
import time
import socket
import sys
import os
import platform
from datetime import datetime
from collections import deque, defaultdict
import warnings
# Suppress scapy warnings on Windows
warnings.filterwarnings("ignore", category=UserWarning, module="scapy")
warnings.filterwarnings("ignore", message=".*libpcap.*")
warnings.filterwarnings("ignore", message=".*pcap.*")
os.environ["SCAPY_USE_PCAPDNET"] = "yes"

# Redirect scapy warnings to suppress console output
import sys
from io import StringIO

# Temporarily capture stderr during scapy import
original_stderr = sys.stderr
sys.stderr = StringIO()

# Import packet capture libraries
from scapy.all import sniff, AsyncSniffer, IP, TCP, UDP, get_if_list, get_if_addr

# Restore stderr after scapy import
sys.stderr = original_stderr

from backend.logger import log_detection, log_info, log_error, log_alert
from backend.firewall import block_ip_manual, process_detection_result
from backend.virustotal import check_ip

# --- Load Configuration ---
try:
    with open("config.yaml", "r") as f:
        cfg = yaml.safe_load(f)
except Exception as e:
    print(f"[Sniffer] ERROR: Failed to load config.yaml: {e}")
    sys.exit(1)

# --- Configuration Variables ---
SCANNING_MODE = cfg.get("scanning", {}).get("mode", "production")
AUTO_DETECT_INTERFACES = cfg.get("scanning", {}).get("interfaces_auto_detect", True)
PACKET_TIMEOUT = cfg.get("scanning", {}).get("packet_timeout", 5)
MAX_PACKETS_PER_SECOND = cfg.get("scanning", {}).get("max_packets_per_second", 1000)
BUFFER_SIZE = cfg.get("scanning", {}).get("buffer_size", 65536)

# Security settings
WHITELIST_ENABLED = cfg.get("security", {}).get("whitelist_enabled", True)
WHITELIST_IPS = set(cfg.get("security", {}).get("whitelist_ips", []))
AUTO_BLOCK_ENABLED = cfg.get("security", {}).get("auto_block_enabled", True)
ML_CONFIDENCE_THRESHOLD = cfg.get("security", {}).get("ml_confidence_threshold", 0.7)

# --- Interface Selection Logic ---
def detect_active_interfaces():
    """Automatically detect active network interfaces"""
    active_interfaces = []
    
    try:
        all_interfaces = get_if_list()
        log_info(f"Detected {len(all_interfaces)} total network interfaces")
        
        for iface in all_interfaces:
            try:
                # Skip loopback interfaces
                if 'loopback' in iface.lower() or 'lo' in iface.lower():
                    continue
                    
                # Try to get IP address to verify interface is active
                ip_addr = get_if_addr(iface)
                if ip_addr and ip_addr != "0.0.0.0":
                    active_interfaces.append(iface)
                    log_info(f"Found active interface: {iface} ({ip_addr})")
                    
            except Exception as e:
                log_error(f"Error checking interface {iface}: {e}")
                continue
                
    except Exception as e:
        log_error(f"Error detecting interfaces: {e}")
        
    return active_interfaces

def select_capture_interface():
    """Select the best interface for packet capture with improved error handling"""
    interfaces = cfg.get("CAPTURE_INTERFACES", [])
    
    if AUTO_DETECT_INTERFACES:
        log_info("Auto-detecting network interfaces...")
        detected_interfaces = detect_active_interfaces()
        if detected_interfaces:
            interfaces = detected_interfaces
            log_info(f"Using auto-detected interfaces: {interfaces}")
        else:
            log_error("No active interfaces detected, using configured interfaces")
    
    if not interfaces:
        log_error("No capture interfaces configured or detected!")
        return None
    
    # Try each interface until one works
    winpcap_error_found = False
    for iface in interfaces:
        try:
            # Test if interface is accessible with a very quick test
            test_sniffer = AsyncSniffer(iface=iface, count=1, timeout=1)
            test_sniffer.start()
            test_sniffer.join(timeout=2)
            test_sniffer.stop()
            
            log_info(f"Selected capture interface: {iface}")
            return iface
            
        except Exception as e:
            error_msg = str(e).lower()
            if 'winpcap' in error_msg or 'npcap' in error_msg or 'pcap' in error_msg:
                winpcap_error_found = True
                log_error(f"Interface {iface} not accessible: {e}")
            else:
                log_error(f"Interface {iface} not accessible: {e}")
            continue
    
    if winpcap_error_found:
        log_error("No accessible capture interfaces found!")
        log_info("RECOMMENDATION: Install Npcap or WinPcap to enable real network packet capture.")
        log_info("Download Npcap from: https://nmap.org/npcap/")
        log_info("The system will continue in testing mode with simulated packets.")
    else:
        log_error("No accessible capture interfaces found!")
    
    return None

# Select the capture interface
try:
    IFACE = select_capture_interface()
except Exception as e:
    print(f"[Sniffer] Warning: Interface selection failed: {e}")
    IFACE = None

if not IFACE and SCANNING_MODE == "production":
    SCANNING_MODE = "testing"
elif not IFACE:
    SCANNING_MODE = "testing"

# Load ML model and scaler
scaler = joblib.load("model/scaler.pkl")
model  = joblib.load("model/model.pkl")

# --- Sliding window state per source IP ---
WINDOW_SIZE = 20
length_buffers = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))

# --- Feature names from the trained model ---
feat_names = [
    'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean',
    'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
    'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
    'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
    'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg',
    'Bwd Seg Size Avg', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
    'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts',
    'Subflow Bwd Byts', 'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
    'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
    'Idle Std', 'Idle Max', 'Idle Min', 'Flow ID', 'Src IP', 'Src Port', 'Dst IP'
]

# --- Shared sniffer instance ---
_sniffer_instance = None

def extract_packet_features(pkt, src_ip, dst_ip, flow_start_time):
    """Extract all 83 features required by the ML model"""
    import time
    from scapy.layers.inet import TCP, UDP
    
    # Basic packet info
    plen = len(pkt)
    proto = pkt[IP].proto
    current_time = time.time()
    
    # Get ports if available
    src_port = 0
    dst_port = 0
    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    
    # Update flow statistics
    flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
    buf = length_buffers[flow_key]
    buf.append(plen)
    
    # Calculate basic statistics
    if len(buf) > 1:
        pkt_mean = float(np.mean(buf))
        pkt_std = float(np.std(buf))
        pkt_min = float(min(buf))
        pkt_max = float(max(buf))
        pkt_var = pkt_std ** 2
    else:
        pkt_mean = pkt_std = pkt_min = pkt_max = pkt_var = float(plen)
    
    # Create feature vector with reasonable defaults
    features = [
        dst_port,           # Dst Port
        proto,              # Protocol
        current_time,       # Timestamp
        1.0,                # Flow Duration
        1,                  # Tot Fwd Pkts
        0,                  # Tot Bwd Pkts
        plen,               # TotLen Fwd Pkts
        0,                  # TotLen Bwd Pkts
        pkt_max,            # Fwd Pkt Len Max
        pkt_min,            # Fwd Pkt Len Min
        pkt_mean,           # Fwd Pkt Len Mean
        pkt_std,            # Fwd Pkt Len Std
        0,                  # Bwd Pkt Len Max
        0,                  # Bwd Pkt Len Min
        0,                  # Bwd Pkt Len Mean
        0,                  # Bwd Pkt Len Std
        plen,               # Flow Byts/s
        1.0,                # Flow Pkts/s
        0,                  # Flow IAT Mean
        0,                  # Flow IAT Std
        0,                  # Flow IAT Max
        0,                  # Flow IAT Min
        0,                  # Fwd IAT Tot
        0,                  # Fwd IAT Mean
        0,                  # Fwd IAT Std
        0,                  # Fwd IAT Max
        0,                  # Fwd IAT Min
        0,                  # Bwd IAT Tot
        0,                  # Bwd IAT Mean
        0,                  # Bwd IAT Std
        0,                  # Bwd IAT Max
        0,                  # Bwd IAT Min
        1 if TCP in pkt and pkt[TCP].flags & 0x08 else 0,  # Fwd PSH Flags
        0,                  # Bwd PSH Flags
        1 if TCP in pkt and pkt[TCP].flags & 0x20 else 0,  # Fwd URG Flags
        0,                  # Bwd URG Flags
        40 if TCP in pkt else 8,  # Fwd Header Len
        0,                  # Bwd Header Len
        1.0,                # Fwd Pkts/s
        0,                  # Bwd Pkts/s
        pkt_min,            # Pkt Len Min
        pkt_max,            # Pkt Len Max
        pkt_mean,           # Pkt Len Mean
        pkt_std,            # Pkt Len Std
        pkt_var,            # Pkt Len Var
        1 if TCP in pkt and pkt[TCP].flags & 0x01 else 0,  # FIN Flag Cnt
        1 if TCP in pkt and pkt[TCP].flags & 0x02 else 0,  # SYN Flag Cnt
        1 if TCP in pkt and pkt[TCP].flags & 0x04 else 0,  # RST Flag Cnt
        1 if TCP in pkt and pkt[TCP].flags & 0x08 else 0,  # PSH Flag Cnt
        1 if TCP in pkt and pkt[TCP].flags & 0x10 else 0,  # ACK Flag Cnt
        1 if TCP in pkt and pkt[TCP].flags & 0x20 else 0,  # URG Flag Cnt
        0,                  # CWE Flag Count
        0,                  # ECE Flag Cnt
        1.0,                # Down/Up Ratio
        plen,               # Pkt Size Avg
        plen,               # Fwd Seg Size Avg
        0,                  # Bwd Seg Size Avg
        0,                  # Fwd Byts/b Avg
        0,                  # Fwd Pkts/b Avg
        0,                  # Fwd Blk Rate Avg
        0,                  # Bwd Byts/b Avg
        0,                  # Bwd Pkts/b Avg
        0,                  # Bwd Blk Rate Avg
        1,                  # Subflow Fwd Pkts
        plen,               # Subflow Fwd Byts
        0,                  # Subflow Bwd Pkts
        0,                  # Subflow Bwd Byts
        8192 if TCP in pkt else 0,  # Init Fwd Win Byts
        0,                  # Init Bwd Win Byts
        1,                  # Fwd Act Data Pkts
        plen,               # Fwd Seg Size Min
        0,                  # Active Mean
        0,                  # Active Std
        0,                  # Active Max
        0,                  # Active Min
        0,                  # Idle Mean
        0,                  # Idle Std
        0,                  # Idle Max
        0,                  # Idle Min
        hash(flow_key) % 1000000,  # Flow ID
        hash(src_ip) % 1000000,    # Src IP (as numeric)
        src_port,           # Src Port
        hash(dst_ip) % 1000000,    # Dst IP (as numeric)
    ]
    
    return features

# --- Rate Limiting and Performance ---
packet_count = 0
packet_count_lock = threading.Lock()
last_reset_time = time.time()

def check_rate_limit():
    """Check if we're within packet processing rate limits"""
    global packet_count, last_reset_time
    
    with packet_count_lock:
        current_time = time.time()
        
        # Reset counter every second
        if current_time - last_reset_time >= 1.0:
            packet_count = 0
            last_reset_time = current_time
        
        packet_count += 1
        return packet_count <= MAX_PACKETS_PER_SECOND

def is_ip_whitelisted(ip):
    """Check if IP is in whitelist"""
    if not WHITELIST_ENABLED:
        return False
    return ip in WHITELIST_IPS

def enhanced_threat_detection(src_ip, ml_prediction, packet_info):
    """Enhanced threat detection combining ML and threat intelligence"""
    threat_score = 0
    detection_details = {
        "ml_prediction": ml_prediction,
        "vt_prediction": None,
        "threat_score": 0,
        "action": "allow",
        "sources": []
    }
    
    # ML-based scoring
    if ml_prediction == "attack":
        threat_score += 70
        detection_details["sources"].append("ML_Model")
    
    # VirusTotal check (for high-confidence ML detections or random sampling)
    check_vt = (ml_prediction == "attack" or 
               (time.time() % 10 == 0))  # Sample 10% of traffic
    
    if check_vt:
        try:
            vt_result = check_ip(src_ip)
            if vt_result.get("success", False):
                detection_details["vt_prediction"] = vt_result
                if vt_result.get("is_malicious", False):
                    threat_score += 100
                    detection_details["sources"].append("VirusTotal")
        except Exception as e:
            log_error(f"VirusTotal check failed for {src_ip}: {e}")
    
    # Determine action based on threat score
    detection_details["threat_score"] = threat_score
    
    if threat_score >= 100:  # High confidence threat
        detection_details["action"] = "block"
    elif threat_score >= 50:  # Medium confidence
        detection_details["action"] = "alert"
    else:
        detection_details["action"] = "allow"
    
    return detection_details

def classify_packet(pkt, user_id, auto_block=False):
    """Enhanced packet classification with threat intelligence"""
    if IP not in pkt:
        return None
    
    # Rate limiting check
    if not check_rate_limit():
        return None
    
    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    
    # Skip whitelisted IPs
    if is_ip_whitelisted(src):
        return None
    
    # Extract packet features
    flow_start_time = time.time()
    features = extract_packet_features(pkt, src, dst, flow_start_time)
    
    # ML prediction
    try:
        feats_df = pd.DataFrame([features], columns=feat_names)
        scaled_feats = scaler.transform(feats_df)
        pred = model.predict(scaled_feats)[0]
        ml_prediction = "attack" if pred == "Attack" else "normal"
    except Exception as e:
        log_error(f"ML prediction error: {e}")
        ml_prediction = "normal"
    
    # Enhanced threat detection
    packet_info = {
        "src": src, "dst": dst, "proto": proto, 
        "size": len(pkt), "timestamp": datetime.now()
    }
    
    detection_result = enhanced_threat_detection(src, ml_prediction, packet_info)
    
    # Process the detection result
    if AUTO_BLOCK_ENABLED and detection_result["action"] == "block":
        try:
            result = process_detection_result(src, detection_result, user_id)
            log_alert(f"BLOCKED: {src} -> {dst} (Score: {detection_result['threat_score']})")
        except Exception as e:
            log_error(f"Failed to process detection result for {src}: {e}")
    elif detection_result["action"] == "alert":
        log_alert(f"SUSPICIOUS: {src} -> {dst} (Score: {detection_result['threat_score']})")
    
    # Log the detection
    log_detection(src, dst, ml_prediction, user_id)
    
    return {
        "src": src,
        "dst": dst,
        "proto": proto,
        "status": ml_prediction,
        "action": detection_result["action"],
        "threat_score": detection_result["threat_score"],
        "size": len(pkt),
        "timestamp": datetime.now().isoformat()
    }

def _sniff_handler(pkt, user_id, auto_block, packet_callback):
    result = classify_packet(pkt, user_id, auto_block)
    if result and packet_callback:
        packet_callback(result)

# --- Testing Mode Functions ---
def create_diverse_test_packets():
    """Generate diverse test packets from various IP ranges"""
    test_scenarios = [
        # Internal network traffic
        {"src": "192.168.1.100", "dst": "192.168.1.1", "port": 80},
        {"src": "10.0.0.50", "dst": "10.0.0.1", "port": 443},
        {"src": "172.16.0.25", "dst": "172.16.0.1", "port": 22},
        
        # External traffic (DNS, web servers)
        {"src": "8.8.8.8", "dst": "192.168.1.100", "port": 53},
        {"src": "1.1.1.1", "dst": "192.168.1.100", "port": 53},
        {"src": "208.67.222.222", "dst": "192.168.1.100", "port": 53},
        
        # Potentially suspicious traffic
        {"src": "185.220.101.182", "dst": "192.168.1.100", "port": 9050},  # Known Tor exit
        {"src": "91.240.118.172", "dst": "192.168.1.100", "port": 8080},   # Suspicious IP
        
        # Common application traffic
        {"src": "142.250.191.14", "dst": "192.168.1.100", "port": 443},   # Google
        {"src": "157.240.12.35", "dst": "192.168.1.100", "port": 443},    # Facebook
    ]
    
    packets = []
    for scenario in test_scenarios:
        if scenario["port"] in [80, 443, 8080]:
            pkt = IP(src=scenario["src"], dst=scenario["dst"]) / TCP(sport=scenario["port"], dport=80)
        elif scenario["port"] == 53:
            pkt = IP(src=scenario["src"], dst=scenario["dst"]) / UDP(sport=53, dport=53)
        else:
            pkt = IP(src=scenario["src"], dst=scenario["dst"]) / TCP(sport=scenario["port"], dport=22)
        packets.append(pkt)
    
    return packets

def testing_mode_sniffer(user_id, auto_block, packet_callback):
    """Advanced testing mode with diverse packet scenarios"""
    log_info("Starting enhanced testing mode with diverse IP ranges...")
    test_packets = create_diverse_test_packets()
    packet_index = 0
    
    while getattr(_sniffer_instance, 'running', True):
        # Cycle through different test packets
        test_pkt = test_packets[packet_index % len(test_packets)]
        packet_index += 1
        
        try:
            _sniff_handler(test_pkt, user_id, auto_block, packet_callback)
        except Exception as e:
            log_error(f"Error processing test packet: {e}")
        
        # Variable delay to simulate realistic traffic
        delay = 2 + (packet_index % 3)  # 2-4 seconds
        time.sleep(delay)

def production_mode_sniffer(user_id, auto_block, packet_callback):
    """Production mode with real network packet capture"""
    log_info(f"Starting production packet capture on interface: {IFACE}")
    
    def packet_handler(pkt):
        try:
            if not getattr(_sniffer_instance, 'running', False):
                return False  # Stop sniffing
            _sniff_handler(pkt, user_id, auto_block, packet_callback)
        except Exception as e:
            log_error(f"Error processing packet: {e}")
    
    try:
        # Use AsyncSniffer for non-blocking operation
        sniffer = AsyncSniffer(
            iface=IFACE,
            prn=packet_handler,
            filter="ip",  # Only IP packets
            store=False,  # Don't store packets in memory
        )
        
        _sniffer_instance.scapy_sniffer = sniffer
        sniffer.start()
        
        # Keep the thread alive while sniffing
        while getattr(_sniffer_instance, 'running', False):
            time.sleep(1)
            
    except Exception as e:
        log_error(f"Production sniffer error: {e}")
    finally:
        if hasattr(_sniffer_instance, 'scapy_sniffer'):
            try:
                _sniffer_instance.scapy_sniffer.stop()
            except:
                pass

def start_sniffing(user_id, auto_block=True, packet_callback=None):
    """Start packet sniffing in production or testing mode"""
    global _sniffer_instance
    
    if _sniffer_instance and getattr(_sniffer_instance, 'running', False):
        log_info("Sniffer already running")
        return
    
    mode = SCANNING_MODE
    log_info(f"Starting sniffer in {mode.upper()} mode...")
    
    # Select sniffer function based on mode
    if mode == "production" and IFACE:
        sniffer_func = production_mode_sniffer
        log_info(f"Production mode: Using interface {IFACE}")
    else:
        sniffer_func = testing_mode_sniffer
        log_info("Testing mode: Using diverse synthetic packets")
    
    # Start sniffer in separate thread
    _sniffer_instance = threading.Thread(
        target=sniffer_func,
        args=(user_id, auto_block, packet_callback),
        daemon=True
    )
    _sniffer_instance.running = True
    _sniffer_instance.start()
    
    log_info(f"Sniffer started successfully in {mode} mode")

def stop_sniffing():
    global _sniffer_instance
    if _sniffer_instance and getattr(_sniffer_instance, 'running', False):
        _sniffer_instance.running = False
        print("[Sniffer] Stopped")
    _sniffer_instance = None
