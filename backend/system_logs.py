# File: backend/system_logs.py - Enhanced Windows System Log Scanner
try:
    import win32evtlog
    import win32evtlogutil
    import win32security
    import win32con
    WINDOWS_EVENTS_AVAILABLE = True
except ImportError:
    WINDOWS_EVENTS_AVAILABLE = False
    print("Warning: pywin32 not available, system log scanning will use fallback mode")

import time
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import re
import threading
import queue
import os

class WindowsSystemLogScanner:
    """
    Comprehensive Windows system log scanner for security events and network activity.
    Monitors Windows Event Logs for security-relevant events.
    """
    
    def __init__(self, user_id: int):
        self.user_id = user_id
        self.running = False
        self.event_queue = queue.Queue()
        
        # Define log sources and their importance
        self.log_sources = {
            'Security': {
                'priority': 'CRITICAL',
                'events': {
                    4624: 'Successful Logon',
                    4625: 'Failed Logon',
                    4648: 'Logon with Explicit Credentials',
                    4672: 'Admin Rights Assigned',
                    4720: 'User Account Created',
                    4726: 'User Account Deleted',
                    4728: 'User Added to Security Group',
                    4732: 'User Added to Local Group',
                    4756: 'Universal Security Group Created',
                    4767: 'User Account Unlocked',
                    5140: 'Network Share Accessed',
                    5156: 'Windows Filtering Platform Connection',
                    5157: 'Windows Filtering Platform Connection Blocked'
                }
            },
            'System': {
                'priority': 'WARNING',
                'events': {
                    7030: 'Service Control Manager',
                    7034: 'Service Crashed',
                    7035: 'Service Control Manager',
                    7036: 'Service Started/Stopped',
                    7040: 'Service Start Type Changed',
                    1074: 'System Shutdown/Restart',
                    6005: 'Event Log Service Started',
                    6006: 'Event Log Service Stopped',
                    6008: 'Unexpected Shutdown',
                    6013: 'System Uptime'
                }
            },
            'Application': {
                'priority': 'INFO',
                'events': {
                    1000: 'Application Error',
                    1001: 'Windows Error Reporting',
                    1002: 'Application Hang'
                }
            },
            'Microsoft-Windows-Windows Defender/Operational': {
                'priority': 'CRITICAL',
                'events': {
                    1116: 'Malware Detected',
                    1117: 'Action Taken on Malware',
                    5001: 'Real-time Protection Disabled',
                    5004: 'Real-time Protection Configuration Changed',
                    5007: 'Configuration Changed',
                    5010: 'Scanning for Malware'
                }
            },
            'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall': {
                'priority': 'WARNING',
                'events': {
                    2004: 'Firewall Rule Added',
                    2005: 'Firewall Rule Changed',
                    2006: 'Firewall Rule Deleted',
                    2033: 'Firewall Blocked Connection'
                }
            }
        }
        
        self.suspicious_patterns = [
            r'powershell.*-enc.*',  # Encoded PowerShell commands
            r'cmd.*\/c.*',          # Command execution
            r'net user.*\/add',     # User creation
            r'reg add.*',           # Registry modifications
            r'schtasks.*\/create',  # Scheduled task creation
            r'wmic.*process.*call.*create',  # WMI process creation
            r'certutil.*-urlcache', # File download attempts
            r'rundll32.*javascript', # Suspicious DLL execution
            r'regsvr32.*\/s.*\/u.*', # Suspicious registry server
            r'mshta.*http',         # HTML application execution
            r'bitsadmin.*\/transfer' # Background transfer
        ]
        
        self.setup_logging()
        
    def setup_logging(self):
        """Initialize logging for system log scanning"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/system_scanner.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def start_monitoring(self) -> bool:
        """Start continuous system log monitoring"""
        try:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            self.logger.info("System log monitoring started")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start system log monitoring: {e}")
            return False

    def stop_monitoring(self):
        """Stop system log monitoring"""
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=5)
        self.logger.info("System log monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        last_check = {}
        
        while self.running:
            try:
                for log_name in self.log_sources.keys():
                    try:
                        # Get events since last check
                        since_time = last_check.get(log_name, datetime.now() - timedelta(minutes=5))
                        events = self.scan_event_log(log_name, since_time)
                        
                        for event in events:
                            if self._is_security_relevant(event):
                                self.event_queue.put(event)
                                self._log_security_event(event)
                        
                        last_check[log_name] = datetime.now()
                        
                    except Exception as e:
                        self.logger.warning(f"Error scanning {log_name}: {e}")
                
                # Sleep for 30 seconds before next scan
                for _ in range(30):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)

    def scan_event_log(self, log_name: str, since_time: Optional[datetime] = None) -> List[Dict]:
        """
        Scan Windows Event Log for security-relevant events
        
        Args:
            log_name: Name of the event log to scan
            since_time: Only return events after this time
            
        Returns:
            List of event dictionaries
        """
        events = []
        
        if not WINDOWS_EVENTS_AVAILABLE:
            # Fallback mode - simulate some basic system events
            return self._generate_fallback_events(log_name, since_time)
        
        try:
            # Open the event log
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Calculate time filter
            if since_time is None:
                since_time = datetime.now() - timedelta(hours=1)
            
            while True:
                event_records = win32evtlog.ReadEventLog(hand, flags, 0)
                if not event_records:
                    break
                
                for event_record in event_records:
                    # Convert event time - handle both timestamp and datetime objects
                    try:
                        if hasattr(event_record.TimeGenerated, 'timestamp'):
                            # If it's already a datetime object, convert to timestamp first
                            event_time = datetime.fromtimestamp(event_record.TimeGenerated.timestamp())
                        else:
                            # If it's a numeric timestamp
                            event_time = datetime.fromtimestamp(float(event_record.TimeGenerated))
                    except (TypeError, ValueError, AttributeError) as e:
                        # Fallback to current time if conversion fails
                        self.logger.debug(f"Event time conversion failed: {e}, using current time")
                        event_time = datetime.now()
                    
                    # Skip old events
                    if event_time < since_time:
                        break
                    
                    # Extract event details
                    event_data = self._extract_event_data(event_record, log_name)
                    if event_data:
                        events.append(event_data)
                
                # Break if we've gone back too far
                if event_records:
                    try:
                        last_event_time = event_records[-1].TimeGenerated
                        if hasattr(last_event_time, 'timestamp'):
                            last_event_time = datetime.fromtimestamp(last_event_time.timestamp())
                        else:
                            last_event_time = datetime.fromtimestamp(float(last_event_time))
                        if last_event_time < since_time:
                            break
                    except (TypeError, ValueError, AttributeError):
                        # If we can't determine the time, continue processing
                        pass
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            self.logger.warning(f"Could not scan {log_name}: {e}")
        
        return events

    def _extract_event_data(self, event_record, log_name: str) -> Optional[Dict]:
        """Extract relevant data from event record"""
        try:
            event_id = event_record.EventID & 0xFFFF  # Remove qualifiers
            event_source = event_record.SourceName
            
            # Handle datetime conversion safely
            try:
                if hasattr(event_record.TimeGenerated, 'timestamp'):
                    event_time = datetime.fromtimestamp(event_record.TimeGenerated.timestamp())
                else:
                    event_time = datetime.fromtimestamp(float(event_record.TimeGenerated))
            except (TypeError, ValueError, AttributeError):
                event_time = datetime.now()
            
            # Get event description
            try:
                event_description = win32evtlogutil.SafeFormatMessage(event_record, log_name)
                if not event_description:
                    event_description = f"Event ID {event_id} from {event_source}"
            except:
                event_description = f"Event ID {event_id} from {event_source}"
            
            # Check if this is a monitored event
            log_config = self.log_sources.get(log_name, {})
            monitored_events = log_config.get('events', {})
            
            if event_id not in monitored_events and log_name != 'Security':
                return None
            
            event_data = {
                'log_name': log_name,
                'event_id': event_id,
                'event_source': event_source,
                'timestamp': event_time.isoformat(),
                'description': event_description,
                'priority': log_config.get('priority', 'INFO'),
                'event_type': monitored_events.get(event_id, 'Unknown Event'),
                'computer_name': event_record.ComputerName,
                'user_sid': getattr(event_record, 'UserSid', None),
                'raw_data': event_record.Data
            }
            
            # Extract additional context for security events
            if log_name == 'Security':
                event_data.update(self._extract_security_context(event_record, event_description))
            
            return event_data
            
        except Exception as e:
            self.logger.debug(f"Error extracting event data: {e}")
            return None

    def _extract_security_context(self, event_record, description: str) -> Dict:
        """Extract additional security context from security events"""
        context = {}
        
        try:
            event_id = event_record.EventID & 0xFFFF
            
            # Extract IP addresses
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, description)
            if ips:
                context['source_ips'] = list(set(ips))
            
            # Extract usernames
            username_patterns = [
                r'Account Name:\s*([^\s\r\n]+)',
                r'Target Account Name:\s*([^\s\r\n]+)',
                r'Subject Account Name:\s*([^\s\r\n]+)'
            ]
            
            for pattern in username_patterns:
                matches = re.findall(pattern, description, re.IGNORECASE)
                if matches:
                    context['username'] = matches[0]
                    break
            
            # Extract process information
            process_pattern = r'Process Name:\s*([^\r\n]+)'
            process_matches = re.findall(process_pattern, description, re.IGNORECASE)
            if process_matches:
                context['process_name'] = process_matches[0].strip()
            
            # Extract network information for connection events
            if event_id in [5156, 5157]:
                port_pattern = r'Destination Port:\s*(\d+)'
                port_matches = re.findall(port_pattern, description, re.IGNORECASE)
                if port_matches:
                    context['destination_port'] = int(port_matches[0])
            
            # Check for logon types
            if event_id in [4624, 4625]:
                logon_type_pattern = r'Logon Type:\s*(\d+)'
                logon_type_matches = re.findall(logon_type_pattern, description)
                if logon_type_matches:
                    logon_type = int(logon_type_matches[0])
                    context['logon_type'] = logon_type
                    context['logon_type_desc'] = self._get_logon_type_description(logon_type)
            
        except Exception as e:
            self.logger.debug(f"Error extracting security context: {e}")
        
        return context

    def _get_logon_type_description(self, logon_type: int) -> str:
        """Get human-readable logon type description"""
        logon_types = {
            2: 'Interactive',
            3: 'Network',
            4: 'Batch',
            5: 'Service',
            7: 'Unlock',
            8: 'NetworkCleartext',
            9: 'NewCredentials',
            10: 'RemoteInteractive',
            11: 'CachedInteractive'
        }
        return logon_types.get(logon_type, f'Unknown ({logon_type})')

    def _generate_fallback_events(self, log_name: str, since_time: Optional[datetime] = None) -> List[Dict]:
        """Generate simulated events in fallback mode when Windows Events API is not available"""
        events = []
        
        # Only generate basic events every few minutes to avoid spam
        if since_time and (datetime.now() - since_time).total_seconds() < 300:  # 5 minutes
            return events
        
        try:
            # Generate some basic system status events
            if log_name == 'System':
                event = {
                    'log_name': log_name,
                    'event_id': 6013,
                    'event_source': 'System',
                    'timestamp': datetime.now().isoformat(),
                    'description': f'System uptime report - running normally',
                    'priority': 'INFO',
                    'event_type': 'System Uptime',
                    'computer_name': 'LocalHost',
                    'user_sid': None,
                    'raw_data': None
                }
                events.append(event)
            
            # Occasionally generate a security event for demonstration
            elif log_name == 'Security' and datetime.now().minute % 10 == 0:
                event = {
                    'log_name': log_name,
                    'event_id': 4624,
                    'event_source': 'Security',
                    'timestamp': datetime.now().isoformat(),
                    'description': 'Successful logon demonstration event',
                    'priority': 'INFO',
                    'event_type': 'Successful Logon',
                    'computer_name': 'LocalHost',
                    'user_sid': None,
                    'raw_data': None
                }
                events.append(event)
        
        except Exception as e:
            self.logger.debug(f"Error generating fallback events: {e}")
        
        return events

    def _is_security_relevant(self, event: Dict) -> bool:
        """Determine if an event is security-relevant"""
        try:
            # Always relevant if high priority
            if event['priority'] in ['CRITICAL', 'ERROR']:
                return True
            
            # Check for suspicious patterns in description
            description = event.get('description', '').lower()
            for pattern in self.suspicious_patterns:
                if re.search(pattern, description, re.IGNORECASE):
                    event['suspicious_pattern'] = pattern
                    return True
            
            # Check for failed logons
            if event['event_id'] == 4625:
                return True
            
            # Check for privilege escalation
            if event['event_id'] in [4672, 4720, 4728, 4732]:
                return True
            
            # Check for network activity
            if event['event_id'] in [5156, 5157] and event.get('source_ips'):
                return True
            
            # Check for malware detection
            if 'malware' in description or 'virus' in description:
                return True
            
            # Check for firewall blocks
            if event['event_id'] == 2033:
                return True
            
        except Exception as e:
            self.logger.debug(f"Error checking security relevance: {e}")
        
        return False

    def _log_security_event(self, event: Dict):
        """Log security event to system log"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            priority = event.get('priority', 'INFO')
            
            # Determine log level based on priority
            if priority == 'CRITICAL':
                level = 'CRITICAL'
            elif event.get('suspicious_pattern') or event['event_id'] in [4625, 5157, 2033]:
                level = 'ERROR'
            elif priority == 'WARNING':
                level = 'WARNING'
            else:
                level = 'INFO'
            
            # Format log message
            log_message = f"System Event - {event['event_type']}: {event['description']}"
            
            # Add context if available
            context_parts = []
            if event.get('username'):
                context_parts.append(f"User: {event['username']}")
            if event.get('source_ips'):
                context_parts.append(f"Source IPs: {', '.join(event['source_ips'])}")
            if event.get('process_name'):
                context_parts.append(f"Process: {event['process_name']}")
            if event.get('destination_port'):
                context_parts.append(f"Port: {event['destination_port']}")
            
            if context_parts:
                log_message += f" ({', '.join(context_parts)})"
            
            # Add user context
            log_message += f" [user_id={self.user_id}, source=system_logs]"
            
            # Write to log file
            log_entry = f"{timestamp} - {level} - {log_message}\n"
            with open("logs/system.log", "a", encoding="utf-8") as f:
                f.write(log_entry)
            
            self.logger.info(f"Logged security event: {event['event_type']} (ID: {event['event_id']})")
            
        except Exception as e:
            self.logger.error(f"Error logging security event: {e}")

    def get_recent_events(self, hours: int = 1) -> List[Dict]:
        """Get recent security events from queue"""
        events = []
        
        try:
            # Get events from queue (non-blocking)
            while not self.event_queue.empty():
                try:
                    event = self.event_queue.get_nowait()
                    events.append(event)
                except queue.Empty:
                    break
                    
        except Exception as e:
            self.logger.error(f"Error getting recent events: {e}")
        
        return events

    def scan_for_indicators(self) -> Dict[str, int]:
        """Scan recent events for security indicators"""
        indicators = {
            'failed_logons': 0,
            'privilege_escalations': 0,
            'malware_detections': 0,
            'firewall_blocks': 0,
            'suspicious_processes': 0,
            'network_connections': 0
        }
        
        try:
            # Scan last hour of security events
            since_time = datetime.now() - timedelta(hours=1)
            
            for log_name in ['Security', 'System', 'Microsoft-Windows-Windows Defender/Operational']:
                events = self.scan_event_log(log_name, since_time)
                
                for event in events:
                    event_id = event.get('event_id', 0)
                    
                    # Count different types of security events
                    if event_id == 4625:
                        indicators['failed_logons'] += 1
                    elif event_id in [4672, 4720, 4728, 4732]:
                        indicators['privilege_escalations'] += 1
                    elif event_id in [1116, 1117]:
                        indicators['malware_detections'] += 1
                    elif event_id == 2033:
                        indicators['firewall_blocks'] += 1
                    elif event_id in [5156, 5157]:
                        indicators['network_connections'] += 1
                    
                    # Check for suspicious processes
                    description = event.get('description', '').lower()
                    for pattern in self.suspicious_patterns:
                        if re.search(pattern, description, re.IGNORECASE):
                            indicators['suspicious_processes'] += 1
                            break
            
        except Exception as e:
            self.logger.error(f"Error scanning for indicators: {e}")
        
        return indicators

    def get_system_health_status(self) -> Dict[str, any]:
        """Get overall system health status based on log analysis"""
        try:
            indicators = self.scan_for_indicators()
            
            # Calculate threat level
            threat_score = 0
            threat_score += indicators['failed_logons'] * 2
            threat_score += indicators['privilege_escalations'] * 10
            threat_score += indicators['malware_detections'] * 25
            threat_score += indicators['firewall_blocks'] * 3
            threat_score += indicators['suspicious_processes'] * 15
            threat_score += indicators['network_connections'] * 1
            
            # Determine threat level
            if threat_score >= 50:
                threat_level = 'CRITICAL'
                status = 'Multiple security threats detected'
            elif threat_score >= 20:
                threat_level = 'HIGH'
                status = 'Security threats present'
            elif threat_score >= 5:
                threat_level = 'MEDIUM'
                status = 'Some security activity detected'
            else:
                threat_level = 'LOW'
                status = 'System appears secure'
            
            return {
                'threat_level': threat_level,
                'threat_score': threat_score,
                'status': status,
                'indicators': indicators,
                'last_scan': datetime.now().isoformat(),
                'monitoring_active': self.running
            }
            
        except Exception as e:
            self.logger.error(f"Error getting system health status: {e}")
            return {
                'threat_level': 'UNKNOWN',
                'threat_score': 0,
                'status': 'Error retrieving system status',
                'indicators': {},
                'last_scan': datetime.now().isoformat(),
                'monitoring_active': False
            }

# Global system scanner instance
_system_scanner = None

def get_system_scanner(user_id: int) -> WindowsSystemLogScanner:
    """Get or create the global system scanner instance"""
    global _system_scanner
    if _system_scanner is None:
        _system_scanner = WindowsSystemLogScanner(user_id)
    return _system_scanner

def start_system_monitoring(user_id: int) -> bool:
    """Start system log monitoring"""
    scanner = get_system_scanner(user_id)
    return scanner.start_monitoring()

def stop_system_monitoring():
    """Stop system log monitoring"""
    global _system_scanner
    if _system_scanner:
        _system_scanner.stop_monitoring()

def get_system_health() -> Dict[str, any]:
    """Get current system health status"""
    global _system_scanner
    if _system_scanner:
        return _system_scanner.get_system_health_status()
    return {
        'threat_level': 'UNKNOWN',
        'threat_score': 0,
        'status': 'System monitoring not active',
        'indicators': {},
        'last_scan': datetime.now().isoformat(),
        'monitoring_active': False
    }
