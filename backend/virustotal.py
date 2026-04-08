# File: backend/virustotal.py

import requests
import yaml
import os
import json
from datetime import datetime
from backend.logger import log_info, log_error

# Load config
with open(os.path.join(os.path.dirname(__file__), "..", "config.yaml"), 'r') as f:
    cfg = yaml.safe_load(f)

VT_API_KEY = cfg.get("virustotal", {}).get("api_key", "")
VT_ENABLED = cfg.get("virustotal", {}).get("enabled", False)

class VirusTotalClient:
    def __init__(self):
        self.api_key = VT_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.enabled = VT_ENABLED and self.api_key != ""
        
        if not self.enabled:
            log_info("VirusTotal API integration is disabled or missing API key")
        else:
            log_info("VirusTotal API integration is enabled")
    
    def check_ip(self, ip_address):
        """Check an IP address against VirusTotal API
        
        Args:
            ip_address (str): The IP address to check
            
        Returns:
            dict: Result with malicious status and details
        """
        if not self.enabled:
            return {
                "success": False,
                "is_malicious": False,
                "message": "VirusTotal API is disabled",
                "details": {}
            }
        
        try:
            url = f"{self.base_url}/ip_addresses/{ip_address}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                # Determine if malicious based on detection ratio
                malicious_count = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)
                total_engines = sum(stats.values()) if stats else 0
                
                is_malicious = False
                if total_engines > 0:
                    malicious_ratio = (malicious_count + suspicious_count) / total_engines
                    is_malicious = malicious_ratio >= 0.05  # 5% threshold
                
                return {
                    "success": True,
                    "is_malicious": is_malicious,
                    "message": "IP checked successfully",
                    "details": {
                        "stats": stats,
                        "reputation": attributes.get("reputation", 0),
                        "country": attributes.get("country", "Unknown"),
                        "as_owner": attributes.get("as_owner", "Unknown"),
                        "last_analysis_date": attributes.get("last_analysis_date", 0)
                    }
                }
            elif response.status_code == 404:
                return {
                    "success": True,
                    "is_malicious": False,
                    "message": "IP not found in VirusTotal database",
                    "details": {}
                }
            else:
                log_error(f"VirusTotal API error: {response.status_code} - {response.text}")
                return {
                    "success": False,
                    "is_malicious": False,
                    "message": f"API error: {response.status_code}",
                    "details": {}
                }
                
        except Exception as e:
            log_error(f"VirusTotal API request failed: {str(e)}")
            return {
                "success": False,
                "is_malicious": False,
                "message": f"Request failed: {str(e)}",
                "details": {}
            }
    
    def get_formatted_report(self, ip_address):
        """Get a formatted report for an IP address
        
        Args:
            ip_address (str): The IP address to check
            
        Returns:
            str: Formatted report text
        """
        result = self.check_ip(ip_address)
        
        if not result["success"]:
            return f"VirusTotal check failed: {result['message']}"
        
        details = result["details"]
        stats = details.get("stats", {})
        
        if not stats:
            return "No VirusTotal data available for this IP"
        
        # Format the report
        report = ["=== VirusTotal Report ==="]
        report.append(f"IP: {ip_address}")
        report.append(f"Status: {'🔴 Malicious' if result['is_malicious'] else '🟢 Clean'}")
        
        if stats:
            report.append(f"Detection: {stats.get('malicious', 0)} malicious, {stats.get('suspicious', 0)} suspicious")
            report.append(f"Engines: {sum(stats.values())} total")
        
        if details.get("country"):
            report.append(f"Country: {details['country']}")
        
        if details.get("as_owner"):
            report.append(f"Owner: {details['as_owner']}")
        
        if details.get("last_analysis_date"):
            date = datetime.fromtimestamp(details["last_analysis_date"]).strftime('%Y-%m-%d %H:%M:%S')
            report.append(f"Last Analysis: {date}")
        
        return "\n".join(report)

# Create a singleton instance
vt_client = VirusTotalClient()

# Convenience functions
def check_ip(ip_address):
    return vt_client.check_ip(ip_address)

def get_formatted_report(ip_address):
    return vt_client.get_formatted_report(ip_address)