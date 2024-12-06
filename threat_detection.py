import numpy as np
from scipy import stats
from datetime import datetime
from collections import Counter

class AdvancedThreatDetector:
    def __init__(self, log_entries):
        """
        Initialize threat detector with log entries
        """
        self.log_entries = log_entries
        self.threat_weights = {
            'login_attempts': 0.4,
            'unique_endpoints': 0.3,
            'request_volume': 0.2,
            'time_concentration': 0.1
        }
    
    def ml_anomaly_detection(self):
        """
        Use statistical methods to detect unusual network behavior
        """
        request_times = [datetime.strptime(entry['timestamp'], '%d/%b/%Y:%H:%M:%S %z') 
                         for entry in self.log_entries]  
        request_intervals = [
            (request_times[i+1] - request_times[i]).total_seconds() 
            for i in range(len(request_times) - 1)
        ]     
        if len(request_intervals) < 2:
            return []     
        z_scores = np.abs(stats.zscore(request_intervals))   
        anomalies = [
            {
                'timestamp': str(request_times[i]), 
                'interval': f"{request_intervals[i]:.2f} seconds", 
                'z_score': z_score
            }
            for i, z_score in enumerate(z_scores)
            if z_score > 2.5  
        ]  
        return anomalies
    
    def predict_future_threats(self):
        """
        Basic predictive modeling of potential future security threats
        """
        ip_attack_patterns = Counter()
        for entry in self.log_entries:
            if entry.get('is_failed_login', False):
                ip_attack_patterns[entry['ip']] += 1
        potential_targets = ip_attack_patterns.most_common(3) 
        return {
            'potential_targets': [ip for ip, count in potential_targets],
            'attack_pattern_confidence': dict(ip_attack_patterns)
        }
    
    def calculate_ip_threat_score(self, ip):
        """
        Calculate a comprehensive threat score for an IP
        """
        ip_entries = [entry for entry in self.log_entries if entry['ip'] == ip]
        failed_logins = sum(1 for entry in ip_entries if entry.get('is_failed_login', False))
        login_score = min(failed_logins * 10, 40)  
        unique_endpoints = len(set(entry['endpoint'] for entry in ip_entries))
        endpoint_score = min(unique_endpoints * 5, 30)   
        request_volume = len(ip_entries)
        volume_score = min(request_volume * 2, 20)
        if ip_entries:
            timestamps = [datetime.strptime(entry['timestamp'], '%d/%b/%Y:%H:%M:%S %z') for entry in ip_entries]
            time_spread = (max(timestamps) - min(timestamps)).total_seconds()
            time_score = 10 if time_spread < 60 else 0  
        else:
            time_score = 0    
        total_score = login_score + endpoint_score + volume_score + time_score
        return min(total_score, 100)
