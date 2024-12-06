import requests
import json
from datetime import datetime

def get_ip_geolocation(ip_address):
    """
    Retrieve geographical information for an IP address
    """
    try:
        response = requests.get(f'https://ipapi.co/{ip_address}/json/')
        geo_data = response.json()
        return {
            'country': geo_data.get('country_name', 'Unknown'),
            'city': geo_data.get('city', 'Unknown'),
            'latitude': geo_data.get('latitude'),
            'longitude': geo_data.get('longitude'),
            'region': geo_data.get('region', 'Unknown'),
            'org': geo_data.get('org', 'Unknown')
        }
    except Exception as e:
        return {
            'error': str(e),
            'ip': ip_address
        }

def generate_comprehensive_report(log_analyzer, threat_detector):
    """
    Create a detailed JSON report with deep insights
    """
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_requests': sum(log_analyzer.ip_requests.values()),
            'unique_ips': len(log_analyzer.ip_requests),
            'most_active_ip': max(log_analyzer.ip_requests, key=log_analyzer.ip_requests.get)
        },
        'suspicious_activity': {
            'high_risk_ips': list(log_analyzer.identify_suspicious_activity().keys()),
            'failed_login_attempts': dict(log_analyzer.failed_login_attempts)
        },
        'endpoint_analysis': dict(log_analyzer.endpoint_counts),
        'anomaly_detection': threat_detector.ml_anomaly_detection(),
        'threat_predictions': threat_detector.predict_future_threats()
    }
    report['ip_threat_scores'] = {}
    for ip in log_analyzer.ip_requests.keys():
        report['ip_threat_scores'][ip] = {
            'threat_score': threat_detector.calculate_ip_threat_score(ip),
            'geolocation': get_ip_geolocation(ip)
        }
    with open('comprehensive_log_report.json', 'w') as f:
        json.dump(report, f, indent=2) 
    return report
