from loganalyzer import LogAnalyzer
from threat_detection import AdvancedThreatDetector
from visualization import SecurityVisualizer
from utils import generate_comprehensive_report

def main(log_file_path='sample.log'):
    """
    Main function to orchestrate log analysis, threat detection, and reporting.
    """
    log_analyzer = LogAnalyzer(log_file_path)
    log_analyzer.parse_log_file()
    log_analyzer.generate_report()
    log_analyzer.save_results_to_csv()
    threat_detector = AdvancedThreatDetector(log_analyzer.log_entries)
    comprehensive_report = generate_comprehensive_report(log_analyzer, threat_detector)
    print("\n📊 Comprehensive Report Generated: comprehensive_log_report.json")
    visualizer = SecurityVisualizer(log_analyzer)
    print("\n🖼️ Generating Visualizations...")
    ip_requests_viz = visualizer.ip_request_distribution()
    print("✅ IP Requests Distribution Visualization: ip_requests_visualization.html")
    endpoint_heatmap_viz = visualizer.endpoint_access_heatmap()
    print("✅ Endpoint Access Heatmap: endpoint_access_heatmap.html")
    anomalies = threat_detector.ml_anomaly_detection()
    print("\n🚨 Anomalies Detected:")
    for anomaly in anomalies:
        print(f"Timestamp: {anomaly['timestamp']}, Interval: {anomaly['interval']}, Z-Score: {anomaly['z_score']}")
    threat_predictions = threat_detector.predict_future_threats()
    print("\n🔮 Potential Future Threat Targets:")
    for ip in threat_predictions['potential_targets']:
        print(f"IP: {ip}")
    print("\n🛡️ IP Threat Scores:")
    for ip, details in comprehensive_report['ip_threat_scores'].items():
        print(f"IP: {ip}, Threat Score: {details['threat_score']}, Country: {details['geolocation'].get('country', 'Unknown')}")

if __name__ == "__main__":
    main()
