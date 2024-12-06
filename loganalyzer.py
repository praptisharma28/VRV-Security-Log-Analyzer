import re
import csv
from collections import defaultdict

class LogAnalyzer:
    def __init__(self, log_file_path='sample.log'):
        """
        Initialize the LogAnalyzer with the log file path.
        
        Args:
            log_file_path (str): Path to the log file to analyze
        """
        self.log_file_path = log_file_path
        self.log_entries = []
        self.ip_requests = defaultdict(int)
        self.endpoint_counts = defaultdict(int)
        self.failed_login_attempts = defaultdict(int)
    
    def parse_log_file(self):
        """
        Parse the log file and extract relevant information.
        
        Returns:
            None: Populates instance variables with parsed data
        """
        with open(self.log_file_path, 'r') as log_file:
            for line in log_file:
                match = re.match(
                    r'(\S+) .* \[(.+)\] "(\w+) (/\S*) HTTP/\d\.\d" (\d+) \d+ ?(.*)?', 
                    line.strip()
                )
                
                if match:
                    ip_address, timestamp, method, endpoint, status_code, extra_info = match.groups()
                    self.ip_requests[ip_address] += 1
                    self.endpoint_counts[endpoint] += 1
                    is_failed_login = status_code == '401' or (extra_info and 'Invalid credentials' in extra_info)
                    if is_failed_login:
                        self.failed_login_attempts[ip_address] += 1
                    self.log_entries.append({
                        'ip': ip_address,
                        'timestamp': timestamp,
                        'method': method,
                        'endpoint': endpoint,
                        'status_code': status_code,
                        'is_failed_login': is_failed_login,
                        'extra_info': extra_info
                    })
    
    def identify_suspicious_activity(self, threshold=3):
        """
        Identify IPs with suspicious login activity.
        
        Args:
            threshold (int): Number of failed attempts to consider suspicious
        
        Returns:
            dict: IP addresses exceeding the failed login threshold
        """
        return {ip: count for ip, count in self.failed_login_attempts.items() if count > threshold}
    
    def generate_report(self):
        """
        Generate a comprehensive report of log analysis.
        """
        print("\n🔍 Log Analysis Report 🔍")
        print("-" * 40)
        # IP Request Counts
        print("\nIP Request Counts:")
        for ip, count in sorted(self.ip_requests.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:<20} {count}")
        # Most Frequently Accessed Endpoint
        print("\nMost Frequently Accessed Endpoint:")
        most_accessed_endpoint = max(self.endpoint_counts.items(), key=lambda x: x[1])
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
        # Suspicious Activity
        print("\nSuspicious Activity Detected:")
        suspicious_ips = self.identify_suspicious_activity()
        if suspicious_ips:
            for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
                print(f"{ip:<20} {count} failed login attempts")
        else:
            print("No suspicious IPs detected.")
    
    def save_results_to_csv(self, output_file='log_analysis_results.csv'):
        """
        Save analysis results to a CSV file.
        """
        with open(output_file, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            # IP Requests Section
            csv_writer.writerow(['Requests per IP'])
            csv_writer.writerow(['IP Address', 'Request Count'])
            for ip, count in sorted(self.ip_requests.items(), key=lambda x: x[1], reverse=True):
                csv_writer.writerow([ip, count])
            # Most Accessed Endpoint Section
            csv_writer.writerow([])  
            csv_writer.writerow(['Most Accessed Endpoint'])
            csv_writer.writerow(['Endpoint', 'Access Count'])
            most_accessed = max(self.endpoint_counts.items(), key=lambda x: x[1])
            csv_writer.writerow(most_accessed)
            # Suspicious Activity Section
            csv_writer.writerow([]) 
            csv_writer.writerow(['Suspicious Activity'])
            csv_writer.writerow(['IP Address', 'Failed Login Count'])
            suspicious_ips = self.identify_suspicious_activity()
            for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
                csv_writer.writerow([ip, count])
        
        print(f"\nResults saved to {output_file}")
