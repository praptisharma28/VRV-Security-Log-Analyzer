# Security Log Analyzer🛡️

## Overview
A sophisticated Python-based log analysis tool designed for cybersecurity professionals to detect, analyze, and visualize potential security threats from web server logs.

## Features
- Detailed IP request analysis
- Suspicious activity detection
- Endpoint access tracking
- Threat score calculation
- Geolocation insights
- Interactive visualizations

## Prerequisites
- Python 3.8+
- Required libraries:
  ```
  pip install requests plotly numpy scipy
  ```

## Installation
1. Clone the repository
   ```bash
   git clone https://github.com/praptisharma28/vrv-security-log-analyzer.git
   cd vrv-security-log-analyzer
   ```

2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

## Usage
```bash
python3 main.py 
```

## Output Files
- `log_analysis_results.csv`: Detailed log analysis
- `comprehensive_log_report.json`: Advanced threat insights
- `ip_requests_visualization.html`: Request distribution chart
- `endpoint_access_heatmap.html`: Endpoint access visualization

## Project Structure
- `main.py`: Primary execution script
- `loganalyzer.py`: Log parsing and basic analysis
- `threat_detection.py`: Advanced threat detection algorithms
- `visualization.py`: Data visualization components
- `utils.py`: Utility functions for additional processing

## Submission Guidelines
- Ensure all dependencies are installed
- Provide a sample log file
- Run the script and review generated reports
