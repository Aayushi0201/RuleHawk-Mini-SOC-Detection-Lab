# RuleHawk: Mini SOC Detection Engineering Lab

RuleHawk is a Python and Streamlit-based Mini SOC project that detects suspicious activity from security logs using YAML-based detection rules.

## Features

- Parses Linux auth logs, Apache access logs, Windows Sysmon CSV, and normalized CSV logs
- Uses Sigma-style YAML detection rules
- Supports single-event, aggregation, correlation, and exclusion-based detections
- Maps alerts to MITRE ATT&CK techniques
- Assigns severity and risk scores
- Provides SOC dashboard, Rule Library, Rule Lab, CSV export, and HTML incident reports

## Detection Examples

- Suspicious PowerShell encoded command
- Certutil file download
- Registry Run Key persistence
- SSH brute force
- Successful login after multiple failures
- SQL injection attempt
- Directory traversal
- Web scanner activity

## Installation

```bash
git clone https://github.com/Aayushi0201/RuleHawk-Mini-SOC-Detection-Lab.git
cd RuleHawk-Mini-SOC-Detection-Lab
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
