# 🔒 Security Monitoring System

Advanced cybersecurity threat detection system built with Python. Implements automated anomaly detection and brute force attack identification for healthcare environments.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()

## 📋 Project Overview

This project demonstrates practical cybersecurity monitoring techniques through custom-built detection algorithms. Developed as part of an advanced cybersecurity case study analyzing **NexaHealth Solutions Ltd**, a mid-sized digital health services provider in Nairobi, Kenya.

### Key Features

- **Anomaly Detection Engine**: Identifies unusual access patterns to sensitive data
- **Brute Force Detection**: Recognizes credential stuffing and password attack attempts
- **Behavioral Baseline Learning**: Establishes normal user behavior patterns
- **Real-time Alert System**: Generates severity-based security alerts
- **Automated Response**: Implements IP blocking and password reset protocols

## 🎯 Detection Capabilities

### Anomaly Detection
- **Volume Anomalies**: Flags access exceeding 3 standard deviations from baseline
- **Temporal Anomalies**: Detects off-hours access outside typical working patterns
- **Geographic Anomalies**: Identifies access from unexpected locations
- **Multi-factor Correlation**: Combines multiple indicators for high-confidence alerts

### Brute Force Detection
- **Failed Login Tracking**: Monitors authentication attempts per IP address
- **Time-window Analysis**: Detects attack patterns within configurable timeframes
- **Automated Blocking**: Triggers IP blacklisting after threshold exceeded
- **User Protection**: Forces password resets for targeted accounts

## 🚀 Getting Started

### Prerequisites

```bash
Python 3.11 or higher
pandas
numpy
```
## Installation
### 1. Clone the repository
```bash
git clone https://github.com/yourusername/security-monitoring-system.git
cd security-monitoring-system
```
### 2. Create virtual environment
```bash
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\Activate.ps1
# Mac/Linux:
source venv/bin/activate
```
### 3. Install dependencies
```bash
pip install pandas numpy
```
## Quick Start
### 1. Generate test data
```bash
python scripts/generate_test_data.py
```
### 2. Run anomaly detection
```bash
python scripts/anomaly_detector.py
```
### 3. Run brute force detection
```bash
python scripts/brute_force_detector.py
```

## 📁 Project Structure
```text
security-monitoring-system/
├── scripts/
│   ├── anomaly_detector.py       # Anomaly detection engine
│   ├── brute_force_detector.py   # Brute force detection system
│   └── generate_test_data.py     # Test data generator
├── data/
│   ├── historical_access_logs.csv    # Baseline training data
│   ├── current_access_log.txt        # Real-time access logs
│   └── auth_log.txt                  # Authentication logs
├── logs/
│   └── (generated alert logs)
├── README.md
└── requirements.txt
```
## 📈 Technical Details
### Anomaly Detection Algorithm
- **Baseline Learning: Statistical analysis of historical user behavior
- **Feature Extraction: Access volume, time patterns, geographic locations
- **Threshold Calculation: Mean + (3 × Standard Deviation)
- **Multi-dimensional Analysis: Correlates multiple anomaly indicators
- **Severity Assignment: Risk-based alert prioritization

## Brute Force Detection Algorithm
- **Sliding Window: Tracks failed attempts within configurable timeframe
- **IP-User Pairing: Associates attack patterns with specific targets
- **Threshold Monitoring: Triggers alerts when limit exceeded
- **Automated Response: Blocks IPs and enforces password resets
- **Attack Attribution: Identifies geographic origin and patterns

## 🎓 Academic Context
This project was developed as part of an advanced cybersecurity case study analyzing:

- **Systems & Network Security: Infrastructure vulnerability assessment
- **Applied Cryptography: Data protection and encryption strategies
- **Governance, Risk & Compliance (GRC): Organizational security framework
- **Security Automation: Python-based monitoring and response systems
- **Professional Ethics: Responsible disclosure and patient data protection

## Case Study: NexaHealth Solutions Ltd
Mid-sized digital health services provider, Nairobi, Kenya

### Key Findings:

- **Identity & Access Management identified as highest priority risk
- **Password-only authentication creates critical vulnerability
- **Security awareness gaps enable social engineering attacks
- **Lack of automated monitoring delays breach detection

## 🛡️ Security Considerations
Important: This is an educational project demonstrating security concepts.

For production use, consider:

- **Integration with enterprise SIEM platforms (Splunk, ELK)
- **Encrypted log storage and transmission
- **Role-based access control (RBAC)
- **Compliance with data protection regulations (GDPR, HIPAA, Kenya DPA)
- **Professional penetration testing
- **Incident response playbooks

## 🤝 Contributing
Contributions are welcome! Areas for enhancement:

- **Real-time log streaming support
- **Email/SMS alert notifications
- **Dashboard visualization (Streamlit/Dash)
- **Machine learning-based anomaly detection
- **Integration with external threat intelligence feeds
- **Support for additional log formats (Syslog, JSON)

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments
- **Inspired by threat detection methodologies from Brian Krebs, Bruce Schneier, and Troy Hunt
- **Built for cybersecurity education and practical threat modeling
- **Thanks to the open-source security community

## 📚 References
- **NIST Cybersecurity Framework
- **OWASP Top 10
- **Verizon Data Breach Investigations Report
- **Kenya Data Protection Act 2019

## 👥 Author
- [Paul Omondi](https://github.com/PaulJkr)

## 📞 Need Help?
- Create an issue on GitHub
- Ask in the team chat
- Check the documentation links above

---

**Happy Coding! 🎉**
