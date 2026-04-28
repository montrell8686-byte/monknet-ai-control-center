# Monknet AI Control Center v1.0

Monknet AI Control Center is a real-time cybersecurity monitoring dashboard built with Python (Flask) that simulates core Security Operations Center (SOC) functionality.

## 🔍 Overview
This project was designed to explore how security monitoring systems detect and analyze suspicious activity. It focuses on transforming system and authentication data into actionable insights through a clean, modern interface.

## 🚀 Features
- Live system monitoring (CPU & RAM)
- Real-time system clock
- Failed login detection
- Event tracking with timestamps, accounts, and IP addresses
- Detection of rapid repeated login attempts (brute-force patterns)
- Dynamic threat classification (LOW / MEDIUM / HIGH)
- Visual alert escalation for high-risk activity

## 🧠 Detection Logic
The system analyzes login attempts and identifies patterns such as rapid repeated activity. If multiple failed attempts occur within short time intervals, the system escalates the threat level accordingly.

This simulates how SOC environments detect brute-force attacks and suspicious authentication behavior.

## ⚙️ Tech Stack
- Python
- Flask
- HTML / CSS / JavaScript
- psutil

## 🧪 Current Status
**Detection Mode:** Simulated Events (Testing Phase)

The system currently uses simulated events to validate detection logic and UI behavior. The architecture is designed to support integration with real system logs.

## 🔮 Future Improvements
- Integration with real Windows Event Logs and Linux logs
- Expanded detection rules and anomaly analysis
- Automated alerting and response system
- Network scanning integration (e.g., Nmap)

## 📸 Preview

### System Dashboard
![Dashboard](dashboard.png)

### Security Events Detection
![Security Events](security-events.png)

## 🛠️ How to Run
```bash
pip install flask psutil
python main.py
