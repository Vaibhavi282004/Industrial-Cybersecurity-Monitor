# Industrial Cybersecurity Monitor

An OT (Operational Technology) cybersecurity monitoring dashboard designed to provide visibility into industrial assets, security events, threat detection, and risk analysis.

## Features

- OT asset inventory monitoring
- Security event monitoring
- Threat detection and alert analysis
- Risk assessment for industrial assets
- Security severity visualization
- Interactive Streamlit dashboard
- CSV-based OT security data
- Python-based detection and risk analysis

## Technology Stack

- Python
- Streamlit
- Pandas
- NumPy
- SQLite
- Scikit-learn
- Matplotlib

## Project Structure

```text
Industrial-Cybersecurity-Monitor/
│
├── dashboard/
│   └── app.py
│
├── data/
│   ├── detected_security_events.csv
│   ├── ot_assets.csv
│   ├── ot_network_logs.csv
│   └── security_alerts.csv
│
├── src/
│   ├── database.py
│   ├── evaluate_detection.py
│   ├── generate_logs.py
│   ├── risk_engine.py
│   └── threat_detection.py
│
└── .gitignore
