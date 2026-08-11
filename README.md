# MITM Attack Detection via Digital Certificate Analysis

## About the Project
This project is an automated security tool designed to proactively identify Man-in-the-Middle (MITM) attacks, with a specific focus on SSL/TLS stripping and unauthorized certificate spoofing. 

By extracting, parsing, and analyzing digital certificates directly from live network traffic or PCAP files, the system acts as a real-time detection engine. It compares intercepted certificates against a trusted baseline to immediately flag anomalies, forged signatures, and potential eavesdropping attempts.

## System Architecture
The project is divided into two core modules:
* **MITM_Collector**: Responsible for capturing network traffic and extracting SSL/TLS certificates (PEM format) from raw packets or PCAP files.
* **MITM_Detector**: The core analysis engine that runs rule-based checks, compares intercepted certificates against trusted baselines, and logs security alerts.

## Key Features
* **Automated Extraction:** Parses live network traffic and PCAP files to extract digital certificates.
* **Baseline Comparison:** Validates incoming certificates against a pre-defined trusted baseline.
* **Anomaly Detection:** Identifies forged signatures, unexpected issuer changes, and SSL/TLS stripping attempts.
* **Security Logging:** Generates detailed logs of flagged events for incident response.

## Built With
* **Language:** Python 3.x
* **Network Analysis:** Wireshark (for packet capturing and traffic validation)
* **Concepts:** Applied Cryptography, Network Perimeter Defense, SSL/TLS Protocols

## Getting Started
### Usage
**1. Certificate Collection:**
Navigate to the Collector module to extract certificates from your `.pcap` files.
```bash
cd MITM_Collector
python extract_cert.py

2. Attack Detection:
Navigate to the Detector module to run the analysis against the extracted certificates.
cd MITM_Detector
python run_check.py
Proof of Concept
This system was rigorously validated against simulated attack scenarios using network protocol analyzers. It serves as a solid proof-of-concept for enhancing network perimeter defenses and proactively mitigating internal/external eavesdropping threats.
