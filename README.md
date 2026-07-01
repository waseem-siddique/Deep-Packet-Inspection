# Deep Packet Inspection Engine

A high-performance **Deep Packet Inspection (DPI)** engine designed to analyze network traffic in real time and perform offline forensic analysis using PCAP files. The application identifies application-layer protocols and detects potentially malicious network activity through signature-based threat detection.

Developed by **Mohammed Waseem Siddique**.

---

# About the Developer

Hi, I'm **Mohammed Waseem Siddique**, a Computer Science student with a strong interest in **Cybersecurity, Network Security, Threat Detection, and Software Development**.

This project was built to demonstrate practical knowledge of packet analysis, protocol identification, and intrusion detection while applying real-world networking concepts in a production-style application.

I'm passionate about building secure, scalable, and impactful software solutions, and I'm always eager to learn new technologies and contribute to meaningful projects.

---

# Project Overview

The **Deep Packet Inspection Engine** provides both live network monitoring and offline packet analysis to help identify network protocols and detect suspicious or malicious traffic patterns.

### Key Features

* Capture and inspect live network traffic from any available network interface.
* Analyze PCAP files for offline investigation and digital forensics.
* Automatically identify common application-layer protocols, including:

  * HTTP
  * DNS
  * TLS (including Server Name Indication (SNI) extraction)
  * SSH
  * FTP
* Detect known attack signatures using pattern matching, including:

  * SQL Injection
  * Cross-Site Scripting (XSS)
  * Command Injection
  * Reverse Shell payloads
* Generate structured CSV reports containing:

  * Timestamp
  * Source and Destination IP Addresses
  * Detected Protocol
  * Threat Severity
  * Detection Details

---

# Installation

Clone the repository and install the required dependencies.

```bash
git clone https://github.com/yourusername/deep-packet-inspection.git
cd deep-packet-inspection
pip install -r requirements.txt
```
