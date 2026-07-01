# 🔍 Deep Packet Inspection (DPI) Engine

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.5.0%2B-green.svg)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A production-ready **Deep Packet Inspection** engine for real-time network traffic analysis and offline PCAP forensics. Built with Python and Scapy, featuring protocol detection, signature-based threat identification, and structured reporting.

![DPI Banner](https://img.shields.io/badge/DPI-Engine-red?style=for-the-badge)

---

## 👨‍💻 Developer

<table>
  <tr>
    <td align="center">
      <img src="photo.jpg" width="120px" height="120px" style="border-radius:50%"/><br>
      <strong>Mohammed Waseem Siddique</strong><br>
      <em>Cybersecurity & Network Intelligence Engineer</em>
    </td>
  </tr>
</table>

> 🔥 **Open to impactful opportunities** — Ready to invest my time into challenging projects in network security, backend engineering, and system design.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Demo](#-demo)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Threat Signatures](#-threat-signatures)
- [Technologies Used](#-technologies-used)
- [Results & Output](#-results--output)
- [Future Enhancements](#-future-enhancements)
- [Contributing](#-contributing)
- [Contact](#-contact)

---

## ✨ Features

### Core Capabilities
- 🔴 **Live Packet Capture** — Sniff traffic on any network interface in real-time
- 🔵 **Offline PCAP Analysis** — Forensic analysis of pre-recorded packet captures
- 🟢 **Protocol Detection** — Identifies HTTP, DNS, TLS (SNI), SSH, FTP
- 🟡 **Threat Intelligence** — Signature-based detection of 6+ attack patterns
- 📊 **CSV Reporting** — Structured logging with timestamps, IPs, and severity levels

### Security Detection
| Threat Type | Pattern | Severity |
|-------------|---------|----------|
| SQL Injection | `UNION SELECT`, `' OR '1'='1` | 🔴 CRITICAL |
| XSS Attacks | `<script>`, `javascript:` | 🔴 CRITICAL |
| Reverse Shells | `/bin/bash`, `nc -e` | 🟠 HIGH |
| Command Injection | `cmd.exe`, encoded PowerShell | 🟠 HIGH |
| Suspicious User-Agent | `curl`, `wget`, `python-requests` | 🟡 LOW |

---

## 🏗 Architecture
┌─────────────────────────────────────────────────────────┐
│ DPI ENGINE │
│ │
│ ┌──────────────┐ ┌──────────────┐ ┌────────────┐ │
│ │ Packet │ │ Protocol │ │ Signature │ │
│ │ Capture │──▶│ Detector │──▶│ Matcher │ │
│ │ (Scapy) │ │ (HTTP/DNS) │ │ (Regex) │ │
│ └──────────────┘ └──────────────┘ └────────────┘ │
│ │ │
│ ┌────────▼─────┐│
│ │ CSV Logger ││
│ └──────────────┘│
└─────────────────────────────────────────────────────────┘

### Design Patterns
- **Modular Architecture** — Each component is independent and testable
- **Strategy Pattern** — Protocol detectors implement consistent interfaces
- **Observer Pattern** — Logger observes and records all detection events
- **Separation of Concerns** — Config, detection, matching, and logging are isolated

---

## 🎮 Demo

### Live Capture Mode
```bash
$ sudo python main.py -i eth0

    ____  ___   ____    ____  _  _______   ____
   / __ \/   | / __ \  / __ \/ |/ / ___/  /  _/
  / /_/ / /| |/ /_/ / / /_/ /    / /__  _/ /  
 / ____/ ___ / ____/ / ____/ /|  / /_/  / /   
/_/   /_/  |_/_/     /_/   /_/ |_/_____/ /___/ 

============================================================
   Developed by: Mohammed Waseem Siddique
   Ready to invest my time into more projects
   and real-world impactful opportunities.
============================================================

INFO - Sniffing on interface eth0 ... (Ctrl+C to stop)
INFO - HTTP | 192.168.1.100 -> 93.184.216.34 [HTTP] Request GET example.com/
INFO - DNS | 192.168.1.100 -> 8.8.8.8 [DNS] Query google.com
🚨 Threat detected: SQL Injection attempt from 10.0.0.5 to 192.168.1.10

PCAP Analysis
$ python main.py -r suspicious_traffic.pcap -o forensic_report.csv