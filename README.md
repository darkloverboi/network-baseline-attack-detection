# 🛡️ Network Baseline Attack Detection System

<p align="center">
<img width="1920" height="1020" alt="Screenshot 2026-02-27 214705" src="https://github.com/user-attachments/assets/f4cb60f3-33a6-42ca-8dbc-05f13c45bbf6" />

</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/Scapy-2.5%2B-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge"/>
</p>

> A real-time network traffic monitoring and attack detection system that establishes a **statistical baseline** of normal network behavior and raises alerts when anomalies or known attack patterns are detected.

---

## 📌 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Attack Types Detected](#attack-types-detected)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [Tech Stack](#tech-stack)
- [Contributing](#contributing)
- [License](#license)

---

## 🔍 Overview

The **Network Baseline Attack Detection System** is a Python-based cybersecurity tool designed to monitor live or captured network traffic, learn what "normal" looks like for a given network, and flag deviations that indicate potential attacks. Unlike traditional signature-only systems, this tool uses **statistical thresholding** and **behavioral analysis** alongside pattern matching to catch both known and anomalous threats.

---

## ✨ Features

- 📊 **Baseline Learning** — Automatically profiles normal network traffic (packet rate, byte volume, protocol distribution) over a configurable time window
- 🚨 **Real-Time Alerting** — Generates alerts when traffic deviates beyond statistical thresholds (mean ± N × std dev)
- 🔎 **Multi-Protocol Analysis** — Monitors TCP, UDP, ICMP, ARP, and DNS traffic simultaneously
- 🧠 **Attack Pattern Recognition** — Detects common attack signatures including SYN floods, port scans, ICMP floods, and ARP spoofing
- 📁 **PCAP Support** — Analyze pre-captured `.pcap` / `.pcapng` files as well as live interfaces
- 📈 **Traffic Statistics Dashboard** — View real-time counts, rates, top talkers, and protocol breakdown
- 🪵 **Logging** — All alerts and traffic summaries are saved to structured log files for audit and review
- ⚙️ **Configurable Thresholds** — Easily tune detection sensitivity through a config file

---

## ⚙️ How It Works

```
[ Network Interface / PCAP File ]
           │
           ▼
   [ Packet Capture Engine ]   ← Scapy / PyShark
           │
           ▼
   [ Traffic Parser & Classifier ]
           │
      ┌────┴────┐
      ▼         ▼
 [Baseline   [Attack Pattern
  Profiler]   Matcher]
      │         │
      └────┬────┘
           ▼
    [ Anomaly Detector ]
    (Z-score / Threshold)
           │
           ▼
    [ Alert Generator ]
    (Console + Log File)
```

**Phase 1 – Baseline Collection:** During an initial observation window (default: 60 seconds), the system captures packets and builds a statistical profile of normal traffic — average packets per second, bytes per second, SYN/ACK ratios, etc.

**Phase 2 – Live Detection:** Post-baseline, incoming packets are compared against the profile in real time. Any metric exceeding the configured standard deviation threshold triggers an alert.

**Phase 3 – Pattern Matching:** In parallel, packets are inspected for known attack signatures (e.g., a flood of SYN packets with no ACK, repetitive ICMP echo requests, ARP replies with no prior request).

---

## 🎯 Attack Types Detected

| Attack | Detection Method |
|---|---|
| **SYN Flood (DoS)** | High SYN/ACK ratio + packet rate anomaly |
| **ICMP Flood (Ping Flood)** | ICMP packet rate exceeds baseline threshold |
| **UDP Flood** | Sudden spike in UDP traffic volume |
| **Port Scan** | Single source hitting multiple destination ports |
| **ARP Spoofing / Poisoning** | Unsolicited ARP replies or MAC changes |
| **DNS Amplification** | Unusually large DNS response sizes |
| **Brute Force (SSH/FTP)** | Repeated TCP connection attempts to port 22/21 |
| **Traffic Volume Anomaly** | General statistical deviation from baseline |

---

## 📁 Project Structure

```
network-baseline-attack-detection/
│
├── main.py                   # Entry point — starts capture and detection
├── config.py                 # Configuration: interface, thresholds, timeouts
├── requirements.txt          # Python dependencies
│
├── core/
│   ├── capture.py            # Packet capture using Scapy
│   ├── parser.py             # Packet parsing and feature extraction
│   ├── baseline.py           # Baseline profiling and statistics
│   ├── detector.py           # Anomaly detection and attack matching
│   └── alerter.py            # Alert formatting and logging
│
├── utils/
│   ├── logger.py             # Logging utilities
│   └── helpers.py            # IP/MAC utility functions
│
├── logs/                     # Generated alert and traffic logs
├── pcap_samples/             # Sample PCAP files for testing
├── screenshots/              # UI and output screenshots
└── README.md
```

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- Administrator / root privileges (required for raw packet capture)
- `libpcap` (Linux) or `Npcap` (Windows) installed

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/darkloverboi/network-baseline-attack-detection.git
cd network-baseline-attack-detection

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Linux) Verify you have capture permissions
sudo setcap cap_net_raw=eip $(which python3)
# OR simply run with sudo
```

### Dependencies

```
scapy>=2.5.0
psutil>=5.9.0
colorama>=0.4.6
tabulate>=0.9.0
pyshark>=0.6          # optional, for PCAP analysis
```

---

## 🖥️ Usage

### Monitor a Live Network Interface

```bash
# Run with root/admin privileges
sudo python3 main.py --interface eth0

# Set custom baseline duration (in seconds)
sudo python3 main.py --interface eth0 --baseline 120

# Set custom alert sensitivity (default: 2 standard deviations)
sudo python3 main.py --interface eth0 --threshold 3
```

### Analyze a PCAP File

```bash
python3 main.py --pcap pcap_samples/attack_traffic.pcap
```

### View Help

```bash
python3 main.py --help
```

### Example Output

```
[*] Starting baseline collection on interface: eth0
[*] Baseline window: 60 seconds
[+] Baseline established:
    - Avg PPS     : 142.3
    - Avg BPS     : 89,421
    - SYN/ACK     : 0.87
    - Top Protocol: TCP (72%)

[*] Detection mode active...

[!] ALERT [HIGH]   SYN FLOOD detected from 192.168.1.105
    → SYN/ACK ratio: 12.4 (threshold: 2.0)
    → Packet rate  : 4,200 pps (baseline: 142 pps)
    → Timestamp    : 2026-02-27 14:33:07

[!] ALERT [MEDIUM] PORT SCAN detected from 10.0.0.44
    → Unique ports probed: 487 in 3s
    → Protocol: TCP SYN
    → Timestamp: 2026-02-27 14:33:09
```

---

## 📸 Screenshots

| Dashboard | Alert Log | Baseline Stats |
<img width="1920" height="1020" alt="Screenshot 2026-02-27 214751" src="https://github.com/user-attachments/assets/062bdbf3-1e94-40c8-8a4c-7f6b446f695b" />

<img width="1920" height="1020" alt="Screenshot 2026-02-27 214807" src="https://github.com/user-attachments/assets/9beaafc9-40a7-4a9e-9de1-3ba545b702ef" />

---<img width="1920" height="1020" alt="Screenshot 2026-02-27 214835" src="https://github.com/user-attachments/assets/34260e3b-25b5-462d-81fb-248173abf723" />


## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3 |
| Packet Capture | Scapy |
| Statistical Analysis | Python `statistics` module |
| CLI Interface | argparse + colorama |
| Logging | Python `logging` module |
| PCAP Analysis | PyShark / Scapy rdpcap |
| OS Support | Linux, Windows (with Npcap) |

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detector`)
3. Commit your changes (`git commit -m 'Add DNS tunneling detection'`)
4. Push to the branch (`git push origin feature/new-detector`)
5. Open a Pull Request

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized network monitoring only**. Do not use this tool on networks you do not own or have explicit permission to monitor. The author is not responsible for any misuse.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Shebin K Babu** — aka **DarkLoverBoi**

Built with ❤️ 

---

## 🌐 Connect With Me

This is my official GitHub. Feel free to reach out or collaborate!

| Platform | Link |
|---|---|
| 🐙 GitHub | [@darkloverboi](https://github.com/darkloverboi) |
| 📧 Email | [kshebin86@gmail.com](mailto:kshebin86@gmail.com) |
| 💼 LinkedIn | [linkedin.com/in/shebink1](https://www.linkedin.com/in/shebink1/) |
| 🌍 Portfolio | [darkloverboi.space](https://darkloverboi.space) |

> 🔔 Follow for more **Cybersecurity** and **AI** project updates!

---

> ⭐ If you found this project useful, please consider giving it a star!
