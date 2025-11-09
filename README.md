# AntiTrack – Network Fingerprint Spoofer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Termux%20%7C%20Windows-green" alt="Platforms">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="MIT License">
  <img src="https://img.shields.io/badge/Status-Stable-success" alt="Stable">
</p>

<p align="center">
  <strong>A professional TCP/IP stack fingerprint spoofer</strong><br>
  Built for cybersecurity researchers, network developers, and penetration testers.
</p>

---

## Key Features

- **Modify TCP/IP fingerprint** (`TTL`, `Window Size`, `TCP Options`)
- **Emulate real OS signatures** (Windows, Linux, macOS, iOS)
- **Send custom packets** to confuse scanners like **Nmap**
- **Full cross-platform support** – Termux / Linux / Windows
- **Detailed session reports** (JSON)
- **Noise burst mode** to disrupt detection systems

---

## Legal & Ethical Use Only

> **For testing environments only**  
> Examples: labs, private networks, or with explicit written permission.

---

## Requirements

```bash
Python 3.10+
scapy library
Root/admin privileges (on Linux/Termux)
```
## Installation
```bash
pip install scapy
```
```bash
git clone https://github.com/mraskal/AntiTrack.git
```
```bash
cd AntiTrack
```
```bash
pip install scapy
```
## Usage

**Spoof a specific OS**
```bash
sudo python3 antitrack.py 192.168.1.100 -p 443 -f windows_10 -c 3
```
**noise Burst**
```bash
sudo python3 antitrack.py 192.168.1.100 --noise 100
```
**List Available Fingerprints**
```bash
python3 antitrack.py --list
```
## Supported OS Fingerprints
**OS**
**Windows 10**
**Windows 7**
**Linux 5.x**
**Linux 3.x**
**Random (dynamic)**

## Sample Report (JSON)
```bash
{
  "session_id": "20251109_152301",
  "start_time": "2025-11-09T15:23:01.123456",
  "interface": "eth0",
  "packets_sent": [
    {
      "index": 1,
      "fingerprint": "windows_10",
      "dst": "192.168.1.100:80",
      "ttl": 128,
      "window": 65535,
      "mss": 1460,
      "options": [
        ["MSS", 1460],
        ["NOP", null],
        ["WScale", 8],
        ["SAckOK", ""],
        ["Timestamp", [1741622581000, 0]]
      ],
      "response": true,
      "sent_at": "2025-11-09T15:23:01.124"
    }
  ],
  "end_time": "2025-11-09T15:23:02.567"
}
```

## Quick commands 

# Spoof Windows 10 on port 443
```bash
sudo python3 antitrack.py 10.10.10.10 -p 443 -f windows_10
```
# Send 50 random packets (noise)
```bash
sudo python3 antitrack.py 10.10.10.10 --noise 50
```
# Use specific interface
```bash
sudo python3 antitrack.py 192.168.1.1 -i wlan0 -f linux_5_x
```
# Spoof Windows 10 on port 443
```bash
sudo python3 antitrack.py 10.10.10.10 -p 443 -f windows_10
```
# Send 50 random packets (noise)
```bash
sudo python3 antitrack.py 10.10.10.10 --noise 50
```
# Use specific interface
```bash
sudo python3 antitrack.py 192.168.1.1 -i wlan0 -f linux_5_x
```
## Termux support
``` bash
pkg install python tsu
pip install scapy
tsu
python3 antitrack.py 192.168.43.1 --noise 30
```
# Legal Disclaimer
> For educational and research purposes only.
> Do not use on networks or devices you do not own or without explicit permission.
> The author is not responsible for misuse.

# Contributing
Welcome:
New OS fingerprints
Report enhancements
IPv6 support
GUI frontend
Fork → Modify → Pull Request
License

**MIT License** – Free to use, modify, and distribute.

created with ♥ love by **ASKAL** 

