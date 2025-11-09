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
pip install scapy
git clone https://github.com/yourusername/AntiTrack.git
cd AntiTrack
pip install scapy
sudo python3 antitrack.py 192.168.1.100 -p 443 -f windows_10 -c 3
sudo python3 antitrack.py 192.168.1.100 --noise 100
python3 antitrack.py --list

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

# Spoof Windows 10 on port 443
sudo python3 antitrack.py 10.10.10.10 -p 443 -f windows_10

# Send 50 random packets (noise)
sudo python3 antitrack.py 10.10.10.10 --noise 50

# Use specific interface
sudo python3 antitrack.py 192.168.1.1 -i wlan0 -f linux_5_x

