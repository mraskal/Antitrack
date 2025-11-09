#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AntiTrack - Professional Network Fingerprint Spoofer
==================================================

A powerful yet fully legal Python tool for cybersecurity researchers and network
developers to spoof TCP/IP stack fingerprints. Ideal for penetration testing,
evading passive OS detection, and confusing Nmap-like scanners.

Features:
    • Modify TCP/IP fingerprint (TTL, Window Size, TCP Options)
    • Emulate popular OS signatures (Windows, Linux, macOS)
    • Send custom packets to disrupt scanning tools
    • Cross-platform: Termux / Linux / Windows (via Python + Scapy)
    • Session reports with detailed packet logs

Requirements:
    • Python 3.10+
    • Scapy (`pip install scapy`)
    • Root/admin privileges (for raw packet crafting)

created with ♥ love by ASKAL
"""

import argparse
import random
import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple, Optional

from scapy.all import (
    IP, TCP, RandShort, send, sr1, Ether, RandMAC,
    IPOption, Padding, Raw
)
from scapy.config import conf

# Configure Scapy
conf.verb = 0  # Silent mode

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger("AntiTrack")

# ======================
# OS Fingerprint Database
# ======================

OS_FINGERPRINTS = {
    "windows_10": {
        "ttl": 128,
        "window": 65535,
        "mss": 1460,
        "window_scale": 8,
        "sack": True,
        "timestamp": True,
        "nop": True,
        "options_order": ["MSS", "NOP", "WindowScale", "SACK", "TS"]
    },
    "windows_7": {
        "ttl": 128,
        "window": 8192,
        "mss": 1460,
        "window_scale": 2,
        "sack": True,
        "timestamp": False,
        "nop": True,
        "options_order": ["MSS", "NOP", "SACK"]
    },
    "linux_5_x": {
        "ttl": 64,
        "window": 64240,
        "mss": 1460,
        "window_scale": 7,
        "sack": True,
        "timestamp": True,
        "nop": False,
        "options_order": ["MSS", "SACK", "TS", "WindowScale"]
    },
    "linux_3_x": {
        "ttl": 64,
        "window": 5840,
        "mss": 1460,
        "window_scale": 10,
        "sack": True,
        "timestamp": True,
        "nop": True,
        "options_order": ["MSS", "NOP", "TS", "SACK", "WindowScale"]
    },
    "macos_ventura": {
        "ttl": 64,
        "window": 65535,
        "mss": 1460,
        "window_scale": 5,
        "sack": True,
        "timestamp": True,
        "nop": False,
        "options_order": ["MSS", "WindowScale", "SACK", "TS"]
    },
    "ios_16": {
        "ttl": 64,
        "window": 65535,
        "mss": 1380,
        "window_scale": 4,
        "sack": True,
        "timestamp": True,
        "nop": False,
        "options_order": ["MSS", "SACK", "TS", "WindowScale"]
    },
    "random": {
        "ttl": lambda: random.choice([32, 64, 128, 255]),
        "window": lambda: random.randint(1024, 65535),
        "mss": lambda: random.choice([536, 1460, 1380, 1400]),
        "window_scale": lambda: random.randint(0, 14),
        "sack": lambda: random.choice([True, False]),
        "timestamp": lambda: random.choice([True, False]),
        "nop": lambda: random.choice([True, False]),
        "options_order": "random"
    }
}

class AntiTrack:
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or conf.iface
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report = {
            "session_id": self.session_id,
            "start_time": datetime.now().isoformat(),
            "interface": str(self.interface),
            "packets_sent": [],
            "end_time": None
        }
        self.reports_dir = "antitrack_reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    def build_tcp_options(self, fp: Dict) -> List[Tuple[str, any]]:
        """Build TCP options list based on fingerprint."""
        opts = []
        order = fp.get("options_order", [])

        if order == "random":
            order = ["MSS", "WindowScale", "SACK", "TS", "NOP"]

        for opt in order:
            if opt == "MSS" and "mss" in fp:
                opts.append(("MSS", fp["mss"]))
            elif opt == "WindowScale" and fp.get("window_scale", -1) >= 0:
                opts.append(("WScale", fp["window_scale"]))
            elif opt == "SACK" and fp.get("sack"):
                opts.append(("SAckOK", b''))
            elif opt == "TS" and fp.get("timestamp"):
                ts_val = int(datetime.now().timestamp() * 1000) % (2**32)
                opts.append(("Timestamp", (ts_val, 0)))
            elif opt == "NOP" and fp.get("nop"):
                opts.append(("NOP", None))

        # Add padding if needed
        total_len = sum(len(str(v)) if v is not None else 1 for _, v in opts)
        if total_len % 4 != 0:
            padding = 4 - (total_len % 4)
            opts.append(("NOP", None) * padding)

        return opts

    def spoof_packet(
        self,
        dst_ip: str,
        dst_port: int = 80,
        src_port: Optional[int] = None,
        fingerprint: str = "linux_5_x",
        count: int = 1
    ) -> List[Dict]:
        """Send spoofed packets with selected OS fingerprint."""
        if fingerprint not in OS_FINGERPRINTS:
            raise ValueError(f"Unknown fingerprint: {fingerprint}")

        fp = OS_FINGERPRINTS[fingerprint]
        sent_packets = []

        for i in range(count):
            # Resolve dynamic values
            ttl = fp["ttl"]() if callable(fp["ttl"]) else fp["ttl"]
            window = fp["window"]() if callable(fp["window"]) else fp["window"]
            mss = fp["mss"]() if callable(fp["mss"]) else fp["mss"]
            wscale = fp["window_scale"]() if callable(fp["window_scale"]) else fp["window_scale"]
            sack = fp["sack"]() if callable(fp["sack"]) else fp["sack"]
            ts = fp["timestamp"]() if callable(fp["timestamp"]) else fp["timestamp"]
            nop = fp["nop"]() if callable(fp["nop"]) else fp["nop"]

            # Build TCP options
            tcp_opts = self.build_tcp_options({
                **fp,
                "mss": mss,
                "window_scale": wscale,
                "sack": sack,
                "timestamp": ts,
                "nop": nop
            })

            # Layer 2 (for local networks)
            ether = Ether(src=RandMAC()) if conf.L3socket == conf.L2socket else None

            # IP Layer
            ip = IP(
                dst=dst_ip,
                ttl=ttl,
                flags="DF" if random.random() > 0.3 else 0
            )

            # TCP Layer
            tcp = TCP(
                sport=src_port or RandShort(),
                dport=dst_port,
                flags="S",
                window=window,
                options=tcp_opts
            )

            # Final packet
            packet = (ether / ip / tcp) if ether else (ip / tcp)

            # Send packet
            try:
                log.info(f"[{i+1}/{count}] Sending spoofed SYN to {dst_ip}:{dst_port} as [{fingerprint.upper()}]")
                ans = sr1(packet, timeout=3, iface=self.interface)

                pkt_log = {
                    "index": i + 1,
                    "fingerprint": fingerprint,
                    "dst": f"{dst_ip}:{dst_port}",
                    "ttl": ttl,
                    "window": window,
                    "mss": mss,
                    "options": tcp_opts,
                    "response": bool(ans),
                    "sent_at": datetime.now().isoformat()
                }
                sent_packets.append(pkt_log)
                self.report["packets_sent"].append(pkt_log)

            except Exception as e:
                log.error(f"Failed to send packet: {e}")
                sent_packets.append({
                    "index": i + 1,
                    "error": str(e),
                    "sent_at": datetime.now().isoformat()
                })

        return sent_packets

    def noise_burst(
        self,
        dst_ip: str,
        dst_port: int = 80,
        count: int = 50,
        delay: float = 0.01
    ):
        """Send a burst of random-fingerprint packets to confuse scanners."""
        log.info(f"Launching noise burst: {count} packets to {dst_ip}:{dst_port}")
        fingerprints = [fp for fp in OS_FINGERPRINTS.keys() if fp != "random"]
        
        for i in range(count):
            fp = random.choice(fingerprints)
            self.spoof_packet(dst_ip, dst_port, fingerprint=fp, count=1)
            if delay > 0:
                import time
                time.sleep(delay)

    def save_report(self):
        """Save session report to JSON file."""
        self.report["end_time"] = datetime.now().isoformat()
        report_path = os.path.join(self.reports_dir, f"report_{self.session_id}.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=2, ensure_ascii=False)
        log.info(f"Report saved: {report_path}")

def main():
    parser = argparse.ArgumentParser(
        description="AntiTrack - Network Fingerprint Spoofer",
        epilog="created with ♥ love by ASKAL"
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("-f", "--fingerprint", choices=OS_FINGERPRINTS.keys(), default="linux_5_x",
                        help="OS fingerprint to emulate")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--noise", type=int, metavar="N", help="Send N random packets (noise burst)")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("--list", action="store_true", help="List available fingerprints")

    args = parser.parse_args()

    if args.list:
        print("Available fingerprints:")
        for name in OS_FINGERPRINTS.keys():
            print(f"  • {name}")
        return

    if os.getuid() != 0 and os.name != "nt":
        log.error("This tool requires root privileges for raw packet crafting.")
        return

    antitrack = AntiTrack(interface=args.interface)

    try:
        if args.noise:
            antitrack.noise_burst(args.target, args.port, count=args.noise)
        else:
            antitrack.spoof_packet(
                dst_ip=args.target,
                dst_port=args.port,
                fingerprint=args.fingerprint,
                count=args.count
            )
    finally:
        antitrack.save_report()

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════╗
    ║             AntiTrack                ║
    ║  Network Fingerprint Spoofer v1.0    ║
    ╚══════════════════════════════════════╝
    """)
    main()
    print("\ncreated with ♥ love by ASKAL")