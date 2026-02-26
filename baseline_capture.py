#!/usr/bin/env python3
import subprocess
import time
import os
import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap

CAPTURE_DURATION = 60
OUTPUT_DIR = "../captures/baseline"

stats = {
    "start_time": "",
    "end_time": "",
    "total_packets": 0,
    "tcp_packets": 0,
    "udp_packets": 0,
    "icmp_packets": 0,
    "unique_src_ips": [],
    "unique_dst_ips": [],
    "port_frequency": {},
    "packets_per_second": []
}

captured_packets = []
seen_src = set()
seen_dst = set()
second_counter = {"count": 0, "last_second": int(time.time())}

def get_interface():
    result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'default' in line:
            parts = line.split()
            if 'dev' in parts:
                return parts[parts.index('dev') + 1]
    return "wlan0"

def packet_handler(pkt):
    global second_counter
    if not pkt.haslayer(IP):
        return
    stats["total_packets"] += 1
    captured_packets.append(pkt)
    current_second = int(time.time())
    if current_second != second_counter["last_second"]:
        stats["packets_per_second"].append(second_counter["count"])
        second_counter["count"] = 1
        second_counter["last_second"] = current_second
    else:
        second_counter["count"] += 1
    seen_src.add(pkt[IP].src)
    seen_dst.add(pkt[IP].dst)
    if pkt.haslayer(TCP):
        stats["tcp_packets"] += 1
        port = pkt[TCP].dport
        stats["port_frequency"][port] = stats["port_frequency"].get(port, 0) + 1
    elif pkt.haslayer(UDP):
        stats["udp_packets"] += 1
    elif pkt.haslayer(ICMP):
        stats["icmp_packets"] += 1

def run_capture():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    interface = get_interface()
    print(f"\n[*] Starting baseline capture on {interface} for {CAPTURE_DURATION}s")
    print("[*] Generate NORMAL traffic — browse, ping, etc\n")
    stats["start_time"] = datetime.now().isoformat()
    sniff(iface=interface, prn=packet_handler, timeout=CAPTURE_DURATION, store=False)
    stats["end_time"] = datetime.now().isoformat()
    stats["unique_src_ips"] = list(seen_src)
    stats["unique_dst_ips"] = list(seen_dst)
    top_ports = dict(sorted(stats["port_frequency"].items(), key=lambda x: x[1], reverse=True)[:20])
    stats["port_frequency"] = top_ports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = f"{OUTPUT_DIR}/baseline_{timestamp}.pcap"
    wrpcap(pcap_file, captured_packets)
    json_file = f"{OUTPUT_DIR}/baseline_stats_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"\n[✓] Done! Total packets: {stats['total_packets']}")
    print(f"[✓] Saved: {pcap_file}")
    print(f"[✓] Saved: {json_file}")
    return json_file

if __name__ == "__main__":
    run_capture()
