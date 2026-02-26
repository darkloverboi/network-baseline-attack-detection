#!/usr/bin/env python3
import subprocess
import time
import os
import json
import threading
import random
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap, send, sr1

TARGET_IP = "127.0.0.1"
OUTPUT_DIR = "../captures/attack"

attack_stats = {
    "start_time": "",
    "end_time": "",
    "total_packets": 0,
    "tcp_packets": 0,
    "udp_packets": 0,
    "icmp_packets": 0,
    "unique_src_ips": [],
    "unique_dst_ips": [],
    "port_frequency": {},
    "packets_per_second": [],
    "attacks_performed": []
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
    attack_stats["total_packets"] += 1
    captured_packets.append(pkt)
    current_second = int(time.time())
    if current_second != second_counter["last_second"]:
        attack_stats["packets_per_second"].append(second_counter["count"])
        second_counter["count"] = 1
        second_counter["last_second"] = current_second
    else:
        second_counter["count"] += 1
    seen_src.add(pkt[IP].src)
    seen_dst.add(pkt[IP].dst)
    if pkt.haslayer(TCP):
        attack_stats["tcp_packets"] += 1
        port = pkt[TCP].dport
        attack_stats["port_frequency"][port] = attack_stats["port_frequency"].get(port, 0) + 1
    elif pkt.haslayer(UDP):
        attack_stats["udp_packets"] += 1
    elif pkt.haslayer(ICMP):
        attack_stats["icmp_packets"] += 1

def attack_port_scan():
    print("\n  [ATTACK 1] Nmap Port Scan...")
    start = datetime.now().isoformat()
    result = subprocess.run(
        ['nmap', '-sS', '-p', '1-1000', '--open', TARGET_IP],
        capture_output=True, text=True
    )
    attack_stats["attacks_performed"].append({
        "type": "nmap_port_scan",
        "target": TARGET_IP,
        "ports_scanned": "1-1000",
        "start_time": start,
        "end_time": datetime.now().isoformat()
    })
    print("  [✓] Port scan complete")

def attack_syn_flood():
    print("\n  [ATTACK 2] SYN Flood (200 packets)...")
    start = datetime.now().isoformat()
    for i in range(200):
        pkt = IP(dst=TARGET_IP)/TCP(
            dport=random.randint(1, 65535),
            sport=random.randint(1024, 65535),
            flags="S"
        )
        send(pkt, verbose=False)
    attack_stats["attacks_performed"].append({
        "type": "syn_flood",
        "target": TARGET_IP,
        "packets_sent": 200,
        "start_time": start,
        "end_time": datetime.now().isoformat()
    })
    print("  [✓] SYN flood complete")

def attack_icmp_flood():
    print("\n  [ATTACK 3] ICMP Flood (100 packets)...")
    start = datetime.now().isoformat()
    for i in range(100):
        pkt = IP(dst=TARGET_IP)/ICMP()
        send(pkt, verbose=False)
    attack_stats["attacks_performed"].append({
        "type": "icmp_flood",
        "target": TARGET_IP,
        "packets_sent": 100,
        "start_time": start,
        "end_time": datetime.now().isoformat()
    })
    print("  [✓] ICMP flood complete")

def attack_udp_flood():
    print("\n  [ATTACK 4] UDP Flood (150 packets)...")
    start = datetime.now().isoformat()
    for i in range(150):
        pkt = IP(dst=TARGET_IP)/UDP(
            dport=random.randint(1, 65535),
            sport=random.randint(1024, 65535)
        )
        send(pkt, verbose=False)
    attack_stats["attacks_performed"].append({
        "type": "udp_flood",
        "target": TARGET_IP,
        "packets_sent": 150,
        "start_time": start,
        "end_time": datetime.now().isoformat()
    })
    print("  [✓] UDP flood complete")

def attack_banner_grab():
    print("\n  [ATTACK 5] Banner Grab...")
    start = datetime.now().isoformat()
    common_ports = [21, 22, 23, 25, 80, 443, 3306, 8080]
    grabbed = []
    for port in common_ports:
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=0.5, verbose=False)
        if response:
            grabbed.append(port)
    attack_stats["attacks_performed"].append({
        "type": "banner_grab",
        "target": TARGET_IP,
        "ports_probed": common_ports,
        "responsive_ports": grabbed,
        "start_time": start,
        "end_time": datetime.now().isoformat()
    })
    print(f"  [✓] Banner grab complete")

def run_attacks():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    interface = get_interface()
    print("\n[*] Starting attack simulation — target: localhost (SAFE)")
    attack_stats["start_time"] = datetime.now().isoformat()

    capture_thread = threading.Thread(
        target=lambda: sniff(
            iface=interface,
            prn=packet_handler,
            timeout=90,
            store=False
        )
    )
    capture_thread.start()
    time.sleep(2)

    attack_port_scan()
    time.sleep(3)
    attack_syn_flood()
    time.sleep(3)
    attack_icmp_flood()
    time.sleep(3)
    attack_udp_flood()
    time.sleep(3)
    attack_banner_grab()

    print("\n[*] Waiting for capture thread...")
    capture_thread.join()

    attack_stats["end_time"] = datetime.now().isoformat()
    attack_stats["unique_src_ips"] = list(seen_src)
    attack_stats["unique_dst_ips"] = list(seen_dst)
    top_ports = dict(sorted(
        attack_stats["port_frequency"].items(),
        key=lambda x: x[1], reverse=True
    )[:20])
    attack_stats["port_frequency"] = top_ports

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = f"{OUTPUT_DIR}/attack_{timestamp}.pcap"
    wrpcap(pcap_file, captured_packets)
    json_file = f"{OUTPUT_DIR}/attack_stats_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump(attack_stats, f, indent=2)

    print(f"\n[✓] Done! Total packets: {attack_stats['total_packets']}")
    print(f"[✓] Saved: {pcap_file}")
    print(f"[✓] Saved: {json_file}")
    return json_file

if __name__ == "__main__":
    run_attacks()
