#!/usr/bin/env python3
import json
import os
import glob
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUTPUT_DIR = "../reports/charts"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_latest_json(folder):
    files = glob.glob(f"{folder}/*.json")
    if not files:
        print(f"[!] No JSON files in {folder}")
        return None
    latest = max(files, key=os.path.getctime)
    print(f"[*] Loading: {latest}")
    with open(latest) as f:
        return json.load(f)

def chart_protocol_comparison(baseline, attack):
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('Protocol Breakdown: Baseline vs Attack', fontsize=16, fontweight='bold')
    colors = ['#2196F3', '#4CAF50', '#FF5722']
    for ax, data, title in zip(axes, [baseline, attack], ['Baseline (Normal)', 'Attack Traffic']):
        values = [data['tcp_packets'], data['udp_packets'], data['icmp_packets']]
        labels = [f'TCP\n{values[0]}', f'UDP\n{values[1]}', f'ICMP\n{values[2]}']
        ax.pie(values, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax.set_title(title, fontsize=13, fontweight='bold')
    plt.tight_layout()
    path = f"{OUTPUT_DIR}/chart1_protocol_comparison.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[✓] Chart 1 saved")
    return path

def chart_packet_volume(baseline, attack):
    fig, ax = plt.subplots(figsize=(10, 6))
    categories = ['Total Packets', 'TCP', 'UDP', 'ICMP']
    b_values = [baseline['total_packets'], baseline['tcp_packets'], baseline['udp_packets'], baseline['icmp_packets']]
    a_values = [attack['total_packets'], attack['tcp_packets'], attack['udp_packets'], attack['icmp_packets']]
    x = np.arange(len(categories))
    width = 0.35
    bars1 = ax.bar(x - width/2, b_values, width, label='Baseline', color='#2196F3', alpha=0.85)
    bars2 = ax.bar(x + width/2, a_values, width, label='Attack', color='#F44336', alpha=0.85)
    for bar in bars1:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5, str(int(bar.get_height())), ha='center', va='bottom', fontsize=10)
    for bar in bars2:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5, str(int(bar.get_height())), ha='center', va='bottom', fontsize=10)
    ax.set_xlabel('Packet Type', fontsize=12)
    ax.set_ylabel('Packet Count', fontsize=12)
    ax.set_title('Packet Volume: Baseline vs Attack', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend(fontsize=11)
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    path = f"{OUTPUT_DIR}/chart2_packet_volume.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[✓] Chart 2 saved")
    return path

def chart_top_ports(baseline, attack):
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.suptitle('Top 10 Destination Ports: Baseline vs Attack', fontsize=15, fontweight='bold')
    for ax, data, title, color in zip(axes, [baseline, attack], ['Baseline', 'Attack'], ['#2196F3', '#F44336']):
        ports = list(data['port_frequency'].keys())[:10]
        counts = list(data['port_frequency'].values())[:10]
        port_labels = [str(p) for p in ports]
        bars = ax.barh(port_labels, counts, color=color, alpha=0.8)
        ax.set_xlabel('Packet Count', fontsize=11)
        ax.set_ylabel('Destination Port', fontsize=11)
        ax.set_title(f'{title} Traffic', fontsize=12, fontweight='bold')
        for bar, count in zip(bars, counts):
            ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2, str(count), va='center', fontsize=9)
        ax.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    path = f"{OUTPUT_DIR}/chart3_top_ports.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[✓] Chart 3 saved")
    return path

def chart_packets_per_second(baseline, attack):
    fig, axes = plt.subplots(2, 1, figsize=(14, 10))
    fig.suptitle('Packets Per Second Timeline', fontsize=15, fontweight='bold')
    for ax, data, title, color in zip(
        axes,
        [baseline, attack],
        ['Baseline (Normal Behavior)', 'Attack Traffic (Deviation)'],
        ['#2196F3', '#F44336']
    ):
        pps = data.get('packets_per_second', [0])
        if not pps:
            pps = [0]
        x = list(range(len(pps)))
        ax.plot(x, pps, color=color, linewidth=2)
        ax.fill_between(x, pps, alpha=0.3, color=color)
        ax.axhline(y=np.mean(pps), color='black', linestyle='--', alpha=0.7, label=f'Mean: {np.mean(pps):.1f} pkt/s')
        ax.set_xlabel('Time (seconds)', fontsize=11)
        ax.set_ylabel('Packets/Second', fontsize=11)
        ax.set_title(title, fontsize=12, fontweight='bold')
        ax.legend(fontsize=10)
        ax.grid(alpha=0.3)
    plt.tight_layout()
    path = f"{OUTPUT_DIR}/chart4_pps_timeline.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[✓] Chart 4 saved")
    return path

def calculate_deviation(baseline, attack):
    def safe_div(a, b):
        return round(((a - b) / b * 100), 1) if b > 0 else 0
    return {
        "total_packet_increase_pct": safe_div(attack['total_packets'], baseline['total_packets']),
        "tcp_increase_pct": safe_div(attack['tcp_packets'], baseline['tcp_packets']),
        "udp_increase_pct": safe_div(attack['udp_packets'], baseline['udp_packets']),
        "icmp_increase_pct": safe_div(attack['icmp_packets'], baseline['icmp_packets']),
        "baseline_avg_pps": round(np.mean(baseline.get('packets_per_second', [0])), 2),
        "attack_avg_pps": round(np.mean(attack.get('packets_per_second', [0])), 2),
    }

def run_analysis():
    print("\n[*] Loading data...")
    baseline = load_latest_json("../captures/baseline")
    attack = load_latest_json("../captures/attack")
    if not baseline or not attack:
        print("[!] Missing data. Run capture scripts first.")
        return None
    print("[*] Generating charts...")
    chart1 = chart_protocol_comparison(baseline, attack)
    chart2 = chart_packet_volume(baseline, attack)
    chart3 = chart_top_ports(baseline, attack)
    chart4 = chart_packets_per_second(baseline, attack)
    deviation = calculate_deviation(baseline, attack)
    print(f"\n[*] DEVIATION SUMMARY")
    print(f"    Total Packet Increase : {deviation['total_packet_increase_pct']}%")
    print(f"    TCP Increase          : {deviation['tcp_increase_pct']}%")
    print(f"    ICMP Increase         : {deviation['icmp_increase_pct']}%")
    print(f"    Baseline Avg PPS      : {deviation['baseline_avg_pps']}")
    print(f"    Attack Avg PPS        : {deviation['attack_avg_pps']}")
    return {
        "baseline": baseline,
        "attack": attack,
        "deviation": deviation,
        "charts": [chart1, chart2, chart3, chart4]
    }

if __name__ == "__main__":
    run_analysis()
