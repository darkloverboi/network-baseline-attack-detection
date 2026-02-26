#!/usr/bin/env python3
import json
import os
import base64
from datetime import datetime
import sys
sys.path.insert(0, "/home/kali/network-baseline-attack-detection/scripts")
from traffic_analyzer import run_analysis

def img_to_base64(path):
    with open(path, 'rb') as f:
        return base64.b64encode(f.read()).decode('utf-8')

def generate_report():
    print("\n[*] Running analysis pipeline...")
    results = run_analysis()
    if not results:
        print("[!] No results to report.")
        return

    baseline = results["baseline"]
    attack = results["attack"]
    dev = results["deviation"]
    charts = results["charts"]

    chart_titles = [
        "Protocol Breakdown Comparison",
        "Packet Volume: Baseline vs Attack",
        "Top 10 Destination Ports",
        "Packets Per Second Timeline"
    ]
    chart_imgs = []
    for chart_path, title in zip(charts, chart_titles):
        b64 = img_to_base64(chart_path)
        chart_imgs.append((title, b64))

    attacks_html = ""
    for a in attack.get("attacks_performed", []):
        attacks_html += f"""
        <tr>
            <td><span class="badge-red">{a['type'].replace('_',' ').title()}</span></td>
            <td>{a.get('target','N/A')}</td>
            <td>{a.get('packets_sent', a.get('ports_scanned','N/A'))}</td>
            <td>{a.get('start_time','N/A')[:19].replace('T',' ')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Baseline vs Attack Deviation Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#e0e0e0;}}
.header{{background:linear-gradient(135deg,#1a1f2e,#16213e);border-bottom:3px solid #00d4ff;padding:40px;text-align:center;}}
.header h1{{font-size:2em;color:#00d4ff;margin-bottom:10px;}}
.header p{{color:#888;}}
.badge-red{{background:#f44336;color:#fff;padding:3px 10px;border-radius:12px;font-size:0.8em;}}
.badge-green{{background:#00c853;color:#fff;padding:3px 10px;border-radius:12px;font-size:0.8em;}}
.container{{max-width:1200px;margin:0 auto;padding:30px 20px;}}
.section{{background:#1a1f2e;border-radius:12px;padding:25px;margin:20px 0;border:1px solid #2d3561;}}
.section h2{{color:#00d4ff;font-size:1.3em;margin-bottom:20px;border-bottom:1px solid #2d3561;padding-bottom:10px;}}
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:15px;}}
.stat-card{{background:#0f1117;border-radius:10px;padding:20px;text-align:center;border:1px solid #2d3561;}}
.stat-card .value{{font-size:2em;font-weight:bold;color:#00d4ff;}}
.stat-card .label{{font-size:0.85em;color:#888;margin-top:5px;}}
.dev-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px;}}
.dev-card{{background:#0f1117;border-radius:10px;padding:20px;text-align:center;border-left:4px solid #f44336;}}
.dev-card .dev-value{{font-size:1.8em;font-weight:bold;color:#f44336;}}
.chart-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(480px,1fr));gap:20px;}}
.chart-card{{background:#0f1117;border-radius:10px;padding:15px;border:1px solid #2d3561;}}
.chart-card h3{{color:#aaa;font-size:0.95em;margin-bottom:10px;text-align:center;}}
.chart-card img{{width:100%;border-radius:8px;}}
table{{width:100%;border-collapse:collapse;}}
th{{background:#0f1117;color:#00d4ff;padding:12px;text-align:left;font-size:0.9em;}}
td{{padding:10px 12px;border-bottom:1px solid #2d3561;font-size:0.9em;}}
.finding{{background:#0f1117;border-radius:8px;padding:15px;margin:10px 0;border-left:4px solid #f44336;}}
.finding.info{{border-color:#2196f3;}}
.finding h4{{color:#f44336;margin-bottom:5px;}}
.finding.info h4{{color:#2196f3;}}
.finding p{{font-size:0.9em;color:#aaa;line-height:1.6;}}
footer{{text-align:center;padding:30px;color:#555;border-top:1px solid #2d3561;margin-top:20px;}}
</style>
</head>
<body>
<div class="header">
<h1>Network Baseline vs Attack Deviation Report</h1>
<p>Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')} &nbsp;|&nbsp; Raspberry Pi — Kali Linux &nbsp;|&nbsp; <span class="badge-green">Controlled Lab Environment</span></p>
</div>
<div class="container">

<div class="section">
<h2>Executive Summary</h2>
<p style="color:#aaa;line-height:1.7;">This project demonstrates a complete network security monitoring workflow on a <strong style="color:#00d4ff">Raspberry Pi running Kali Linux</strong>. Normal baseline traffic was captured for 60 seconds, followed by controlled attack simulation including port scanning, SYN flooding, ICMP flooding, UDP flooding, and banner grabbing — all targeting localhost in a safe lab environment. Traffic patterns were analyzed to identify behavioral deviations matching real SOC detection scenarios.</p>
</div>

<div class="section">
<h2>Baseline Traffic Statistics</h2>
<div class="stats-grid">
<div class="stat-card"><div class="value">{baseline['total_packets']}</div><div class="label">Total Packets</div></div>
<div class="stat-card"><div class="value" style="color:#2196f3">{baseline['tcp_packets']}</div><div class="label">TCP Packets</div></div>
<div class="stat-card"><div class="value" style="color:#4caf50">{baseline['udp_packets']}</div><div class="label">UDP Packets</div></div>
<div class="stat-card"><div class="value" style="color:#ff9800">{baseline['icmp_packets']}</div><div class="label">ICMP Packets</div></div>
<div class="stat-card"><div class="value">{len(baseline['unique_src_ips'])}</div><div class="label">Unique Source IPs</div></div>
</div>
</div>

<div class="section">
<h2>Attack Traffic Statistics</h2>
<div class="stats-grid">
<div class="stat-card"><div class="value" style="color:#f44336">{attack['total_packets']}</div><div class="label">Total Packets</div></div>
<div class="stat-card"><div class="value" style="color:#f44336">{attack['tcp_packets']}</div><div class="label">TCP Packets</div></div>
<div class="stat-card"><div class="value" style="color:#f44336">{attack['udp_packets']}</div><div class="label">UDP Packets</div></div>
<div class="stat-card"><div class="value" style="color:#f44336">{attack['icmp_packets']}</div><div class="label">ICMP Packets</div></div>
<div class="stat-card"><div class="value" style="color:#f44336">{len(attack['unique_src_ips'])}</div><div class="label">Unique Source IPs</div></div>
</div>
<br>
<table>
<tr><th>Attack Type</th><th>Target</th><th>Volume</th><th>Timestamp</th></tr>
{attacks_html}
</table>
</div>

<div class="section">
<h2>Behavioral Deviation Analysis</h2>
<div class="dev-grid">
<div class="dev-card"><div class="dev-value">{dev['total_packet_increase_pct']}%</div><div style="color:#888;font-size:0.85em">Total Packet Increase</div></div>
<div class="dev-card"><div class="dev-value">{dev['tcp_increase_pct']}%</div><div style="color:#888;font-size:0.85em">TCP Traffic Spike</div></div>
<div class="dev-card"><div class="dev-value">{dev['icmp_increase_pct']}%</div><div style="color:#888;font-size:0.85em">ICMP Traffic Spike</div></div>
<div class="dev-card" style="border-color:#2196f3"><div class="dev-value" style="color:#2196f3">{dev['baseline_avg_pps']}</div><div style="color:#888;font-size:0.85em">Baseline Avg PPS</div></div>
<div class="dev-card"><div class="dev-value">{dev['attack_avg_pps']}</div><div style="color:#888;font-size:0.85em">Attack Avg PPS</div></div>
</div>
</div>

<div class="section">
<h2>Visual Analysis</h2>
<div class="chart-grid">
{''.join(f'<div class="chart-card"><h3>{t}</h3><img src="data:image/png;base64,{b}" alt="{t}"/></div>' for t,b in chart_imgs)}
</div>
</div>

<div class="section">
<h2>Security Findings & SOC Recommendations</h2>
<div class="finding">
<h4>FINDING 1: Abnormal Port Scan Detected</h4>
<p>Sequential TCP SYN packets to ports 1-1000 observed during attack phase. Consistent with Nmap default scan. SOC Rule: Alert when more than 50 unique destination ports contacted by single source within 10 seconds.</p>
</div>
<div class="finding">
<h4>FINDING 2: SYN Flood Signature Detected</h4>
<p>200+ TCP SYN packets without ACK responses observed. Indicates SYN flood or half-open scan. SOC Rule: Alert when SYN:ACK ratio exceeds 10:1 from single source within 5 seconds.</p>
</div>
<div class="finding">
<h4>FINDING 3: ICMP Volume Anomaly</h4>
<p>ICMP packet volume increased significantly above baseline. SOC Rule: Alert when ICMP count exceeds 20 per second from a single source IP.</p>
</div>
<div class="finding info">
<h4>RECOMMENDATION: Implement Behavioral Baselining</h4>
<p>Establish rolling 7-day packet-per-second baselines per protocol. Any deviation exceeding 3 standard deviations should trigger a Tier-1 SOC alert for investigation.</p>
</div>
</div>

<div class="section">
<h2>Lab Environment</h2>
<table>
<tr><th>Component</th><th>Details</th></tr>
<tr><td>Attack Platform</td><td>Raspberry Pi — Kali Linux</td></tr>
<tr><td>Tools Used</td><td>Nmap, Scapy, Python 3, tshark</td></tr>
<tr><td>Attack Types</td><td>Port Scan, SYN Flood, ICMP Flood, UDP Flood, Banner Grab</td></tr>
<tr><td>Target</td><td>Localhost (127.0.0.1) — Controlled Lab Only</td></tr>
<tr><td>Report Generated</td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
</table>
</div>

</div>
<footer>Network Baseline vs Attack Deviation Report &nbsp;|&nbsp; Cybersecurity Portfolio Project &nbsp;|&nbsp; Raspberry Pi Kali Linux Lab</footer>
</body>
</html>"""

    os.makedirs("../reports", exist_ok=True)
    report_path = "../reports/final_report.html"
    with open(report_path, 'w') as f:
        f.write(html)

    print(f"\n[✓] Report saved: {report_path}")
    print("[✓] Open final_report.html in any browser!")
    return report_path

if __name__ == "__main__":
    generate_report()
