#!/usr/bin/env python3
import time
import os
import sys

print("""
╔══════════════════════════════════════════════════════╗
║   NETWORK BASELINE vs ATTACK DEVIATION PROJECT       ║
║   Raspberry Pi Kali Linux Lab                        ║
║   Cybersecurity Portfolio — Full Pipeline            ║
╚══════════════════════════════════════════════════════╝
""")

print("  This script will:")
print("  1. Capture 60s of BASELINE (normal) traffic")
print("  2. Simulate 5 attack types on localhost")
print("  3. Analyze and compare traffic patterns")
print("  4. Generate a professional HTML report")
print("\n  All attacks target LOCALHOST only — fully safe\n")

input("  Press ENTER to start Phase 1: Baseline Capture...")

print("\n" + "="*55)
print("  PHASE 1: BASELINE CAPTURE (60 seconds)")
print("="*55)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from baseline_capture import run_capture
baseline_file = run_capture()

print("\n  Baseline complete. Starting attacks in 3 seconds...")
time.sleep(3)

print("\n" + "="*55)
print("  PHASE 2: ATTACK SIMULATION")
print("="*55)
from attack_simulator import run_attacks
attack_file = run_attacks()

print("\n  Attacks complete. Generating report...")
time.sleep(2)

print("\n" + "="*55)
print("  PHASE 3: REPORT GENERATION")
print("="*55)
from report_generator import generate_report
report_path = generate_report()

print("""
╔══════════════════════════════════════════════════════╗
║   PROJECT COMPLETE!                                  ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║   Your report: reports/final_report.html             ║
║                                                      ║
║   Next steps:                                        ║
║   1. Copy report to Windows laptop                   ║
║   2. Open in Chrome — take screenshots               ║
║   3. Push to GitHub                                  ║
║   4. Add to portfolio website                        ║
╚══════════════════════════════════════════════════════╝
""")
