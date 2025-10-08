#!/usr/bin/env python3
"""
SSH Honeypot Log Analyzer
Analyzes collected attack data to identify patterns and trends
"""

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

def load_logs(log_file='honeypot_logs.json'):
    """Load logs from JSON file"""
    if not Path(log_file).exists():
        print(f"Error: {log_file} not found")
        sys.exit(1)
    
    with open(log_file, 'r') as f:
        return json.load(f)

def analyze_credentials(logs):
    """Analyze username and password patterns"""
    usernames = Counter()
    passwords = Counter()
    combos = Counter()
    
    for entry in logs:
        if entry.get('auth_method') == 'password':
            user = entry.get('username', 'N/A')
            pwd = entry.get('password', 'N/A')
            
            usernames[user] += 1
            passwords[pwd] += 1
            combos[(user, pwd)] += 1
    
    return usernames, passwords, combos

def analyze_sources(logs):
    """Analyze source IP addresses and geographical patterns"""
    ips = Counter()
    ports = Counter()
    
    for entry in logs:
        ips[entry.get('source_ip', 'Unknown')] += 1
        ports[entry.get('source_port', 0)] += 1
    
    return ips, ports

def analyze_timeline(logs):
    """Analyze attack patterns over time"""
    by_hour = defaultdict(int)
    by_day = defaultdict(int)
    
    for entry in logs:
        try:
            dt = datetime.fromisoformat(entry['timestamp'])
            by_hour[dt.hour] += 1
            by_day[dt.date().isoformat()] += 1
        except:
            continue
    
    return by_hour, by_day

def analyze_commands(logs):
    """Analyze command execution attempts"""
    commands = Counter()
    
    for entry in logs:
        if entry.get('type') == 'exec_request':
            commands[entry.get('command', 'N/A')] += 1
    
    return commands

def print_report(logs):
    """Generate and print comprehensive analysis report"""
    print("\n" + "="*60)
    print("SSH HONEYPOT ANALYSIS REPORT")
    print("="*60)
    
    print(f"\nTotal Events Logged: {len(logs)}")
    
    # Credential Analysis
    print("\n" + "-"*60)
    print("TOP 10 USERNAMES ATTEMPTED:")
    print("-"*60)
    usernames, passwords, combos = analyze_credentials(logs)
    for user, count in usernames.most_common(10):
        print(f"  {user:<20} - {count:>5} attempts")
    
    print("\n" + "-"*60)
    print("TOP 10 PASSWORDS ATTEMPTED:")
    print("-"*60)
    for pwd, count in passwords.most_common(10):
        display_pwd = pwd if len(pwd) <= 30 else pwd[:27] + "..."
        print(f"  {display_pwd:<30} - {count:>5} attempts")
    
    print("\n" + "-"*60)
    print("TOP 10 USERNAME/PASSWORD COMBINATIONS:")
    print("-"*60)
    for (user, pwd), count in combos.most_common(10):
        print(f"  {user}/{pwd:<40} - {count:>5} attempts")
    
    # Source Analysis
    print("\n" + "-"*60)
    print("TOP 10 SOURCE IPs:")
    print("-"*60)
    ips, ports = analyze_sources(logs)
    for ip, count in ips.most_common(10):
        print(f"  {ip:<20} - {count:>5} connections")
    
    # Command Analysis
    print("\n" + "-"*60)
    print("COMMANDS EXECUTED:")
    print("-"*60)
    commands = analyze_commands(logs)
    if commands:
        for cmd, count in commands.most_common(10):
            display_cmd = cmd if len(cmd) <= 50 else cmd[:47] + "..."
            print(f"  {display_cmd:<50} - {count:>5} times")
    else:
        print("  No command execution attempts logged")
    
    # Timeline Analysis
    print("\n" + "-"*60)
    print("ATTACK DISTRIBUTION BY HOUR:")
    print("-"*60)
    by_hour, by_day = analyze_timeline(logs)
    for hour in sorted(by_hour.keys()):
        bar = '#' * (by_hour[hour] // max(1, max(by_hour.values()) // 50))
        print(f"  {hour:02d}:00 - {by_hour[hour]:>5} | {bar}")
    
    # Authentication Methods
    print("\n" + "-"*60)
    print("AUTHENTICATION METHODS:")
    print("-"*60)
    auth_methods = Counter(entry.get('auth_method', 'unknown') for entry in logs)
    for method, count in auth_methods.most_common():
        print(f"  {method:<20} - {count:>5} attempts")
    
    print("\n" + "="*60 + "\n")

def export_csv(logs, output_file='honeypot_analysis.csv'):
    """Export logs to CSV format"""
    import csv
    
    with open(output_file, 'w', newline='') as f:
        if logs:
            writer = csv.DictWriter(f, fieldnames=logs[0].keys())
            writer.writeheader()
            writer.writerows(logs)
    
    print(f"Data exported to {output_file}")

if __name__ == '__main__':
    log_file = sys.argv[1] if len(sys.argv) > 1 else 'honeypot_logs.json'
    logs = load_logs(log_file)
    print_report(logs)
    
    # Optionally export to CSV
    export = input("\nExport to CSV? (y/n): ").strip().lower()
    if export == 'y':
        export_csv(logs)
