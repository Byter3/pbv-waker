#!/usr/bin/env python3
"""
BMC Scanner - Scans IP range for available BMC web interfaces on port 443
"""

import socket
import concurrent.futures
from datetime import datetime

def check_port(ip, port=443, timeout=2):
    """Check if a port is open on a given IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def scan_ip(ip):
    """Scan a single IP and return it if BMC is available."""
    if check_port(ip, 443):
        return ip
    return None

def main():
    print("=" * 60)
    print("BMC Scanner - Checking for BMC web interfaces on port 443")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scanning range: 10.10.101.1 - 10.10.101.255")
    print("-" * 60)
    
    # Generate IP list
    ips = [f"10.10.101.{i}" for i in range(1, 256)]
    
    available_bmcs = []
    
    # Use thread pool for faster scanning
    print("Scanning... (this may take a minute)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(scan_ip, ip): ip for ip in ips}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            if completed % 50 == 0:
                print(f"  Progress: {completed}/255 IPs checked...")
            
            result = future.result()
            if result:
                available_bmcs.append(result)
                print(f"  [FOUND] BMC available at: {result}")
    
    # Sort results by IP
    available_bmcs.sort(key=lambda x: int(x.split('.')[-1]))
    
    print("-" * 60)
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f"RESULTS: Found {len(available_bmcs)} BMC(s) with web interface on port 443")
    print("=" * 60)
    
    if available_bmcs:
        print("\nAvailable BMC IPs:")
        for ip in available_bmcs:
            print(f"  - https://{ip}/")
    else:
        print("\nNo BMCs found in the specified range.")
    
    print()
    return available_bmcs

if __name__ == "__main__":
    main()
