import psutil
import socket
import requests
import time
import getpass

SERVER_URL = "http://10.10.101.109:5000/api/register"
TARGET_SUBNET_PREFIX = "10.10.101."

def get_network_info():
    """
    Finds the interface with an IP in the 10.10.101.x range.
    Returns (hostname, ip, mac) or None if not found.
    """
    hostname = socket.gethostname()
    interfaces = psutil.net_if_addrs()

    for iface_name, addrs in interfaces.items():
        ip_address = None
        mac_address = None
        
        for addr in addrs:
            if addr.family == socket.AF_INET:
                if addr.address.startswith(TARGET_SUBNET_PREFIX):
                    ip_address = addr.address
            elif addr.family == psutil.AF_LINK: # MAC address
                mac_address = addr.address.upper()
        
        if ip_address and mac_address:
            # Found the correct interface
             # Normalize MAC to AA:BB:CC... format if needed (psutil usually checks OS)
             # On Windows it uses - sometimes, lets ensure :
            mac_address = mac_address.replace('-', ':')
            return hostname, ip_address, mac_address
            
    return None

def register():
    info = get_network_info()
    if not info:
        print(f"No network interface found with IP starting with {TARGET_SUBNET_PREFIX}")
        return

    name, ip, mac = info
    current_user = getpass.getuser()
    
    payload = {
        "name": name,
        "ip": ip,
        "mac": mac,
        "user": current_user
    }
    
    print(f"Registering {name} ({ip}) - {mac} as user: {current_user}...")
    
    try:
        response = requests.post(SERVER_URL, json=payload)
        if response.status_code == 200:
            print("Successfully registered!")
        else:
            print(f"Failed to register. Status: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    register()
