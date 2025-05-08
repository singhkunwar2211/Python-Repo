# scanner.py
import socket
import subprocess
import platform
import re
import nmap  # Import the nmap library
from concurrent.futures import ThreadPoolExecutor, as_completed

IS_WINDOWS = platform.system().lower() == "windows"

# Function to ping IP
def ping_ip(ip):
    try:
        if IS_WINDOWS:
            subprocess.run(["ping", "-n", "1", "-w", "1000", ip], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

# Function to get MAC address from ARP
def get_mac_from_arp(ip):
    try:
        if IS_WINDOWS:
            arp_output = subprocess.check_output(["arp", "-a"], encoding="utf-8")
        else:
            arp_output = subprocess.check_output(["arp", "-n"], encoding="utf-8")

        mac_regex = re.compile(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})")
        for line in arp_output.splitlines():
            if ip in line:
                match = mac_regex.search(line)
                return match.group(0) if match else "Unknown"
    except Exception:
        pass
    return "Unknown"

# Function to resolve hostname from IP
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

# Function to get vendor and OS information using Nmap
def get_vendor_and_os(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-T4 -O')  #  OS detection.  Removed -F
        os_info = nm[ip].get("osmatch", [{"name": "Unknown"}])[0]['name']
        #  Vendor from nmap is unreliable, we will use mac address lookup
        return  "Unknown", os_info
    except Exception as e:
        print(f"Error scanning {ip}: {e}")
        return "Unknown", "Unknown"

# Function to get vendor from MAC address
def get_vendor_from_mac(mac_address):
    #  Simplified OUI database (for demonstration purposes).
    #  In a real application, use a larger database or an online API.
    oui_database = {
        "00:05:69": "Intel Corporation",
        "00:16:3E": "Cisco Systems",
        "00:26:B9": "Apple Inc.",
        "00:0C:29": "VMware, Inc.",
        "00:50:56": "VMware, Inc.",
        "00:01:E6": "Dell Inc",
        "00:04:23": "Hewlett-Packard Company",
        "00:03:BA": "Samsung Electronics Co., Ltd.",
    }
    if mac_address != "Unknown":
        oui = mac_address[:8].upper()  # Get the first 6 characters (OUI)
        if oui in oui_database:
            return oui_database[oui]
        else:
            return "Unknown Vendor"
    else:
        return "Unknown Vendor"

# Function to scan a single IP address
def scan_ip(ip):
    ping_ip(ip)
    mac = get_mac_from_arp(ip)
    hostname = resolve_hostname(ip)
    vendor, os = get_vendor_and_os(ip) # Get OS, not vendor
    vendor = get_vendor_from_mac(mac)  # Get Vendor from Mac
    return {"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor, "os": os}

# Function to scan multiple IPs in parallel
def scan_ips_parallel(ip_list, max_threads=10):
    devices = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in ip_list}
        for future in as_completed(futures):
            result = future.result()
            devices.append(result)

    # Sort results by IP numerically
    devices.sort(key=lambda x: list(map(int, x["ip"].split("."))))
    return devices

# Function to generate a range of IPs
def generate_ip_range(ip_range_str):
    start_ip, end_ip = ip_range_str.split('-')
    base_ip = '.'.join(start_ip.split('.')[:-1])
    start_octet = int(start_ip.split('.')[-1])
    end_octet = int(end_ip.split('.')[-1])
    return [f"{base_ip}.{i}" for i in range(start_octet, end_octet + 1)]

if __name__ == "__main__":
    target_network = input("Enter the IP range to scan (e.g., 192.168.1.1-192.168.1.254): ")
    results = scan_ips_parallel(generate_ip_range(target_network))
    print("\nScan Results:")
    for device in results:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}, Vendor: {device['vendor']}, OS: {device['os']}")
