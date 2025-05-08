import socket
import subprocess
import platform
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

IS_WINDOWS = platform.system().lower() == "windows"
DEFAULT_TIMEOUT = 2
MAX_PORT = 65535

# Function to ping IP
def ping_ip(ip, timeout=DEFAULT_TIMEOUT):
    try:
        if IS_WINDOWS:
            subprocess.run(["ping", "-n", "1", "-w", f"{timeout * 1000}", ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        else:
            subprocess.run(["ping", "-c", "1", "-W", str(timeout), ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False

def check_tcp_port(ip, port, timeout=DEFAULT_TIMEOUT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0  # 0 indicates success
    except socket.error:
        return False

# Function to check if a host is up (using ping and TCP)
def is_host_up(ip):
    return ping_ip(ip) or check_tcp_port(ip, 80) or check_tcp_port(ip, 443)

# Function to get MAC address from ARP
def get_mac_from_arp(ip):
    try:
        if IS_WINDOWS:
            arp_output = subprocess.check_output(["arp", "-a"], encoding="utf-8", timeout=DEFAULT_TIMEOUT)
        else:
            arp_output = subprocess.check_output(["arp", "-n"], encoding="utf-8", timeout=DEFAULT_TIMEOUT)

        mac_regex = re.compile(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})")
        for line in arp_output.splitlines():
            if ip in line:
                match = mac_regex.search(line)
                return match.group(0) if match else "Unknown"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return "Unknown"

# Function to resolve hostname from IP
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

# Function to scan a single IP address
def scan_ip(ip):
    if not is_host_up(ip):
        return None  # Return None for inactive hosts

    mac = get_mac_from_arp(ip)
    hostname = resolve_hostname(ip)
    return {"ip": ip, "mac": mac, "hostname": hostname}

# Function to scan multiple IPs in parallel
def scan_ips_parallel(ip_list, max_threads=10):
    devices = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in ip_list}
        for future in as_completed(futures):
            result = future.result()
            if result:  # Only append if result is not None (host is up)
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
    if results:
        for device in results:
            print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}")
    else:
        print("No active hosts found in the specified range.")

