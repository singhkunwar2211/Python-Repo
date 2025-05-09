import socket
import subprocess
import platform
import re
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

IS_WINDOWS = platform.system().lower() == "windows"
DEFAULT_TIMEOUT = 0.5
MAX_THREADS = 20
MAX_ARP_RETRIES = 2
MAX_HOST_RETRIES = 2
RETRY_DELAY_BASE = 0.1

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to ping IP
def ping_ip(ip, timeout=DEFAULT_TIMEOUT):
    try:
        if IS_WINDOWS:
            subprocess.run(["ping", "-n", "1", "-w", f"{int(timeout * 1000)}", ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, check=True)
        else:
            subprocess.run(["ping", "-c", "1", "-W", str(timeout), ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, check=True)
        logging.debug(f"Ping successful for {ip}")
        return True
    except subprocess.CalledProcessError as e:
        logging.debug(f"Ping failed for {ip}: {e}")
        return False
    except subprocess.TimeoutExpired:
        logging.debug(f"Ping timed out for {ip}")
        return False
    except OSError as e:
        logging.error(f"Error executing ping for {ip}: {e}")
        return False

def check_tcp_port(ip, port, timeout=DEFAULT_TIMEOUT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            logging.debug(f"TCP connection successful on {ip}:{port}")
            return True
        else:
            logging.debug(f"TCP connection failed on {ip}:{port}, error: {result}")
            return False
    except socket.error as e:
        logging.error(f"Socket error on {ip}:{port}: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred on {ip}:{port}: {e}")
        return False

# Function to check if a host is up (using ping and TCP)
def is_host_up(ip, retries=MAX_HOST_RETRIES):
    for attempt in range(retries):
        if ping_ip(ip) or check_tcp_port(ip, 80) or check_tcp_port(ip, 443):
            return True
        if attempt < retries - 1:
            time.sleep(RETRY_DELAY_BASE * (2 ** attempt))
    logging.info(f"Host {ip} is down after {retries} attempts")
    return False

# Function to get MAC address from ARP with retry
def get_mac_from_arp(ip, retries=MAX_ARP_RETRIES):
    for attempt in range(retries):
        try:
            if IS_WINDOWS:
                arp_output = subprocess.check_output(["arp", "-a"], encoding="utf-8", timeout=DEFAULT_TIMEOUT)
            else:
                arp_output = subprocess.check_output(["arp", "-n"], encoding="utf-8", timeout=DEFAULT_TIMEOUT)

            mac_regex = re.compile(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})")
            for line in arp_output.splitlines():
                if ip in line:
                    match = mac_regex.search(line)
                    if match:
                        mac_address = match.group(0)
                        logging.debug(f"Found MAC address {mac_address} for IP {ip} on attempt {attempt + 1}")
                        return mac_address
                    else:
                        logging.warning(f"No MAC address found in ARP output for IP {ip} on attempt {attempt + 1}")
                        break  # Exit inner loop, go to next retry
            logging.info(f"No MAC address found for IP {ip} in ARP table on attempt {attempt + 1}")
        except subprocess.CalledProcessError as e:
            logging.error(f"ARP command failed for {ip} on attempt {attempt + 1}: {e}")
        except subprocess.TimeoutExpired:
            logging.error(f"ARP command timed out for {ip} on attempt {attempt + 1}")
        except OSError as e:
            logging.error(f"Error executing ARP command for {ip} on attempt {attempt + 1}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while getting MAC for IP {ip} on attempt {attempt + 1}: {e}")

        if attempt < retries - 1:
            time.sleep(RETRY_DELAY_BASE * (2 ** attempt))  # Exponential backoff
    return "None"

# Function to resolve hostname from IP with retry
def resolve_hostname(ip, retries=MAX_HOST_RETRIES):
    for attempt in range(retries):
        try:
            socket.setdefaulttimeout(DEFAULT_TIMEOUT)
            hostname = socket.gethostbyaddr(ip)[0]
            logging.debug(f"Resolved hostname {hostname} for IP {ip} on attempt {attempt + 1}")
            socket.setdefaulttimeout(None)
            return hostname
        except socket.herror as e:
            logging.info(f"No hostname found for IP {ip} on attempt {attempt + 1}: {e}")
            socket.setdefaulttimeout(None)
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY_BASE * (2 ** attempt))  # Exponential backoff
            else:
                return "Unknown"
        finally:
            socket.setdefaulttimeout(None)
    return "Unknown"

# Function to scan a single IP address
def scan_ip(ip):
    start_time = time.time()
    if is_host_up(ip):  # Check if the host is up first
        mac = get_mac_from_arp(ip, retries=MAX_ARP_RETRIES)
        hostname = resolve_hostname(ip, retries=MAX_HOST_RETRIES)
        end_time = time.time()
        logging.info(f"Scanned IP {ip} in {end_time - start_time:.2f} seconds")
        if hostname == "Unknown":  # Add this condition
            return {"ip": ip, "mac": "None", "hostname": "Unknown"}
        else:
            return {"ip": ip, "mac": mac, "hostname": hostname}
    else:
        end_time = time.time()
        logging.info(f"Skipping scan of {ip} as host is down in {end_time - start_time:.2f} seconds")
        return {"ip": ip, "mac": "None", "hostname": "Unknown"}

# Function to scan multiple IPs in parallel
def scan_ips_parallel(ip_list, max_threads=MAX_THREADS):
    devices = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in ip_list}
        for future in as_completed(futures):
            result = future.result()
            if result:
                devices.append(result)

    # Sort results by IP
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
    start_time = time.time()
    results = scan_ips_parallel(generate_ip_range(target_network))
    end_time = time.time()
    print("\nScan Results:")
    if results:
        for device in results:
            print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}")
    else:
        print("No active hosts found in the specified range.")
    print(f"Scan completed in {end_time - start_time:.2f} seconds.")
