#!/usr/bin/env python

import socket
import threading
import queue
from tqdm import tqdm
import time

# Ask user for target input
target = input("Enter the IP address or hostname to scan: ")

try:
    target_ip = socket.gethostbyname(target)
except socket.gaierror:
    print("❌ Invalid hostname or IP address.")
    exit()

print(f"🔍 Scanning target: {target} ({target_ip})")

# Ask for number of threads
try:
    thread_count = int(input("Enter number of threads to use (default = 10): ") or 10)
except ValueError:
    print("Invalid thread count. Using default = 10.")
    thread_count = 10

# Globals
port_queue = queue.Queue()
open_ports = []
progress = None

# Vulnerability Guessing Dictionary
vuln_guess = {
    21: "FTP: Check for anonymous login vulnerability",
    22: "SSH: Brute force, outdated SSH versions",
    23: "Telnet: Insecure protocol, should be disabled",
    25: "SMTP: Open relay or spoofing possible",
    53: "DNS: Cache poisoning or zone transfer",
    80: "HTTP: Check for outdated web server software",
    110: "POP3: Cleartext credentials, weak auth",
    135: "RPC: Vulnerable to MS03-026 (Blaster worm)",
    139: "NetBIOS: Info leakage, LLMNR/NBT-NS attacks",
    143: "IMAP: Unencrypted communication",
    445: "SMB: EternalBlue (MS17-010), WannaCry",
    3306: "MySQL: Default credentials or weak config",
    3389: "RDP: BlueKeep (CVE-2019-0708), brute force",
    8080: "HTTP proxy: May expose internal services"
}

# Scan a single port
def port_scanner(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((target_ip, port))
        return True
    except:
        return False

# Fill port queue
def fill_queue():
    for port in range(1, 1024):
        port_queue.put(port)

# Worker thread to scan ports
def worker():
    global progress
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            break
        if port_scanner(port):
            print(f"✅ Port {port} is open.")
            open_ports.append(port)
        progress.update(1)

# Run the scanner
start_time = time.time()
fill_queue()
total_ports = port_queue.qsize()
progress = tqdm(total=total_ports, desc="⚙️ Scanning Ports")

thread_list = []
for _ in range(thread_count):
    thread = threading.Thread(target=worker)
    thread_list.append(thread)
    thread.start()

for thread in thread_list:
    thread.join()

progress.close()
end_time = time.time()

# Results
print("\n🎯 Scanning complete.")
print(f"🔓 Open ports on {target_ip}: {open_ports if open_ports else 'None'}")
print(f"⏱️ Scan Duration: {end_time - start_time:.2f} seconds")

# Vulnerability Suggestions
if open_ports:
    print("\n🧠 Possible Vulnerabilities:")
    for port in open_ports:
        if port in vuln_guess:
            print(f"⚠️  Port {port}: {vuln_guess[port]}")
        else:
            print(f"ℹ️  Port {port}: No known guess — may be custom or uncommon service.")
