import subprocess
import re
import sqlite3
import csv
from scapy.all import sniff, wrpcap, get_if_list, get_if_hwaddr
import os
import matplotlib.pyplot as plt
import time

# -------------------------
# 1. Database Setup
# -------------------------
DB_NAME = "iot_devices.db"

def setup_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            ip TEXT,
            mac TEXT,
            vendor TEXT,
            model TEXT,
            version TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_device(ip, mac, vendor="Unknown", name=None, model=None, version=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO devices (name, ip, mac, vendor, model, version) 
        VALUES (?, ?, ?, ?, ?, ?)
    """, (name, ip, mac, vendor, model, version))
    conn.commit()
    conn.close()
    print(f"Device {name or mac} saved to the database.")

def delete_device(mac):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM devices WHERE mac = ?", (mac,))
    conn.commit()
    conn.close()
    print(f"Device with MAC {mac} deleted.")

def list_saved_devices():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices")
    devices = cursor.fetchall()
    conn.close()
    return devices

# -------------------------
# 2. Connected Device Scanning
# -------------------------
def get_filtered_devices(hotspot_subnet):
    devices = []
    try:
        result = subprocess.run("arp -a", shell=True, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([\w:-]+)', line)
            if match:
                ip = match.group(1)
                mac = match.group(2)
                if ip.startswith(hotspot_subnet):  # Filter by subnet
                    # Exclude gateway and broadcast addresses
                    if ip == f"{hotspot_subnet}1" or ip == f"{hotspot_subnet}255":
                        continue
                    devices.append({"IPv4": ip, "MAC": mac})
    except Exception as e:
        print(f"Error: {e}")
    return devices

# -------------------------
# 3. Packet Capture
# -------------------------
def capture_packets(interface, output_file, count=50):
    print(f"Capturing {count} packets on interface {interface}...")
    start_time = time.time()

    packets = sniff(iface=interface, count=count)
    end_time = time.time()

    total_data = sum(len(packet) for packet in packets)
    elapsed_time = end_time - start_time
    data_rate = (total_data / elapsed_time) / 1024

    wrpcap(output_file, packets)
    print(f"Packets saved to {output_file}")
    print(f"Total Data: {total_data / 1024:.2f} KB, Elapsed Time: {elapsed_time:.2f} seconds")
    print(f"Data Rate: {data_rate:.2f} KB/s")
    return packets

# -------------------------
# 4. Display Network Interfaces
# -------------------------
def list_interfaces():
    interfaces = get_if_list()
    print("Available Network Interfaces:")
    for interface in interfaces:
        try:
            mac = get_if_hwaddr(interface)
            print(f"Interface: {interface}, MAC Address: {mac}")
        except:
            print(f"Interface: {interface}, MAC Address: Unknown")

# -------------------------
# 5. Intrusion Detection System (IDS)
# -------------------------
def detect_intrusions(interface, packet_limit=100):
    print(f"Starting IDS on interface {interface}, analyzing {packet_limit} packets...")

    start_time = time.time()
    total_data = 0
    packets_analyzed = 0

    def analyze_packet(packet):
        nonlocal total_data, packets_analyzed
        packets_analyzed += 1
        total_data += len(packet)

        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst

            if packet.haslayer("TCP") or packet.haslayer("UDP"):
                port = packet.sport if packet.haslayer("TCP") else packet.dport
                print(f"Suspicious connection attempt: IP {ip_src} -> {ip_dst}:{port}")

            if packet.haslayer("ICMP"):
                icmp_type = packet["ICMP"].type
                if icmp_type == 8:
                    print(f"Possible Ping Flood detected from {ip_src} to {ip_dst}")

        elif packet.haslayer("ARP"):
            print(f"ARP packet detected: {packet.summary()}")

        if packets_analyzed >= packet_limit:
            return False
        return True

    sniff(iface=interface, count=packet_limit, prn=analyze_packet)

    end_time = time.time()
    elapsed_time = end_time - start_time
    data_rate = (total_data / elapsed_time) / 1024
    print(f"IDS session complete. Total Data: {total_data / 1024:.2f} KB, Elapsed Time: {elapsed_time:.2f} seconds")
    print(f"Data Rate: {data_rate:.2f} KB/s")

# -------------------------
# Bonus Features
# -------------------------
def scan_device_vulnerabilities(device_ip):
    print(f"Scanning device {device_ip} for vulnerabilities...")
    
    result = subprocess.run(f"nmap -sV {device_ip}", shell=True, capture_output=True, text=True)
    vulnerabilities = []
    for line in result.stdout.splitlines():
        if "open" in line:
            vulnerabilities.append(line)
    return vulnerabilities

def monitor_traffic(interface, packet_limit=50):
    def packet_callback(packet):
        print(packet.summary())

    print(f"Monitoring traffic on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, count=packet_limit)

# -------------------------
# Main Application
# -------------------------
def main():
    print("IoT Device Manager with IDS")
    print("===========================")
    
    setup_database()

    while True:
        print("\nOptions:")
        print("1. List connected IoT devices")
        print("2. Save a device to the database")
        print("3. View saved devices")
        print("4. Delete a device from the database")
        print("5. Export saved devices to CSV")
        print("6. Capture packets")
        print("7. List network interfaces")
        print("8. Run Intrusion Detection System (IDS)")
        print("9. Scan device for vulnerabilities")
        print("10. Monitor network traffic")
        print("11. Exit")
        
        choice = input("Enter your choice: ").strip()
        
        if choice == "1":
            print("\nConnected Devices:")
            hotspot_subnet = input("Enter your hotspot subnet (e.g., 192.168.0.): ").strip()
            devices = get_filtered_devices(hotspot_subnet)
            for device in devices:
                print(f"IPv4: {device['IPv4']}, MAC: {device['MAC']}")
        
        elif choice == "2":
            print("\nSave a Device:")
            ip = input("Enter IP address: ").strip()
            mac = input("Enter MAC address: ").strip()
            name = input("Enter name (optional): ").strip() or None
            model = input("Enter model (optional): ").strip() or None
            version = input("Enter version (optional): ").strip() or None
            save_device(ip, mac, name=name, model=model, version=version)
        
        elif choice == "3":
            print("\nSaved Devices:")
            devices = list_saved_devices()
            for device in devices:
                print(f"ID: {device[0]}, Name: {device[1]}, IP: {device[2]}, MAC: {device[3]}, Vendor: {device[4]}, Model: {device[5]}, Version: {device[6]}")
        
        elif choice == "4":
            print("\nDelete a Device:")
            mac = input("Enter MAC address of the device to delete: ").strip()
            delete_device(mac)
        
        elif choice == "5":
            print("\nExporting Devices to CSV...")
            file_name = input("Enter CSV file name (e.g., devices.csv): ").strip()
            devices = list_saved_devices()
            with open(file_name, 'w', newline='') as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow(["ID", "Name", "IP", "MAC", "Vendor", "Model", "Version"])
                csvwriter.writerows(devices)
            print(f"Devices exported to {file_name}")
        
        elif choice == "6":
            print("\nCapture Packets:")
            interface = input("Enter the network interface (e.g., Wi-Fi): ").strip()
            output_file = input("Enter the output .pcap file name: ").strip()
            count = int(input("Enter the number of packets to capture: ").strip())
            capture_packets(interface, output_file, count)
        
        elif choice == "7":
            print("\nNetwork Interfaces:")
            list_interfaces()
        
        elif choice == "8":
            print("\nRunning Intrusion Detection System (IDS):")
            interface = input("Enter the network interface (e.g., Wi-Fi): ").strip()
            packet_limit = int(input("Enter the number of packets to analyze: ").strip())
            detect_intrusions(interface, packet_limit)
        
        elif choice == "9":
            device_ip = input("Enter the device IP to scan: ").strip()
            vulnerabilities = scan_device_vulnerabilities(device_ip)
            if vulnerabilities:
                print("\nFound Vulnerabilities:")
                for vuln in vulnerabilities:
                    print(vuln)
            else:
                print("No vulnerabilities detected.")
        
        elif choice == "10":
            print("\nMonitor Network Traffic:")
            interface = input("Enter the network interface (e.g., Wi-Fi): ").strip()
            packet_limit = int(input("Enter the number of packets to monitor: ").strip())
            monitor_traffic(interface, packet_limit)
        
        elif choice == "11":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()