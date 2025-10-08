#!/usr/bin/env python3

import argparse
import sys
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP
import socket

# Colors for terminal output
class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"

def get_protocol_name(protocol_number):
    """Get protocol name from its number."""
    protocol_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        89: "OSPF",
    }
    return protocol_map.get(protocol_number, "Unknown")

def packet_handler(packet):
    """Processes each captured packet."""
    if Ether in packet and IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        protocol_name = get_protocol_name(protocol)

        print(
            f"{Colors.CYAN}[{timestamp}]{Colors.RESET} "
            f"{Colors.GREEN}Source: {src_ip}{Colors.RESET} -> "
            f"{Colors.YELLOW}Destination: {dst_ip}{Colors.RESET} | "
            f"{Colors.MAGENTA}Protocol: {protocol_name.upper()}{Colors.RESET}"
        )

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(
                f"    {Colors.BLUE}TCP Packet:{Colors.RESET} "
                f"Source Port: {src_port} | Destination Port: {dst_port}"
            )
            if packet[TCP].payload:
                print(f"    {Colors.RED}Payload:{Colors.RESET} {bytes(packet[TCP].payload)[:30]}...")

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(
                f"    {Colors.BLUE}UDP Packet:{Colors.RESET} "
                f"Source Port: {src_port} | Destination Port: {dst_port}"
            )
            if packet[UDP].payload:
                print(f"    {Colors.RED}Payload:{Colors.RESET} {bytes(packet[UDP].payload)[:30]}...")

def main():
    """Main function to start the sniffer."""
    parser = argparse.ArgumentParser(description="A simple network sniffer.")
    parser.add_argument(
        "-i", "--interface", type=str, default="wlan0", help="Interface to sniff on (default: wlan0)"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)"
    )
    args = parser.parse_args()

    print(f"{Colors.YELLOW}[*] Starting sniffer on interface {args.interface}...{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Press Ctrl+C to stop.{Colors.RESET}")

    try:
        sniff(iface=args.interface, prn=packet_handler, count=args.count, filter="ip")
    except PermissionError:
        print(f"{Colors.RED}[!] Error: You need to run this script with root privileges.{Colors.RESET}")
        sys.exit(1)
    except OSError as e:
        print(f"{Colors.RED}[!] Error: {e}. Interface '{args.interface}' may not exist.{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
