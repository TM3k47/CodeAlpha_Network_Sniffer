# network_sniffer by TM_47
from scapy.all import sniff, Ether, IP, TCP

protocol_names = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    2: "IGMP",
    4: "IPv4-in-IPv4",
    41: "IPv6-in-IPv4",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    89: "OSPF",
    132: "SCTP",
    255: "Reserved",
    252: "Experimental",
    253: "Experimental",
    254: "Experimental",
    59: "No Next Header",
    60: "Destination Options",
    103: "PIM",
    121: "SMP",
    80: "HTTP",  

def packet_handler(packet):
    if Ether in packet and IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        protocol_name = protocol_names.get(protocol, "Unknown")

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol Number: {protocol} | Protocol Name: {protocol_name}")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Source Port: {src_port} | Destination Port: {dst_port}")

sniff(iface='wlan0', prn=packet_handler, filter='ip')


