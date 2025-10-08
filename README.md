# Network Sniffer

A simple, minimal network sniffer script using Scapy.

## Description

This script captures network packets on a specified interface and displays information about them, including timestamp, source and destination IP addresses, protocol, and source and destination ports for TCP/UDP packets. It also shows a snippet of the payload if it exists.

## Features

-   Captures packets on a specified network interface.
-   Displays timestamp, source/destination IP, and protocol.
-   Shows source/destination ports for TCP and UDP packets.
-   Displays a snippet of the packet's payload.
-   Colorized output for better readability.
-   Command-line arguments for interface and packet count.

## Dependencies

-   **Scapy**: A powerful interactive packet manipulation program.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/or3ki-01xs/CodeAlpha_Network_Sniffer.git
    cd CodeAlpha_Network_Sniffer
    ```

2.  Install the dependencies:
    ```bash
    pip install scapy
    ```

## Usage

You need to run the script with root privileges to capture packets.

```bash
sudo python3 sniffer.py [OPTIONS]
```

### Options

-   `-i, --interface`: The network interface to sniff on (e.g., `eth0`, `wlan0`). Defaults to `wlan0`.
-   `-c, --count`: The number of packets to capture. `0` means capture indefinitely. Defaults to `0`.

### Examples

-   Capture packets on the default interface (`wlan0`):
    ```bash
    sudo python3 sniffer.py
    ```

-   Capture packets on a specific interface (e.g., `eth0`):
    ```bash
    sudo python3 sniffer.py -i eth0
    ```

-   Capture a specific number of packets (e.g., 10):
    ```bash
    sudo python3 sniffer.py -c 10
    ```

## Example Output

```
[*] Starting sniffer on interface wlan0...
[*] Press Ctrl+C to stop.
[2025-10-08 10:30:01] Source: 192.168.1.10 -> Destination: 1.1.1.1 | Protocol: UDP
    UDP Packet: Source Port: 53 | Destination Port: 54321
    Payload: b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01'
[2025-10-08 10:30:02] Source: 192.168.1.10 -> Destination: 93.184.216.34 | Protocol: TCP
    TCP Packet: Source Port: 12345 | Destination Port: 80
    Payload: b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n...'
```
