# Network Packet Analyzer

This project contains a **Python-based packet sniffer** that captures network packets and saves them into a **PCAP file**. The captured packets are then analyzed by a **Zeek script**.

## Features

- **Packet Sniffer**: A Python script that uses raw sockets to listen for packets on a network interface. It captures these packets and writes them to a PCAP file for further analysis.

- **PCAP File**: The Packet Capture (PCAP) file is a standard format for storing network packets. It can be read by various network analysis tools, including Zeek.

- **Zeek Script**: Zeek, formerly known as Bro, is a powerful network analysis framework. In this project, a Zeek script is used to analyze the PCAP file. The script contains a set of rules for identifying and logging specific network events.

## Usage

The packet sniffer can be run on any system with Python installed. Once the packets have been captured and saved to a PCAP file, the Zeek script can be used to analyze the data. The script will generate logs based on the rules defined within it.

This project is useful for network administrators, security researchers, and anyone interested in network analysis. It provides a simple and flexible way to capture and analyze network traffic.

**Note**: This project is intended for educational and research purposes. Please ensure you have the necessary permissions before capturing network traffic. Unauthorized network sniffing can be illegal and unethical. Always respect privacy and use responsibly.# Packet-Sniffer-with-python
