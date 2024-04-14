# Network Packet Analyzer

This project contains a **Python-based packet sniffer** that captures network packets and saves them into a **PCAP file**. The captured packets are then analyzed by a **Zeek script**.

## Features

- **Packet Sniffer**: A Python script that uses raw sockets to listen for packets on a network interface. It captures these packets and writes them to a PCAP file for further analysis.

- **PCAP File**: The Packet Capture (PCAP) file is a standard format for storing network packets. It can be read by various network analysis tools, including Zeek.

- **Zeek Script**: Zeek, formerly known as Bro, is a powerful network analysis framework. In this project, a Zeek script is used to analyze the PCAP file. The script contains a set of rules for identifying and logging specific network events.

## Usage

The packet sniffer can be run on any system with Python installed. Once the packets have been captured and saved to a PCAP file, the Zeek script can be used to analyze the data. The script will generate logs based on the rules defined within it.

This project is useful for network administrators, security researchers, and anyone interested in network analysis. It provides a simple and flexible way to capture and analyze network traffic.

**Note**: This project is intended for educational and research purposes. Please ensure you have the necessary permissions before capturing network traffic. Unauthorized network sniffing can be illegal and unethical. Always respect privacy and use responsibly.

Make sure you gave correct paths for all files included in zeek script

You can modify the zeek script by adding more protocols and rules which are compatable to your network

In some operating systems zeek will generate logs directly in working directory make sure that to generate logs in logs directory

I have given a exampke of pcap file and logs in example folder.Please refer to it.

## About Zeek

Zeek, formerly known as Bro, is a powerful network analysis framework. It is not restricted to any particular detection approach and is highly stateful, keeping extensive application-layer state about the network it monitors. This makes Zeek a powerful tool for deep network analysis.

## Learning Zeek

If you're new to Zeek and would like to learn more about it, here are some resources that might help:

- **Zeek Documentation**: The official [Zeek documentation](https://github.com/zeek/zeek) is a great place to start. It provides a comprehensive overview of Zeek's capabilities and how to use them.
 
## Installing Zeek

You can install Zeek in two ways:

1. **Using Pip**:
    You can install Zeek using pip, a package installer for Python. Simply run the following command in your terminal:
    ```
    pip install zeek
    ```

2. **Directly from the Zeek website**:
    You can also install Zeek directly from the official Zeek website. Detailed installation instructions can be found at this link: Zeek Installation Guide
