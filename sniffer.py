import socket
from general import *
import time
import argparse
import logging
import netifaces
from conn_scripts.net_interface import Ethernet
from conn_scripts.ipv4 import IPv4
from conn_scripts.icmp import ICMP
from conn_scripts.tcp import TCP
from conn_scripts.udp import UDP
from conn_scripts.pcap import Pcap
from conn_scripts.http import HTTP
from conn_scripts.dns import DNS

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def get_default_interface():
    try:
        default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        return default_interface
    except Exception as e:
        print(f"Could not find default interface: {e}")
        return None

network_interface = get_default_interface()
if network_interface == 'wlan0':
    net_interface = "WIFI"
elif network_interface == 'ether':
    net_interface = "ETHERNET"

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', help='Network interface to sniff on', default=get_default_interface())
    parser.add_argument('-t', '--time', help='Duration of the capture in seconds', default=10, type=int)
    return parser.parse_args()

def setup_logging():
    logging.basicConfig(format='%(message)s', level=logging.INFO)

def handle_packet(raw_data):
    eth = Ethernet(raw_data)
    
    print('\n{} Frame:'.format(net_interface))
    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

    # IPv4
    if eth.proto == 8:
        ipv4 = IPv4(eth.data)
        print(TAB_1 + 'IPv4 Packet:')
        print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
        print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

        # ICMP
        if ipv4.proto == 1:
            icmp = ICMP(ipv4.data)
            print(TAB_1 + 'ICMP Packet:')
            print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
            print(TAB_2 + 'ICMP Data:')
            print(format_multi_line(DATA_TAB_3, icmp.data))

        # TCP
        elif ipv4.proto == 6:
            tcp = TCP(ipv4.data)
            print(TAB_1 + 'TCP Segment:')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
            print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
            print(TAB_2 + 'Flags:')
            print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
            print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

            if len(tcp.data) > 0:

                # HTTP
                if tcp.src_port == 80 or tcp.dest_port == 80:
                    print(TAB_2 + 'HTTP Data:')
                    try:
                        http = HTTP(tcp.data)
                        http_info = str(http.data).split('\n')
                        for line in http_info:
                            print(DATA_TAB_3 + str(line))
                    except:
                        print(format_multi_line(DATA_TAB_3, tcp.data))
                else:
                    print(TAB_2 + 'TCP Data:')
                    print(format_multi_line(DATA_TAB_3, tcp.data))

        # UDP
        elif ipv4.proto == 17:
            udp = UDP(ipv4.data)
            print(TAB_1 + 'UDP Segment:')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))
        # Other IPv4
        else:
            print(TAB_1 + 'Other IPv4 Data:')
            print(format_multi_line(DATA_TAB_2, ipv4.data))

    else:
        print('Ethernet Data:')
        print(format_multi_line(DATA_TAB_1, eth.data))

def sniffing():
    pcap = Pcap('capture.pcap')
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except Exception as e:
        logging.error(f"Could not open socket: {e}")
        return

    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        handle_packet(raw_data)
    pcap.close()


sniffing()