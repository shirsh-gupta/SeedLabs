from scapy.all import *

def print_telnet_info(pkt):
    if TCP in pkt and pkt[TCP].dport == 23 and pkt[IP].src == '10.9.0.6':
        print("Telnet Packet:")
        print(f"\tDestination IP: {pkt[IP].dst}")
        print(f"\tSource IP: {pkt[IP].src}")
        print(f"\tSource Port: {pkt[TCP].sport}")
        print(f"\tDestination Port: {pkt[TCP].dport}")
# Replace 'br-91d588815d3f' with the correct interface name
iface_name = 'br-91d588815d3f'
# Use a filter to capture only Telnet traffic
filter_str = 'tcp port 23'
# Start packet capture
sniff(iface=iface_name, filter=filter_str, prn=print_telnet_info)