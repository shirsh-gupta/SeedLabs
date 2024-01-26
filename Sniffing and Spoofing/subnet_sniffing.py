from scapy.all import *

def capture_packets(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        subnet = ipaddress.IPv4Network("128.230.0.0/16")
        if src_ip in subnet or dst_ip in subnet:
            pkt.show()
sniff(filter="(icmp or tcp) and (net 128.230.0.0/16)", prn=capture_packets)