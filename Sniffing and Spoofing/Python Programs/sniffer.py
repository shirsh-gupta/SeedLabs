#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface='br-91d588815d3f', filter='icmp', prn=print_pkt)