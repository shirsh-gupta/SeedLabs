from scapy.all import *
spoofed_source_ip = "10.9.0.6" # Replace with the IP address you want to spoof
target_ip = "10.9.0.5" # Replace with the target IP address
# Craft the spoofed ICMP packet
ip_layer = IP(src=spoofed_source_ip, dst=target_ip)
icmp_layer = ICMP()
spoofed_packet = ip_layer / icmp_layer
# Send the spoofed packet
send(spoofed_packet)