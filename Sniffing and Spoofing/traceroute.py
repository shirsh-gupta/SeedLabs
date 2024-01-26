from scapy.all import *
def traceroute(destination, max_hops=30):
    ttl = 1
    while ttl <= max_hops:
        # Create an ICMP packet with increasing TTL
        packet = IP(dst=destination, ttl=ttl) / ICMP()
        reply = sr1(packet, verbose=False, timeout=1)
        if reply is None:
            print(f"{ttl}: *")
        elif reply.type == 0:
            print(f"{ttl}: {reply.src}")
            break
        else:
            print(f"{ttl}: {reply.src} (ICMP Type {reply.type})")
        ttl += 1
if __name__ == "__main__":
    destination = input("Enter destination IP or hostname: ")
    traceroute(destination)