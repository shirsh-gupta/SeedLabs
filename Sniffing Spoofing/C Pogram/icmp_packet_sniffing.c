#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header*)packet;
    struct ip *ip_header = (struct ip*)(packet + ETHER_HDR_LEN); // Assuming Ethernet header

    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    // Replace "source_ip_address" and "destination_ip_address" with the actual IP addresses
    char* target_source_ip = "10.9.0.6";
    char* target_dest_ip = "10.9.0.5";

    // Check if the packet is an ICMP packet between specific hosts
    if (ip_header->ip_p == IPPROTO_ICMP && strcmp(source_ip, target_source_ip) == 0 && strcmp(dest_ip, target_dest_ip) == 0) {
        printf("Captured ICMP packet from %s to %s\n", source_ip, dest_ip);
    }
}

int main() {
    char *dev = "br-91d588815d3f"; // Replace with your network interface name
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the network interface with promiscuous mode turned ON
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // Compile and set a packet filter to capture ICMP packets between specific hosts
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Start capturing packets
    printf("Capturing ICMP packets between specific hosts...\n");
    pcap_loop(handle, 0, packet_handler, NULL); // Capture indefinitely

    // Close the pcap handle
    pcap_close(handle);

    return 0;
}

