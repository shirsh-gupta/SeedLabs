#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

 

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header

 

    int dest_port = ntohs(tcp_header->th_dport);

 

    if (dest_port >= 10 && dest_port <= 100) { // Filter for destination ports in the range [0, 100]
        printf("Got a TCP packet\n");
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
        printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Destination Port: %d\n", dest_port);
        printf("--------------------------\n");
    }
}

 

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp dst portrange 0-100";  // Filter for TCP packets with destination ports in the range [0, 100]
    bpf_u_int32 net;

 

    // Step 1: Open live pcap session on a network interface.
    handle = pcap_open_live("br-91d588815d3f", BUFSIZ, 1, 1000, errbuf); // Replace with your actual interface name

 

    // Step 2: Compile filter_exp into BPF pseudo-code.
    pcap_compile(handle, &fp, filter_exp, 0, net);

 

    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

 

    // Step 3: Capture packets.
    pcap_loop(handle, -1, got_packet, NULL);

 

    pcap_close(handle); // Close the handle
    return 0;
}
