#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // This function will be called for each captured packet.
    printf("Captured a packet\n");
}
int main() {
    char *dev = "br-91d588815d3f"; // Replace with your network interface name
    char errbuf[PCAP_ERRBUF_SIZE];
    // Open the network interface for packet capture (promiscuous mode turned off)
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 1;
    }
    // Compile and set a packet filter (e.g., capture ICMP packets)
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
    printf("Promiscuous mode OFF\n");
    pcap_loop(handle, 10, packet_handler, NULL); // Capture 10 packets
    // Close the pcap handle
    pcap_close(handle);
    // Now, let us turn on promiscuous mode and capture again
    // Reopen the network interface (promiscuous mode turned on)
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 1;
    }
    // Start capturing packets
    printf("\nPromiscuous mode ON\n");
    pcap_loop(handle, 10, packet_handler, NULL); // Capture 10 packets
    // Close the pcap handle
    pcap_close(handle);
    return 0;
}