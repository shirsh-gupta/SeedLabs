#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#define PACKET_SIZE 64
#define DEST_IP "10.9.0.6" // Replace with the destination IP address you want to use
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}
int main() {
    int sd;
    char buffer[PACKET_SIZE];
    struct sockaddr_in sin;
    struct ip *ipHeader = (struct ip *)buffer;
    struct icmphdr *icmpHeader = (struct icmphdr *)(buffer + sizeof(struct ip));
    // Create a raw socket with IP protocol
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket() error");
        exit(-1);
    }
   
    sin.sin_family = AF_INET;
    // Initialize IP header
    ipHeader->ip_hl = 5;                 // Header length
    ipHeader->ip_v = 4;                  // IPv4
    ipHeader->ip_tos = 0;                // Type of service
    ipHeader->ip_len = htons(PACKET_SIZE); // Total length
    ipHeader->ip_id = htons(0);          // Identification
    ipHeader->ip_off = 0;                // Fragment offset
    ipHeader->ip_ttl = 64;               // Time to live
    ipHeader->ip_p = IPPROTO_ICMP;       // Protocol: ICMP
    ipHeader->ip_sum = 0;                // Checksum (0 for now)
    ipHeader->ip_src.s_addr = inet_addr("10.52.65.63"); // Source IP address
    ipHeader->ip_dst.s_addr = inet_addr(DEST_IP); // Destination IP address
    // Initialize ICMP header
    icmpHeader->type = ICMP_ECHO;     // ICMP echo request
    icmpHeader->code = 0;             // Code 0
    icmpHeader->checksum = 0;        // Checksum (0 for now)
    icmpHeader->un.echo.id = 0;      // Identifier
    icmpHeader->un.echo.sequence = 0; // Sequence number
    // Fill in the data part if needed 
    // Size of the data you want to include in the ICMP packet
int data_size = 13; // Size of "Hello, World!" including the null terminator
// Fill in the data part of the ICMP packet with "Hello, World!"
char *data = buffer + sizeof(struct ip) + sizeof(struct icmphdr);
strcpy(data, "Hello, World!"); // Copy the string into the data field
 
    if(sendto(sd, buffer, PACKET_SIZE, 0, (struct sockaddr *)&sin,sizeof(sin)) < 0) {
    perror("sendto() error"); 
    exit(-1);
    }
    close(sd);
    return 0;
}