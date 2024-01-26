#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/socket.h>

 

#define PACKET_LEN 512

 

// Define the Ethernet header structure
struct ethheader {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

 

// Define the IP header structure
struct ipheader {
    u_char iph_ihl:4, iph_ver:4;
    u_char iph_tos;
    u_short iph_len;
    u_short iph_ident;
    u_short iph_flags;
    u_char iph_ttl;
    u_char iph_protocol;
    u_short iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

 

// Define the ICMP header structure
struct icmpheader {
    u_char icmp_type;
    u_char icmp_code;
    u_short icmp_chksum;
    u_short icmp_id1;
    u_short icmp_seq1;
};

 

void send_raw_ip_packet(struct ipheader *ip) {
    struct sockaddr_in dest_info;
    int enable = 1;

 

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

 

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

 

    // Step 3: Provide needed information about the destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

 

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

 

void send_echo_reply(struct ipheader *ip) {
    int ip_header_len = ip->iph_ihl * 4;
    char buffer[PACKET_LEN];

 

    // Make a copy from the original packet to the buffer (faked packet)
    memset(buffer, 0, PACKET_LEN);
    memcpy(buffer, ip, ntohs(ip->iph_len));
    struct ipheader *newip = (struct ipheader *)buffer;
    struct icmpheader *newicmp = (struct icmpheader *)(buffer + ip_header_len);

 

    // Construct IP: SWAP src and dest in the faked ICMP packet
    newip->iph_sourceip = ip->iph_destip;
    newip->iph_destip = ip->iph_sourceip;
    newip->iph_ttl = 64;

 

    // Fill in all the needed ICMP header information.
    // ICMP Type: 8 is request, 0 is reply.
    newicmp->icmp_type = 0;

 

    send_raw_ip_packet(newip);
}

 

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

 

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IPv4 type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

 

        printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("         To: %s\n", inet_ntoa(ip->iph_destip));

 

        /* determine protocol */
        switch (ip->iph_protocol) {
            case IPPROTO_TCP:
                printf("   Protocol: TCP\n");
                return;
            case IPPROTO_UDP:
                printf("   Protocol: UDP\n");
                return;
            case IPPROTO_ICMP:
                printf("   Protocol: ICMP\n");
                send_echo_reply(ip);
                return;
            default:
                printf("   Protocol: others\n");
                return;
        }
    }
}

 

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

 

    char filter_exp[] = "icmp[icmptype] == 8"; // Filter ICMP Echo Request packets

 

    bpf_u_int32 net;

 

    // Step 1: Open a live pcap session on NIC


 

  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("br-91d588815d3f", BUFSIZ, 1, 1000, errbuf);

 

  // Step 2: Compile filter_exp into BPF pseudo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

 

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

 

  pcap_close(handle);   //Close the handle 
  return 0;
}
