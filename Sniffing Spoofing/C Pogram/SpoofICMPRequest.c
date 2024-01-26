#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#define DEST_IP "10.9.0.5"

unsigned short in_cksum(unsigned short *buf, int length) {
  unsigned short *w = buf;
  int nleft = length;
  int sum = 0;
  unsigned short temp=0;
  /*
   * The algorithm uses a 32 bit accumulator (sum), adds
   * sequential 16 bit words to it, and at the end, folds back all
   * the carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
      sum += *w++;
      nleft -= 2;
  }
  /* treat the odd byte at the end, if any */
  if (nleft == 1) {
       *(u_char *)(&temp) = *(u_char *)w;
       sum += temp;
  }
  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
  sum += (sum >> 16);                  // add carry
  return (unsigned short)(~sum);
}
void send_raw_ip_packet(struct ip* ipHeader) {
   struct sockaddr_in dest_info;
   int enable = 1;
   // Step 1: Create a raw network socket.
   int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
   // Step 2: Set socket option.
   setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable));
   // Step 3: Provide needed information about destination.
   dest_info.sin_family = AF_INET;
dest_info.sin_addr.s_addr = ipHeader->ip_dst.s_addr;
   // Step 4: Send the packet out.
   sendto(sock, ipHeader, ntohs(ipHeader->ip_len), 0,
          (struct sockaddr *)&dest_info, sizeof(dest_info));
   close(sock);
}
int main() {
  char buffer[1500];
  memset(buffer, 0, 1500);
   struct ip *ipHeader = (struct ip *)buffer;
   struct icmphdr *icmpHeader = (struct icmphdr *)(buffer + sizeof(struct ip));   
   icmpHeader->type = 8;     // ICMP echo request
   icmpHeader->checksum = 0;       // Checksum (0 for now)
   icmpHeader->checksum = in_cksum((unsigned short *)icmpHeader,sizeof(struct icmphdr));
   ipHeader->ip_hl = 5;                 // Header length
   ipHeader->ip_v = 4;                  // IPv4 
   ipHeader->ip_ttl = 64;               // Time to live   
   ipHeader->ip_len = htons(sizeof(struct ip) + sizeof(struct icmphdr));   
    ipHeader->ip_p = IPPROTO_ICMP;       // Protocol: ICMP 
  ipHeader->ip_src.s_addr = inet_addr("8.8.8.8"); // Source IP address
  ipHeader->ip_dst.s_addr = inet_addr("10.9.0.5"); // Destination IP address   
 send_raw_ip_packet(ipHeader);
  return 0;
}
