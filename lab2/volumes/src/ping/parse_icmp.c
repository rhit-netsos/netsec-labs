#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include <pcap.h>

#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "log.h"
#include "util.h"

void parse_icmp(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
                unsigned len) {
  struct ether_header *eth_hdr;
  struct iphdr *iphdr;
  struct icmphdr *icmphdr, *reticmp;
  struct ether_addr *eth_addr;
  struct in_addr addr;
  u_char *retpkt;
  uint32_t tmp_addr;

  iphdr = (struct iphdr *)(pkt + sizeof(struct ether_header));
  icmphdr =
      (struct icmphdr *)(pkt + sizeof(struct ether_header) + sizeof *iphdr);
  eth_addr = ether_aton(my_mac_addr);

  // TODO:
  // =====
  //
  //  1. Check if the ICMP header is an Echo request, if so, just print that
  //     you have received it, and the source from which it originated.
  //
  //     Recall that the source IPv4 address is in the IPv4 header, not the
  //     ICMP header.
  //
  //  2. Send an ICMP Echo Reply to whoever sent you the request.
  //     Here's on approach to do:
  //
  //     2.1 Allocate room for the new packet, use retpkt from above.
  //
  //     2.2 Copy the old packet into the new one, using memcpy.
  //          Hint: we know the full size of the packet already, it is len!
  //
  //     2.3 Adjust the fields of each header that need to be adjusted.
  //
  //     2.4 Use pcap_inject(handle, retpkt, len); to send the packet on the
  //         wire.
  //
  //     2.5 Free the retpkt to make sure you have no memory LEAKS.
  //
}
