#include <netinet/if_ether.h>
#include <netinet/ether.h>

#include <arpa/inet.h>

#include "ns_arp.h"
#include "util.h"
#include "log.h"

// parse an ARP packet
int parse_arp(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle) {
  static char logfmt[1024];
  char *str = logfmt;
  struct ether_header *eth;
  struct ether_arp *arp;
  struct in_addr *addr;
  struct ether_addr *eth_addr;
  u_short a_op;
  const char *ip, *mac;

  // grab the Ethernet header
  eth = (struct ether_header*)pkt;
  arp = (struct ether_arp*)(pkt + sizeof *eth);
  a_op = ntohs(arp->ea_hdr.ar_op);

  if(a_op == ARPOP_REQUEST) {
    // The ARP request has the following meaningful fields:
    //  - spa: Source physical address.
    //  - sha: Source hardware address.
    //  - tpa: Target physical address.
    //  - tha: Target hardware address.
    ip = ip_to_str((void*)arp->arp_tpa);
    str += sprintf(str, "Who has %s? ", ip);

    ip = ip_to_str((void*)arp->arp_spa);
    str += sprintf(str, "tell %s!\n", ip);

    mac = mac_to_str((void*)arp->arp_sha);
    str += sprintf(str, "\t\tFrom %s ", mac);

    mac = mac_to_str((void*)arp->arp_tha);
    str += sprintf(str, "to %s.", mac);

    print_log("(%s) %s\n", fmt_ts(&hdr->ts), logfmt);
    return 0;
  } else if (a_op == ARPOP_REPLY) {
    ip = ip_to_str((void*)arp->arp_spa);
    mac = mac_to_str((void*)arp->arp_sha);

    print_log("(%s) %s is at %s\n", fmt_ts(&hdr->ts), ip, mac);
    return 0;
  }
}
