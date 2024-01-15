#include <net/ethernet.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "ns_arp.h"
#include "util.h"
#include "log.h"

struct arp_entry {
  int valid;
  struct in_addr ip_addr;
  struct ether_addr mac_addr;
};

// store 16 entries here
struct arp_entry arp_table[16] = {0};
static int initialized = 0;

void initialize_arp_table(void) {
  if(initialized)
    return;

  initialized = 1;
  for(int i = 0; i < 16; i++) {
    arp_table[i].valid = 0;
  }
}

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

  return -1;
}

int bind_arp_sock(int ifindex) {
  int sockfd;
  struct sockaddr_ll sll;

  sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if(sockfd < 1) {
    print_err("Could not create raw socket - %s\n", strerror(errno));
    return -1;
  }

  memset(&sll, 0, sizeof sll);
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifindex;
  if(bind(sockfd, (struct sockaddr*)&sll, sizeof(struct sockaddr_ll)) < 0) {
    print_err("Failed to bind to raw socket - %s\n", strerror(errno));
    return -1;
  }

  return sockfd;
}

int send_arp_request(int sockfd, int ifindex, struct in_addr *sip, struct in_addr *dip, struct ether_addr *saddr) {
  struct sockaddr_ll socket_address;
  char pkt[sizeof(struct ether_header) + sizeof(struct ether_arp)];
  struct ether_header *eth_hdr = (struct ether_header*)pkt;
  struct ether_arp *arp_hdr = (struct ether_arp*)(pkt + sizeof(struct ether_header));

  socket_address.sll_family = AF_PACKET;
  socket_address.sll_protocol = htons(ETH_P_ARP);
  socket_address.sll_ifindex = ifindex;
  socket_address.sll_hatype = htons(ARPHRD_ETHER);
  socket_address.sll_pkttype = (PACKET_BROADCAST);
  socket_address.sll_halen = 6;
  socket_address.sll_addr[6] = 0x00;
  socket_address.sll_addr[7] = 0x00;

  // set ethernet header
  memset(eth_hdr->ether_dhost, 0xff, sizeof eth_hdr->ether_dhost);
  memcpy(eth_hdr->ether_shost, saddr->ether_addr_octet, sizeof eth_hdr->ether_shost);
  eth_hdr->ether_type = htons(ETHERTYPE_ARP);

  // set arp header
  arp_hdr->ea_hdr.ar_op  = htons(ARPOP_REQUEST);
  arp_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
  arp_hdr->ea_hdr.ar_hln = 6;
  arp_hdr->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
  arp_hdr->ea_hdr.ar_pln = 4;

  memcpy(arp_hdr->arp_sha, saddr->ether_addr_octet, sizeof arp_hdr->arp_sha);
  memcpy(arp_hdr->arp_spa, &sip->s_addr, 4);

  memset(arp_hdr->arp_tha, 0, sizeof arp_hdr->arp_tha);
  memcpy(arp_hdr->arp_tpa, (void*)&dip->s_addr, 4);

  if(sendto(sockfd, pkt, sizeof pkt, 0, (struct sockaddr*)&socket_address, sizeof socket_address) < 0) {
    print_err("Could not send ARP request - %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

int read_arp_reply(int sockfd, struct ether_addr *daddr) {
  char pkt[BUFSIZ];
  ssize_t recvlen;
  struct ether_header *eth;
  struct ether_arp *arp;

  recvlen = recvfrom(sockfd, pkt, BUFSIZ, 0, 0, 0);
  if(recvlen == -1) {
    print_err("Failed to receive ARP reply!\n");
    return -1;
  }

  eth = (struct ether_header*)pkt;
  if(eth->ether_type != htons(ETHERTYPE_ARP)) {
    print_err("Failed to receive ARP reply!\n");
    return -1;
  }

  arp = (struct ether_arp*)(eth + sizeof(struct ether_header));
  memcpy(daddr->ether_addr_octet, arp->arp_sha, sizeof daddr->ether_addr_octet);
  return 0;
}

int arp_get_mac(struct in_addr *sip, struct in_addr *dip,
                struct ether_addr *saddr, struct ether_addr *daddr,
                const char *ifname) {
  int i;
  int ifindex;
  int sockfd;

  // check if need to init the table
  initialize_arp_table();

  // is it in the table?
  for(i = 0; i < 16; i++) {
    if(arp_table[i].valid && arp_table[i].ip_addr.s_addr == dip->s_addr) {
      memcpy(daddr->ether_addr_octet, arp_table[i].mac_addr.ether_addr_octet, sizeof daddr->ether_addr_octet);
      return 0;
    }
  }

  // not found, need to ask for it
  ifindex = if_nametoindex(ifname);
  if(!ifindex) {
    print_err("Could not get index for interface %s - %s", ifname, strerror(errno));
    return -1;
  }

  // much of code here obtained from: https://stackoverflow.com/a/39287433
  sockfd = bind_arp_sock(ifindex);
  if(sockfd < 0)
    return -1;

  if(send_arp_request(sockfd, ifindex, sip, dip, saddr) < 0)
    return -1;
  if(read_arp_reply(sockfd, daddr) < 0)
    return -1;

  // save it in the table
  for(int i = 0; i < 16; i++) {
    if(arp_table[i].valid == 0) {
      arp_table[i].valid = 1;
      arp_table[i].ip_addr.s_addr = dip->s_addr;
      memcpy(arp_table[i].mac_addr.ether_addr_octet, daddr->ether_addr_octet, sizeof daddr->ether_addr_octet);
    }
  }

  return 0;
}

