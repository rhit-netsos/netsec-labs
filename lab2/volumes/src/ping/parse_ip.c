#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

/**
 * parse_icmp()
 *
 *  This function parses an icmp header and takes appropriate action based on
 *  that header.
 *
 * @param pkt   The pointer to the START of the packet.
 * @param my_mac_addr   The MAC address of the machine running this code,
 *                      passed as a string.
 * @param handle        The pcap_t handle obtained from main.
 * @param len           The total length of the packet.
 *
 * @return nothing.
 *
 */
extern void parse_icmp(const u_char *, const char *, pcap_t *, unsigned);

void parse_ip(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
              unsigned len) {
  struct iphdr *iphdr;
  uint8_t protocol;
  struct in_addr *addr;

  // move forward to ip header
  iphdr = (struct iphdr *)(pkt + sizeof(struct ether_header));
  protocol = iphdr->protocol;

  // TODO:
  // =====
  //  Add code here to call the function parse_icmp in case the IPv4 header
  //  tells you that there is an IMCP header following it.
  //
  //  This should be fairly simply, just adapt your code from the prelab.
  //
}
