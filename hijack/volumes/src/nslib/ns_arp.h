#ifndef __NS_ARP_H
#define __NS_ARP_H

#include <net/ethernet.h>
#include <pcap.h>

/**
 * Use ARP packets to get MAC mappings for a certain IP address.
 *
 * @param sip       The IP address to lookup in the local ARP table.
 * @param dip       The IP address to lookup in the ARP table.
 * @param saddr     The ether_addr structure representing who the sender is.
 * @param daddr     The ether_addr structure to hold the return value.
 * @param ifname  The name of the interface to grab things on.
 *
 * @return 0 on success, -1 on failure.
 */
int arp_get_mac(struct in_addr *sip, struct in_addr *dip,
                struct ether_addr *saddr, struct ether_addr *daddr,
                const char *ifname);

/**
 * parse_arp()
 *
 * Parse an ARP packet and handle it.
 *
 * @param pkt     The byte content of packet.
 * @param hdr     The pcap header containing metadata.
 * @param handle  The pcap handle for error checking.
 *
 * @return 0 on success, -1 on failure.
 */
int parse_arp(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle);

#endif /* ns_arp_h */
