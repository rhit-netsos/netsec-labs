#ifndef __NS_ARP_H
#define __NS_ARP_H

#include <pcap.h>

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
