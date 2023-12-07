#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <pcap.h>

#include "log.h"
#include "util.h"

// Set the filter to capture only ARP or ICMP packets
static const char *filter_expr = "arp or icmp";

int main(int argc, char **argv) {
  pcap_if_t *alldev_p;           // pcap interfaces pointer
  char errbuf[PCAP_ERRBUF_SIZE]; // error buffer
  pcap_t *handle;                // the main pcap handle
  const char *ifname = "eth0";   // default interface name
  int rc;                        // return code.
  pcap_if_t *p;                  // temporary ptr for iteration
  struct bpf_program filter;     // BPF filter based on expression above
  struct pcap_pkthdr *hdr;       // the pcap header for each captured packet
  const u_char *pkt;             // the actual packet bytes (including headers)
  char *tstr;                    // a string to hold the timestamp

  // check if user provided a filter expression (note, it must be with quotes)
  if(argc > 1)
    filter_expr = argv[1];
  else
    print_warn("Using default filter expression: %s\n", filter_expr);

  print_log("Starting setup...\n");

  // need to find the device we're looking for.
  rc = pcap_findalldevs(&alldev_p, errbuf);
  if(rc) {
    print_err("Could not find any suitable interface: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  for(p = alldev_p; p && strcmp(p->name, ifname); p = p->next);
  if(!p) {
    print_err("Could not find interface with name %s\n", ifname);
    exit(EXIT_FAILURE);
  }

  print_log("Starting %s on interface %s\n", argv[0]+2, p->name);
  handle = pcap_open_live(p->name,        /* name of the device */
      BUFSIZ,                             /* portion of the packet to capture */
      PCAP_OPENFLAG_PROMISCUOUS,          /* promiscuous mode */
      1,                                  /* timeout limit in ms */
      errbuf                              /* error buffer */);
  if(!handle) {
    print_err("Unable to open the adapter on iface %s: %s\n", ifname, errbuf);
    pcap_freealldevs(alldev_p);
    exit(EXIT_FAILURE);
  }

  // no need for dev list anymore, free it
  pcap_freealldevs(alldev_p);

  // compile the filter
  if(pcap_compile(handle, &filter, filter_expr, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    print_err("Bad filter expression - %s: %s\n",
        filter_expr, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  // set the filter
  if(pcap_setfilter(handle, &filter) == -1) {
    print_err("Error setting the filter - %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  print_log("Setup done successfully, listening for packets...\n");

  // MAIN LOOP: keep getting packets until error happens or we are done.
  while((rc = pcap_next_ex(handle, &hdr, &pkt)) >= 0) {
    // Eventually, remove this for speed
    tstr = fmt_ts(&hdr->ts);
    print_log("(%s)\t Got a packet of len %d\n", tstr, hdr->len);
  }

  if(rc == -1) {
    print_err("Error capturing packets: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  return 0;
}

