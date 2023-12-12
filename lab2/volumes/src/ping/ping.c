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

static const char *filter_expr;
static char *my_mac_addr;

extern void parse_ip(const u_char *, const char *, pcap_t *, unsigned);

// build the filter expression for this part of the lab
static char *build_filter_expr(pcap_if_t *pdev) {
  static char ebuf[PCAP_BUF_SIZE];
  struct pcap_addr *addr;
  struct sockaddr_in *sock_addr;
  const char *ipaddr;

  // find IP address of interface
  // assuming there's only one address for now, and it exists.
  addr = pdev->addresses;
  // find the IP address that has AF_INET
  for(; addr; addr = addr->next) {
    sock_addr = (struct sockaddr_in *)addr->addr;
    if(sock_addr->sin_family == AF_INET)
      break;
  }

  if(!addr) {
    print_err("PANIC: Failed to find a valid IPv4 address for %s\n", pdev->name);
    exit(99);
  }

  ipaddr = inet_ntoa(sock_addr->sin_addr);
  snprintf(ebuf, PCAP_BUF_SIZE,
           "icmp and (not ip src %s) and (not ether src %s)",
           ipaddr, my_mac_addr);

  return ebuf;
}

int main(int argc, char **argv) {
  pcap_if_t *alldevp;
  char errbuf[PCAP_ERRBUF_SIZE];
  int rc;
  pcap_t *handle;
  struct pcap_pkthdr *hdr;
  const u_char *pkt;
  int timeout_limit = 1; /* in milliseconds */
  struct ether_header *eth_hdr;
  struct bpf_program filter;

  if(argc < 2) {
    fprintf(stderr, "[ERROR]: No mac address provided!\n");
    fprintf(stderr, "\t Usage: %s <mac addr>\n\n", argv[0]);
    exit(99);
  }
  my_mac_addr = argv[1];

  rc = pcap_findalldevs(&alldevp, errbuf);
  if(rc) {
    fprintf(stderr, "%s (%d): Error finding suitable device: %s\n", argv[0],
        getpid(), errbuf);
    exit(EXIT_FAILURE);
  }

  // for now, assuming eth0 is the default and there's nothing else.
  print_log("%s (%d): Found device: %s\n", argv[0], getpid(), alldevp->name);

  handle = pcap_open_live(alldevp->name, BUFSIZ, 1, timeout_limit, errbuf);
  if(!handle) {
    fprintf(stderr, "%s (%d): Error opening pcap_live on device %s: %s\n",
        alldevp->name, errbuf);
    goto done_on_err;
  }

  // build the filter expression
  filter_expr = build_filter_expr(alldevp);

  // done with alldevp, free it
  pcap_freealldevs(alldevp);

  // compile the filter
  if(pcap_compile(handle, &filter, filter_expr, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    print_err("Bad filter - %s\n", pcap_geterr(handle));
    exit(99);
  }

  // set the filter
  if(pcap_setfilter(handle, &filter) == -1) {
    fprintf(stderr, "Error setting filter - %s\n", pcap_geterr(handle));
    exit(99);
  }

  // print log to verify things are working.
  print_log("Running %s with filter %s\n", argv[0]+2, filter_expr);

  // loop over packets until we are done
  while((rc = pcap_next_ex(handle, &hdr, &pkt)) >= 0) {
    eth_hdr = (struct ether_header*)pkt;
    if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
      parse_ip(pkt, my_mac_addr, handle, hdr->len);
    } else {
      print_err("Got an unknow packet, what to do?\n");
    }
  }

  exit(EXIT_SUCCESS);
done_on_err:
  pcap_freealldevs(alldevp);
  exit(EXIT_FAILURE);
}

