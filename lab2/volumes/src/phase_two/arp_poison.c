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

#include <linux/tcp.h>

#include "log.h"
#include "util.h"

static char *my_mac_addr;

// TODO: Replace this with the IPv4 address of hostB
static const char *victim = "10.10.0.5";
// TODO: Replace this with the IPv4 address of hostA
static const char *target = "10.10.0.4";

#define NUM_REPLIES 5

void send_arp_replies(pcap_t *handle, int num_req) {
  // TODO:
  // ====
  //  Add code here to craft and send num_req ARP requests.
  //
  //  You should build two headers, an Ethernet header and an ARP header and
  //  set their approriate fields.
  //
  struct ether_header *eth;   // the Ethernet header to fill in.
  struct ether_arp *arp;      // the ARP header to fill in.
  struct ether_addr *eth_addr;  // use this to hold Ethernet addresses
  struct in_addr vic_addr;      // use this for ipv4 addresses
  u_char *pkt;                // the packet to create.
  int i = 0;

  // allocate the packet, no need to keep reallocing since we're sending the
  // same thing over and over again.
  pkt = malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
  if(!pkt) {
    print_err("PANIC: Failed to malloc room for the packet!\n");
    exit(99);
  }

  for(; i < num_req; i++) {
    eth = (struct ether_header *)pkt;
    arp = (struct ether_arp *) (pkt + sizeof *eth);

    // 1. Set up the source mac address.
    eth_addr = ether_aton(my_mac_addr);
    memcpy(eth->ether_shost, eth_addr->ether_addr_octet,
           sizeof eth->ether_shost);

    // 2. TODO: Set up the destination mac address

    // 3. TODO: Set up ethernet type

    // 4. TODO: Set up the ARP packet

    // 5. Set up source and destination ARP fields
    //    I have done the source hardware address for you.
    //    Use it to set the target hardware address in the packet.
    eth_addr = ether_aton(my_mac_addr);
    memcpy(arp->arp_sha, eth_addr->ether_addr_octet, sizeof(struct ether_addr));

    // TODO: Set target hardware in the ARP packet


    // 6. Set source and destination ip addresses
    //    I have done the source protocol address for you.
    //    Use it to set up the target protocol address.
    inet_aton(victim, &vic_addr);
    memcpy(arp->arp_spa, &vic_addr.s_addr, 4);

    // TODO: Set target protocol address in the ARP packet

    // 7. Send the packet
    int rc = pcap_inject(
        handle, pkt, sizeof(struct ether_header) + sizeof(struct ether_arp));
    if(rc == PCAP_ERROR_NOT_ACTIVATED) {
      print_err("Pcap was not actived!\n");
      exit(EXIT_FAILURE);
    } else if (rc == PCAP_ERROR) {
      print_err("Pcap error: %s\n", pcap_geterr(handle));
      exit(EXIT_FAILURE);
    }
  }

  free(pkt);
  print_log("Done sending packets...\n");
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

  if(argc < 4) {
    print_err("Missing arguments!\n\n");
    fprintf(stderr, "\t Usage: %s <mac addr> <victim ip> <target ip>\n\n", argv[0]);
    exit(99);
  }
  my_mac_addr = argv[1];
  victim = argv[2];
  target = argv[3];

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

  // send the requests
  send_arp_replies(handle, NUM_REPLIES);

  exit(EXIT_SUCCESS);
done_on_err:
  pcap_freealldevs(alldevp);
  exit(EXIT_FAILURE);
}

