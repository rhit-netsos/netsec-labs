#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

#include <pcap.h>

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "log.h"
#include "util.h"

int hijack_tcp_connection(pcap_t *handle, const u_char *pkt,
                          unsigned pktlen, struct iphdr *iphdr,
                          struct tcphdr *tcphdr, const char *cmd) {
  u_char *retpkt;
  unsigned retpkt_len;
  uint16_t tcp_hdr_len = tcphdr->doff * 4;
  uint32_t seqnum = ntohl(tcphdr->seq);
  uint32_t acknum = ntohl(tcphdr->ack);
  uint32_t data_len = ntohs(iphdr->tot_len) - sizeof(struct iphdr) - tcp_hdr_len;
  uint32_t inject_len = 0;
  char *data;
  int rc;

  // calculate new packet length
  retpkt_len = sizeof(struct ether_header) + sizeof(struct iphdr);
  // for TCP grab the header length with the options
  retpkt_len += tcp_hdr_len;

  // TODO:
  // =====
  // Add room in the packet for your command and some other stuff you would
  // need to send to make this attack work.
  //
  // You will need to write something like:
  inject_len = 0; /* replace the zero here with your own length */
  retpkt_len += inject_len;

  // alloc new packet and copy old one into it.
  retpkt = malloc(retpkt_len);
  if(!retpkt) {
    print_err("malloc failure: something bad is really happening!\n");
    exit(EXIT_FAILURE);
  }

  // copy the original packet to get the ethernet, ip, and tcp header in place
  // before starting to mess with them.
  memcpy(retpkt, pkt, pktlen);

  // now start messing with the new packet, so adjust the header to point to
  // the new thing
  iphdr = (struct iphdr*)(retpkt + sizeof(struct ether_header));
  tcphdr = (struct tcphdr*)(retpkt + sizeof(struct ether_header) + sizeof(struct iphdr));

  // TODO:
  // =====
  //
  // Decide on the next sequence number and the next ack number to send back to
  // the server once the code has been triggered. Make sure to examine the
  // packets closely so you can craft these numbers correctly. TCP is highly
  // sensitive to these values, so not having them correct will definitely
  // cause your exploit to break.
  //
  tcphdr->seq = 0; /* replace this zero value here */
  tcphdr->ack = 0; /* replace this zero value here */

  // grab the data pointer
  data = (char*)tcphdr + tcp_hdr_len;

  // TODO:
  // =====
  //
  // Write the packet for the TCP data, you simply need to put the command here
  // along with some prefix or suffix, depending on how you think the attack
  // should go.
  //

  // adjust the total length
  iphdr->tot_len = htons(sizeof(struct iphdr) + tcp_hdr_len + inject_len);

  // compute checksum
  iphdr->check = 0;
  iphdr->check = chksum((uint16_t*)iphdr, sizeof(struct iphdr));
  tcphdr->check = compute_tcp_checksum(tcphdr, iphdr);

  print_log("Sending hijacked packet with command: %s\n", data);
  rc = pcap_inject(handle, retpkt, retpkt_len);
  if(rc == PCAP_ERROR_NOT_ACTIVATED) {
    print_err("pcap was not activated!\n");
    rc = -1;
    goto done;
  } else if(rc == PCAP_ERROR) {
    print_err("pcap error: %s\n", pcap_geterr(handle));
    rc = -1;
    goto done;
  }

done:
  free(retpkt);
  return (rc == -1)? rc : 0;
}

int is_triggered(struct iphdr *iphdr, struct tcphdr *tcphdr) {
  // TODO:
  // =====
  //
  // Implement your own trigger function here, it doesn't have to be
  // complicated, mine simply waited for the user to type in the "ls" command
  // and then it triggered the hijacking.
  //
  // Hint: Use the code we used in lab 2 to read the data in the packet, if any
  //

  return 0;
}


