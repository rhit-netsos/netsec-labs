#include <string.h>
#include <time.h>
#include <stdio.h>

#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "util.h"

char *fmt_ts(struct timeval *ts) {
  static char fmtstr[NS_UTIL_BUFSIZE];
  char *str = fmtstr;
  struct tm *ltime;
  time_t local_tv_sec;

  local_tv_sec = ts->tv_sec;
  ltime = localtime(&local_tv_sec);
  str += strftime(fmtstr, sizeof fmtstr, "%H:%M:%S", ltime);

  snprintf(str, NS_UTIL_BUFSIZE - strlen(fmtstr), ".%.6d", ts->tv_usec);
  return fmtstr;
}

char *mac_to_str(void *addr) {
  // Adapted from https://stackoverflow.com/a/4738943
  static char buf[18];
  struct ether_addr *eth_addr = (struct ether_addr*)addr;

  sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
      eth_addr->ether_addr_octet[0], eth_addr->ether_addr_octet[1],
      eth_addr->ether_addr_octet[2], eth_addr->ether_addr_octet[3],
      eth_addr->ether_addr_octet[4], eth_addr->ether_addr_octet[5]);
  return buf;
}

char *ip_to_str(void *addr) {
  struct in_addr *iaddr = (struct in_addr*)addr;
  return inet_ntoa(*iaddr);
}

// checksum computation.
uint16_t chksum(uint16_t *hdr, uint32_t len) {
  unsigned long cksum=0;
  while(len >1) {
    cksum+=*hdr++;
    len -= sizeof(uint16_t);
  }

  if(len) {
    cksum += *(u_char*)hdr;
  }

  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >>16);
  return (uint16_t)(~cksum);
}

struct pseudo_tcp_hdr {
  uint32_t saddr;
  uint32_t daddr;
  uint8_t zero;
  uint8_t ptcl;
  uint16_t tcp_len;
};

uint16_t compute_tcp_checksum(struct tcphdr *tcp, struct iphdr *ip) {
  unsigned long cksum = 0;
  uint16_t tcplen = ntohs(ip->tot_len) - (ip->ihl * 4);
  struct pseudo_tcp_hdr pseudohdr;
  uint16_t *hdr;
  uint32_t len;

  // make sure this is zero.
  tcp->check = 0;

  // fill up the pseudo header
  pseudohdr.saddr = ip->saddr;
  pseudohdr.daddr = ip->daddr;
  pseudohdr.zero = 0;
  pseudohdr.ptcl = ip->protocol;
  pseudohdr.tcp_len = htons(tcplen);

  // start over the pseudoheader
  len = sizeof pseudohdr;
  hdr = (uint16_t *)(&pseudohdr);
  while(len > 1) {
    cksum += *hdr++;
    len -= sizeof(uint16_t);
  }

  // pseudo header is always 96 bits or 24 bytes, which means len is 0 now.
  len = tcplen;
  hdr = (uint16_t *)tcp;
  while(len > 1) {
    cksum += *hdr++;
    len -= sizeof(uint16_t);
  }

  if(len)
    cksum += *(u_char *)hdr;

  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >> 16);

  return (uint16_t)~cksum;
}
