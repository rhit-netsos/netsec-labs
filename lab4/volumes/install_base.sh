#!/bin/bash

apt update

apt install -y iproute2 \
  net-tools \
  iputils-* \
  traceroute \
  tcpdump \
  nmap \
  iptables python3 \
  python3-pip \
  vim \
  gdb \
  dnsutils netcat-openbsd \
  telnetd \
  libpcap-dev \
  psutils  \
  telnet

pip install scapy

