// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_SHARED_NETWORK_PACKET_H
#define SING_BOX_EBPF_SHARED_NETWORK_PACKET_H

#include "bpf_compat.h"

#define ETH_P_IP_VALUE 0x0800U
#define ETH_P_IPV6_VALUE 0x86ddU
#define ETH_P_8021Q_VALUE 0x8100U
#define ETH_P_8021AD_VALUE 0x88a8U
#define IPPROTO_TCP_VALUE 6U
#define IPPROTO_UDP_VALUE 17U
#define AF_INET_VALUE 2U
#define AF_INET6_VALUE 10U
#define IPV4_FRAGMENT_OFFSET_MASK 0x1fffU
#define IPV4_FRAGMENT_MORE 0x2000U
#define IPV6_FRAGMENT_OFFSET_MASK 0xfff8U
#define IPV6_FRAGMENT_MORE 0x0001U
#define TCP_FLAG_SYN 0x0002U
#define TCP_FLAG_ACK 0x0010U

/* Bound old-verifier offsets for Ethernet, two VLAN tags, IPv6, and three extension headers. */
#define IPV6_TRANSPORT_MIN_OFFSET 54U
#define IPV6_TRANSPORT_MAX_OFFSET 6206U
#define IPV6_TRANSPORT_MASK 0x1fffU
#define IPV6_TRANSPORT_BYPASS 0xffffffffU
#define IPV6_TRANSPORT_DROP 0xfffffffeU

struct sb_lpm4_key {
    __u32 prefixlen;
    __u8 addr[4];
};

struct sb_lpm6_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct ethernet_header {
    __u8 destination[6];
    __u8 source[6];
    __be16 protocol;
};

struct vlan_header {
    __be16 tci;
    __be16 protocol;
};

struct ipv4_header {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl : 4;
    __u8 version : 4;
#else
    __u8 version : 4;
    __u8 ihl : 4;
#endif
    __u8 tos;
    __be16 total_length;
    __be16 id;
    __be16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __sum16 checksum;
    __be32 source;
    __be32 destination;
};

struct ipv6_header {
    __be32 version_flow;
    __be16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 source[16];
    __u8 destination[16];
};

struct ipv6_extension_header {
    __u8 next_header;
    __u8 length;
};

struct ipv6_fragment_header {
    __u8 next_header;
    __u8 reserved;
    __be16 fragment_offset;
    __be32 identification;
};

struct transport_ports {
    __be16 source;
    __be16 destination;
};

struct tcp_header_min {
    __be16 source;
    __be16 destination;
    __be32 sequence;
    __be32 acknowledgement;
    __be16 flags;
    __be16 window;
    __sum16 checksum;
    __be16 urgent_pointer;
};

struct udp_header_min {
    __be16 source;
    __be16 destination;
    __be16 length;
    __sum16 checksum;
};

#endif
