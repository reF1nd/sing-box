// Copyright 2026, Asterisk4Magisk contributors
// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_SHARED_NETWORK_H
#define SING_BOX_EBPF_SHARED_NETWORK_H

#include <linux/types.h>

#define SB_SHARED_NETWORK_OBJECT_MAP_ENTRIES 65536U
#define SB_SHARED_SOURCE_CIDR_MAP_ENTRIES 4096U
#define SB_SHARED_SOURCE_MAC_MAP_ENTRIES 1024U
#define SB_SHARED_TOKEN_ATTEMPTS 8U
#define SB_SHARED_NETWORK_SCRATCH_SIZE 192U
#define SB_SHARED_ACTIVITY_UPDATE_INTERVAL_NS 1000000000ULL
#define SB_SHARED_STAT_TOKEN_RESERVATION_FAILURE 0U
#define SB_SHARED_STAT_COUNT 1U

#define SB_SHARED_FLAG_IPV4 (1U << 0)
#define SB_SHARED_DNS_MODE_HIJACK 0U
#define SB_SHARED_DNS_MODE_RESPECT_POLICY 1U
#define SB_SHARED_DNS_MODE_OFF 2U

#define SB_SHARED_FLAG_IPV6 (1U << 1)
#define SB_SHARED_FLAG_TCP (1U << 2)
#define SB_SHARED_FLAG_UDP (1U << 3)
#define SB_SHARED_FLAG_HOST_IPV4 (1U << 5)
#define SB_SHARED_FLAG_HOST_IPV6 (1U << 6)
#define SB_SHARED_FLAG_BYPASS_IPV4 (1U << 7)
#define SB_SHARED_FLAG_BYPASS_IPV6 (1U << 8)
#define SB_SHARED_FLAG_INCLUDE_SOURCE (1U << 9)
#define SB_SHARED_FLAG_EXCLUDE_SOURCE (1U << 10)
#define SB_SHARED_FLAG_INCLUDE_SOURCE_MAC (1U << 11)
#define SB_SHARED_FLAG_EXCLUDE_SOURCE_MAC (1U << 12)
#define SB_SHARED_FLAG_BYPASS_PRIVATE_ADDRESS (1U << 13)
#define SB_SHARED_FLAG_BYPASS_FLOW_CACHE (1U << 14)
#define SB_SHARED_FLAG_FAKEIP_IPV4 (1U << 16)
#define SB_SHARED_FLAG_FAKEIP_IPV6 (1U << 17)

struct sb_shared_control {
    __u32 enabled;
    __u32 flags;
    __u16 listener_port;
    __u16 dns_mode;
    __u8 token_ipv4_prefix[4];
    __u8 token_ipv4_prefix_bits;
    __u8 token_ipv6_prefix_bits;
    __u8 reserved2[2];
    __u8 token_ipv6_prefix[16];
    __u32 udp_timeout_seconds;
    __u8 fakeip_ipv4_prefix[4];
    __u8 fakeip_ipv4_mask[4];
    __u8 fakeip_ipv6_prefix[16];
    __u8 fakeip_ipv6_mask[16];
};

struct sb_shared_original_key {
    __u32 ifindex;
    __u8 family;
    __u8 protocol;
    __u16 client_port;
    __u16 original_port;
    __u16 reserved;
    __u8 client_addr[16];
    __u8 original_addr[16];
};

struct sb_shared_token_value {
    __u8 token_addr[16];
    __u64 generation;
    __u64 last_seen_ns;
    __u64 reserved;
};

struct sb_shared_mac_key {
    __u8 address[6];
    __u8 reserved[2];
};

struct sb_shared_listener_key {
    __u8 family;
    __u8 protocol;
    __u16 listener_port;
    __u8 token_addr[16];
    __u16 client_port;
    __u16 reserved;
    __u8 client_addr[16];
};

struct sb_shared_original_value {
    __u8 family;
    __u8 protocol;
    __u16 port;
    __u8 addr[16];
    __u32 ifindex;
    __u64 generation;
    __u8 source_mac[6];
    __u8 reserved2[2];
};

struct sb_shared_bypass_flow_value {
    __u64 last_seen_ns;
    __u32 tcp_sequence;
    __u32 reserved;
};

struct sb_shared_scratch {
    struct sb_shared_original_key original;
    struct sb_shared_token_value token;
    struct sb_shared_listener_key listener_key;
    struct sb_shared_original_value original_value;
    struct sb_shared_bypass_flow_value bypass_flow;
    struct sb_shared_mac_key source_mac;
};

_Static_assert(sizeof(struct sb_shared_control) == 80U, "shared control ABI");
_Static_assert(sizeof(struct sb_shared_original_key) == 44U, "shared original key ABI");
_Static_assert(sizeof(struct sb_shared_listener_key) == 40U, "shared listener key ABI");
_Static_assert(sizeof(struct sb_shared_original_value) == 40U, "shared original value ABI");
_Static_assert(sizeof(struct sb_shared_token_value) == 40U, "shared token value ABI");
_Static_assert(__builtin_offsetof(struct sb_shared_scratch, original_value) == 128U, "shared original value offset ABI");
_Static_assert(sizeof(struct sb_shared_scratch) == SB_SHARED_NETWORK_SCRATCH_SIZE, "shared-network scratch ABI");

#endif
