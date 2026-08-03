// Copyright 2026, Asterisk4Magisk contributors
// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_SHARED_NETWORK_H
#define SING_BOX_EBPF_SHARED_NETWORK_H

#include <linux/types.h>

#define SB_SHARED_NETWORK_OBJECT_MAP_ENTRIES 65536U
#define SB_SHARED_TOKEN_ATTEMPTS 8U
#define SB_SHARED_NETWORK_SCRATCH_SIZE 256U

#define SB_SHARED_FLAG_IPV4 (1U << 0)
#define SB_SHARED_FLAG_IPV6 (1U << 1)
#define SB_SHARED_FLAG_TCP (1U << 2)
#define SB_SHARED_FLAG_UDP (1U << 3)
#define SB_SHARED_FLAG_DNS_HIJACK (1U << 4)
#define SB_SHARED_FLAG_HOST_IPV4 (1U << 5)
#define SB_SHARED_FLAG_HOST_IPV6 (1U << 6)
#define SB_SHARED_FLAG_BYPASS_IPV4 (1U << 7)
#define SB_SHARED_FLAG_BYPASS_IPV6 (1U << 8)

struct sb_shared_control {
    __u32 enabled;
    __u32 flags;
    __u16 listener_port;
    __u16 reserved;
    __u8 token_ipv4_prefix[4];
    __u8 token_ipv4_prefix_bits;
    __u8 token_ipv6_prefix_bits;
    __u8 reserved2[2];
    __u8 token_ipv6_prefix[16];
    __u32 udp_timeout_seconds;
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
};

struct sb_shared_reply_key {
    __u32 ifindex;
    __u8 family;
    __u8 protocol;
    __u16 client_port;
    __u16 listener_port;
    __u16 reserved;
    __u8 client_addr[16];
    __u8 token_addr[16];
};

struct sb_shared_reply_value {
    __u16 original_port;
    __u16 reserved;
    __u8 original_addr[16];
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
    __u32 reserved;
};

struct sb_shared_bypass_flow_value {
    __u64 last_seen_ns;
    __u32 tcp_sequence;
    __u32 reserved;
};

struct sb_shared_scratch {
    struct sb_shared_original_key original;
    struct sb_shared_token_value token;
    struct sb_shared_reply_key reply_key;
    struct sb_shared_reply_value reply_value;
    struct sb_shared_listener_key listener_key;
    struct sb_shared_original_value original_value;
    struct sb_shared_bypass_flow_value bypass_flow;
    __u8 padding[48];
};

_Static_assert(sizeof(struct sb_shared_control) == 40U, "shared control ABI");
_Static_assert(sizeof(struct sb_shared_original_key) == 44U, "shared original key ABI");
_Static_assert(sizeof(struct sb_shared_reply_key) == 44U, "shared reply key ABI");
_Static_assert(sizeof(struct sb_shared_listener_key) == 40U, "shared listener key ABI");
_Static_assert(sizeof(struct sb_shared_original_value) == 28U, "shared original value ABI");
_Static_assert(__builtin_offsetof(struct sb_shared_scratch, original_value) == 164U, "shared original value offset ABI");
_Static_assert(sizeof(struct sb_shared_scratch) == SB_SHARED_NETWORK_SCRATCH_SIZE, "shared-network scratch ABI");

#endif
