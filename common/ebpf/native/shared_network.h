// Copyright 2026, Asterisk4Magisk contributors
// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_SHARED_NETWORK_H
#define SING_BOX_EBPF_SHARED_NETWORK_H

#include <linux/types.h>

#define SB_SHARED_NETWORK_MAP_ENTRIES 65536U
#define SB_SHARED_TOKEN_ATTEMPTS 8U
#define SB_SHARED_NETWORK_SCRATCH_SIZE 256U

#define SB_SHARED_FLAG_IPV4 (1U << 0)
#define SB_SHARED_FLAG_IPV6 (1U << 1)
#define SB_SHARED_FLAG_TCP (1U << 2)
#define SB_SHARED_FLAG_UDP (1U << 3)
#define SB_SHARED_FLAG_DNS_HIJACK (1U << 4)

struct sb_shared_control {
    __u32 enabled;
    __u32 flags;
    __u16 bridge_port;
    __u16 reserved;
    __u8 token_ipv4_prefix[4];
    __u8 token_ipv4_prefix_bits;
    __u8 token_ipv6_prefix_bits;
    __u8 reserved2[2];
    __u8 token_ipv6_prefix[16];
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

struct sb_shared_reverse_key {
    __u32 ifindex;
    __u8 family;
    __u8 protocol;
    __u16 client_port;
    __u16 token_port;
    __u16 reserved;
    __u8 client_addr[16];
    __u8 token_addr[16];
};

struct sb_shared_reverse_value {
    __u16 original_port;
    __u16 reserved;
    __u8 original_addr[16];
};

struct sb_shared_redirect_key {
    __u8 family;
    __u8 protocol;
    __u16 redirect_port;
    __u8 redirect_addr[16];
    __u16 client_port;
    __u16 reserved;
    __u8 client_addr[16];
};

struct sb_shared_original_dst {
    __u8 family;
    __u8 protocol;
    __u16 port;
    __u8 addr[16];
    __u8 flags;
    __u8 reserved[3];
    __u64 socket_cookie;
};

struct sb_shared_scratch {
    struct sb_shared_original_key original;
    struct sb_shared_token_value token;
    struct sb_shared_reverse_key reverse_key;
    struct sb_shared_reverse_value reverse_value;
    struct sb_shared_redirect_key redirect_key;
    __u8 redirect_value_padding[4];
    struct sb_shared_original_dst redirect_value;
    __u8 padding[56];
};

_Static_assert(sizeof(struct sb_shared_control) == 36U, "shared control ABI");
_Static_assert(sizeof(struct sb_shared_original_key) == 44U, "shared original key ABI");
_Static_assert(sizeof(struct sb_shared_reverse_key) == 44U, "shared reverse key ABI");
_Static_assert(sizeof(struct sb_shared_redirect_key) == 40U, "shared redirect key ABI");
_Static_assert(sizeof(struct sb_shared_original_dst) == 32U, "shared original destination ABI");
_Static_assert(__builtin_offsetof(struct sb_shared_scratch, redirect_value) == 168U, "shared redirect value offset ABI");
_Static_assert(sizeof(struct sb_shared_scratch) == SB_SHARED_NETWORK_SCRATCH_SIZE, "shared-network scratch ABI");

#endif
