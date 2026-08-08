// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef SING_BOX_EBPF_ABI_H
#define SING_BOX_EBPF_ABI_H

#include <linux/types.h>

#define SB_EBPF_ORIGINAL_DST_FLAG_CONNECTED_UDP 1U

#define SB_EBPF_PROTO_TCP 6U
#define SB_EBPF_PROTO_UDP 17U
#define SB_EBPF_UDP_FLOW_ACTION_PROXY 1U
#define SB_EBPF_UDP_FLOW_ACTION_BYPASS 2U

#define SB_EBPF_CGROUP_FLAG_TCP (1U << 0U)
#define SB_EBPF_CGROUP_FLAG_UDP (1U << 1U)
#define SB_EBPF_CGROUP_FLAG_IPV4 (1U << 2U)
#define SB_EBPF_CGROUP_FLAG_IPV6 (1U << 3U)
#define SB_EBPF_CGROUP_FLAG_HIJACK_DNS (1U << 4U)
#define SB_EBPF_CGROUP_FLAG_UID_POLICY (1U << 5U)
#define SB_EBPF_CGROUP_FLAG_UID_DEFAULT_BYPASS (1U << 6U)
#define SB_EBPF_CGROUP_FLAG_BYPASS_IPV4 (1U << 7U)
#define SB_EBPF_CGROUP_FLAG_BYPASS_IPV6 (1U << 8U)
#define SB_EBPF_CGROUP_FLAG_AUTO_IPV6 (1U << 9U)
#define SB_EBPF_CGROUP_FLAG_UDP_FLOW (1U << 10U)
#define SB_EBPF_CGROUP_FLAG_EXCLUDE_ANDROID_DNS_TETHER (1U << 11U)

#define SB_EBPF_ANDROID_DNS_TETHER_UID 1052U

struct sb_ebpf_cgroup_control {
    __u32 flags;
    __u32 self_tgid;
    __u32 udp_timeout_seconds;
    __u32 redirect_ipv4_prefix;
    __u32 redirect_ipv4_host_mask;
    __u16 listener_port;
    __u16 reserved;
    __u8 redirect_ipv6_prefix[8];
};

_Static_assert(sizeof(struct sb_ebpf_cgroup_control) == 32U, "unexpected cgroup control ABI");

struct sb_ebpf_listener_key {
    __u8 family;
    __u8 protocol;
    __u16 listener_port;
    __u8 token_addr[16];
};

struct sb_ebpf_original_dst {
    __u8 family;
    __u8 protocol;
    __u16 port;
    __u8 addr[16];
    __u8 flags;
    __u8 reserved[3];
    __u64 socket_cookie;
};

struct sb_ebpf_udp_peer_key {
    __u64 cookie;
};

struct sb_ebpf_udp_peer_value {
    __u8 family;
    __u8 protocol;
    __u16 port;
    __u8 addr[16];
};

struct sb_ebpf_udp_flow_key {
    __u64 cookie;
    __u8 family;
    __u8 protocol;
    __u16 port;
    __u8 addr[16];
    __u8 reserved[4];
};

struct sb_ebpf_udp_flow_value {
    __u8 action;
    __u8 reserved[3];
    __u32 last_seen_seconds;
    struct sb_ebpf_listener_key listener;
    __u8 reserved2[4];
};

_Static_assert(sizeof(struct sb_ebpf_listener_key) == 20U, "unexpected redirect key ABI");
_Static_assert(sizeof(struct sb_ebpf_original_dst) == 32U, "unexpected original destination ABI");
_Static_assert(__builtin_offsetof(struct sb_ebpf_original_dst, socket_cookie) == 24U, "unexpected socket cookie ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_peer_key) == 8U, "unexpected UDP peer key ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_peer_value) == 20U, "unexpected UDP peer value ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_flow_key) == 32U, "unexpected UDP flow key ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_flow_value) == 32U, "unexpected UDP flow value ABI");

struct sb_ebpf_uid_lpm_key {
    __u32 prefixlen;
    __u8 uid[4];
};

struct sb_ebpf_ipv4_cidr_lpm_key {
    __u32 prefixlen;
    __u8 addr[4];
};

struct sb_ebpf_ipv6_cidr_lpm_key {
    __u32 prefixlen;
    __u8 addr[16];
};

#endif
