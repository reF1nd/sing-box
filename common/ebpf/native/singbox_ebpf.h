// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef SING_BOX_EBPF_H
#define SING_BOX_EBPF_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SB_EBPF_DEFAULT_CGROUP_PATH "/sys/fs/cgroup"
#define SB_EBPF_MAX_TCP_REDIRECT_MAP_ENTRIES 65536U
#define SB_EBPF_MAX_UDP_REDIRECT_MAP_ENTRIES 65536U
#define SB_EBPF_MAX_UDP_PEER_MAP_ENTRIES 65536U
#define SB_EBPF_MAX_POLICY_MAP_ENTRIES 4096U
#define SB_EBPF_MAX_BYPASS_CIDR_MAP_ENTRIES 65536U
#define SB_EBPF_STATS_COUNT 6U
#define SB_EBPF_ORIGINAL_DST_FLAG_CONNECTED_UDP 1U

#define SB_EBPF_PROTO_TCP 6U
#define SB_EBPF_PROTO_UDP 17U
#define SB_EBPF_NETWORK_TCP 1U
#define SB_EBPF_NETWORK_UDP 2U
#define SB_EBPF_NETWORK_BOTH (SB_EBPF_NETWORK_TCP | SB_EBPF_NETWORK_UDP)

enum sb_ebpf_stat_index {
    SB_EBPF_STAT_TCP_REDIRECT_ENTRIES = 0,
    SB_EBPF_STAT_UDP_REDIRECT_ENTRIES = 1,
    SB_EBPF_STAT_UDP_REDIRECT_DELETES = 2,
    SB_EBPF_STAT_TOKEN_COLLISIONS = 3,
    SB_EBPF_STAT_MAP_UPDATE_FAILURES = 4,
    SB_EBPF_STAT_REDIRECT_DROPS = 5,
};

struct sb_ebpf_redirect_key {
    uint8_t family;
    uint8_t protocol;
    uint16_t redirect_port;
    uint8_t redirect_addr[16];
};

struct sb_ebpf_original_dst {
    uint8_t family;
    uint8_t protocol;
    uint16_t port;
    uint8_t addr[16];
    uint8_t flags;
    uint8_t reserved[3];
    uint64_t socket_cookie;
    uint32_t uid;
    uint32_t reserved_tail;
};

struct sb_ebpf_udp_peer_key {
    uint64_t cookie;
};

struct sb_ebpf_udp_peer_value {
    uint8_t family;
    uint8_t protocol;
    uint16_t port;
    uint8_t addr[16];
};

_Static_assert(sizeof(struct sb_ebpf_redirect_key) == 20U, "unexpected redirect key ABI");
_Static_assert(sizeof(struct sb_ebpf_original_dst) == 40U, "unexpected original destination ABI");
_Static_assert(offsetof(struct sb_ebpf_original_dst, socket_cookie) == 24U, "unexpected socket cookie ABI");
_Static_assert(offsetof(struct sb_ebpf_original_dst, uid) == 32U, "unexpected UID ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_peer_key) == 8U, "unexpected UDP peer key ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_peer_value) == 20U, "unexpected UDP peer value ABI");

struct sb_ebpf_uid_lpm_key {
    uint32_t prefixlen;
    uint8_t uid[4];
};

struct sb_ebpf_ipv4_cidr_lpm_key {
    uint32_t prefixlen;
    uint8_t addr[4];
};

struct sb_ebpf_ipv6_cidr_lpm_key {
    uint32_t prefixlen;
    uint8_t addr[16];
};

struct sb_ebpf_inbound_config {
    uint8_t inbound_network;
    bool disable_ipv4;
    bool hijack_dns;
    int stats_map_fd;
    uint8_t redirect_ipv4_prefix[4];
    uint32_t redirect_ipv4_prefix_bits;
    uint8_t redirect_ipv6_prefix[16];
    uint32_t redirect_ipv6_prefix_bits;
};

struct sb_ebpf_inbound_runtime {
    int cgroup_fd;
    int tcp_redirect_map_fd;
    int udp_redirect_map_fd;
    int udp_token_map_fd;
    int stats_map_fd;
    int udp_peer_map_fd;
    int bypass_socket_cookie_map_fd;
    int include_uid_map_fd;
    int exclude_uid_map_fd;
    int bypass_ipv4_cidr_map_fd;
    int bypass_ipv6_cidr_map_fd;
    int connect4_prog_fd;
    int connect6_prog_fd;
    int connect6_v4mapped_prog_fd;
    int udp4_sendmsg_prog_fd;
    int udp6_sendmsg_prog_fd;
    int udp6_v4mapped_sendmsg_prog_fd;
    int udp4_recvmsg_prog_fd;
    int udp6_recvmsg_prog_fd;
    int udp6_v4mapped_recvmsg_prog_fd;
    int socket_release_prog_fd;
    uint32_t attached_programs;
};

struct sb_ebpf_shared_network_runtime {
    int control_map_fd;
    int original_to_token_map_fd;
    int token_to_original_map_fd;
    int redirect_map_fd;
    int host_ipv4_map_fd;
    int host_ipv6_map_fd;
    int fallback_bypass_ipv4_map_fd;
    int fallback_bypass_ipv6_map_fd;
    int scratch_map_fd;
    int ingress_prog_fd;
    int egress_prog_fd;
};

int sb_ebpf_inbound_prepare(
    const char *cgroup_path,
    uint16_t listen_port,
    bool enable_tcp,
    bool enable_udp,
    bool enable_ipv4,
    bool enable_bypass_cidr,
    bool hijack_dns,
    const uint8_t redirect_ipv4[4],
    uint32_t redirect_ipv4_prefix_bits,
    bool enable_ipv6,
    const uint8_t redirect_ipv6[16],
    uint32_t redirect_ipv6_prefix_bits,
    uint32_t include_uid_entries,
    uint32_t exclude_uid_entries,
    struct sb_ebpf_inbound_runtime *runtime);
int sb_ebpf_inbound_attach(struct sb_ebpf_inbound_runtime *runtime);
int sb_ebpf_inbound_close(struct sb_ebpf_inbound_runtime *runtime);

int sb_ebpf_load_shared_network_programs(
    const uint8_t *object,
    size_t object_size,
    int bypass_ipv4_map_fd,
    int bypass_ipv6_map_fd,
    struct sb_ebpf_shared_network_runtime *runtime);
int sb_ebpf_shared_network_prepare(
    const uint8_t *object,
    size_t object_size,
    int bypass_ipv4_map_fd,
    int bypass_ipv6_map_fd,
    struct sb_ebpf_shared_network_runtime *runtime);
int sb_ebpf_shared_network_close(struct sb_ebpf_shared_network_runtime *runtime);

int sb_ebpf_create_map(
    enum bpf_map_type type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t flags);
int sb_ebpf_load_prog(
    const struct bpf_insn *insns,
    size_t insn_count,
    const char *name,
    enum bpf_prog_type prog_type,
    enum bpf_attach_type expected_attach_type,
    bool log_error);
int sb_ebpf_attach_prog(int cgroup_fd, int prog_fd, enum bpf_attach_type attach_type);
int sb_ebpf_detach_prog(int cgroup_fd, int prog_fd, enum bpf_attach_type attach_type);
int sb_ebpf_detach_owned_progs(int cgroup_fd);

#endif
