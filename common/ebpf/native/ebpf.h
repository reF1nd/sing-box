// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef SING_BOX_EBPF_H
#define SING_BOX_EBPF_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SB_EBPF_DEFAULT_CGROUP_PATH "/sys/fs/cgroup"
#define SB_EBPF_MAX_POLICY_MAP_ENTRIES 4096U
#define SB_EBPF_MAX_BYPASS_CIDR_MAP_ENTRIES 65536U
#define SB_EBPF_MAX_CONFIGURABLE_MAP_ENTRIES 1048576U
#define SB_EBPF_ORIGINAL_DST_FLAG_CONNECTED_UDP 1U

#define SB_EBPF_PROTO_TCP 6U
#define SB_EBPF_PROTO_UDP 17U
#define SB_EBPF_NETWORK_TCP 1U
#define SB_EBPF_NETWORK_UDP 2U
#define SB_EBPF_NETWORK_BOTH (SB_EBPF_NETWORK_TCP | SB_EBPF_NETWORK_UDP)

struct sb_ebpf_listener_key {
    uint8_t family;
    uint8_t protocol;
    uint16_t listener_port;
    uint8_t token_addr[16];
};

struct sb_ebpf_original_dst {
    uint8_t family;
    uint8_t protocol;
    uint16_t port;
    uint8_t addr[16];
    uint8_t flags;
    uint8_t reserved[3];
    uint64_t socket_cookie;
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

struct sb_ebpf_udp_flow_key {
    uint64_t cookie;
    uint8_t family;
    uint8_t protocol;
    uint16_t port;
    uint8_t addr[16];
    uint8_t reserved[4];
};

_Static_assert(sizeof(struct sb_ebpf_listener_key) == 20U, "unexpected redirect key ABI");
_Static_assert(sizeof(struct sb_ebpf_original_dst) == 32U, "unexpected original destination ABI");
_Static_assert(offsetof(struct sb_ebpf_original_dst, socket_cookie) == 24U, "unexpected socket cookie ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_peer_key) == 8U, "unexpected UDP peer key ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_peer_value) == 20U, "unexpected UDP peer value ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_flow_key) == 32U, "unexpected UDP flow key ABI");

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

struct sb_ebpf_cgroup_config {
    uint8_t inbound_network;
    bool disable_ipv4;
    bool hijack_dns;
    uint8_t redirect_ipv4_prefix[4];
    uint32_t redirect_ipv4_prefix_bits;
    uint8_t redirect_ipv6_prefix[16];
    uint32_t redirect_ipv6_prefix_bits;
};

struct sb_ebpf_cgroup_runtime {
    int cgroup_fd;
    int tcp_redirect_map_fd;
    int udp_redirect_map_fd;
    int udp_token_map_fd;
    int udp_peer_map_fd;
    int udp_flow_map_fd;
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
    bool socket_release_supported;
    bool self_bypass_tgid;
    uint32_t attached_programs;
};

struct sb_ebpf_shared_network_runtime {
    int control_map_fd;
    int original_to_token_map_fd;
    int bypass_flow_map_fd;
    int reply_map_fd;
    int listener_map_fd;
    int host_ipv4_map_fd;
    int host_ipv6_map_fd;
    int fallback_bypass_ipv4_map_fd;
    int fallback_bypass_ipv6_map_fd;
    int scratch_map_fd;
    int ingress_prog_fd;
    int egress_prog_fd;
};

int sb_ebpf_cgroup_prepare(
    const char *cgroup_path,
    bool enable_tcp,
    bool enable_udp,
    bool enable_bypass_ipv4_cidr,
    bool enable_bypass_ipv6_cidr,
    uint32_t include_uid_entries,
    uint32_t exclude_uid_entries,
    uint32_t tcp_redirect_map_capacity,
    uint32_t udp_redirect_map_capacity,
    uint32_t socket_bypass_map_capacity,
    struct sb_ebpf_cgroup_runtime *runtime);
int sb_ebpf_cgroup_load_programs(
    struct sb_ebpf_cgroup_runtime *runtime,
    uint16_t listen_port,
    uint32_t self_tgid,
    bool enable_ipv4,
    bool hijack_dns,
    const uint8_t redirect_ipv4[4],
    uint32_t redirect_ipv4_prefix_bits,
    bool enable_ipv6,
    const uint8_t redirect_ipv6[16],
    uint32_t redirect_ipv6_prefix_bits);
int sb_ebpf_cgroup_attach(struct sb_ebpf_cgroup_runtime *runtime);
int sb_ebpf_cgroup_close(struct sb_ebpf_cgroup_runtime *runtime);

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
    uint32_t map_capacity,
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
