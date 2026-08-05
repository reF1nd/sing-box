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
#define SB_EBPF_ERROR_STAGE_SIZE 64U
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
#define SB_EBPF_CGROUP_FLAG_INCLUDE_UID (1U << 5U)
#define SB_EBPF_CGROUP_FLAG_EXCLUDE_UID (1U << 6U)
#define SB_EBPF_CGROUP_FLAG_BYPASS_IPV4 (1U << 7U)
#define SB_EBPF_CGROUP_FLAG_BYPASS_IPV6 (1U << 8U)
#define SB_EBPF_CGROUP_FLAG_AUTO_IPV6 (1U << 9U)
#define SB_EBPF_CGROUP_FLAG_UDP_FLOW (1U << 10U)

struct sb_ebpf_cgroup_control {
    uint32_t flags;
    uint32_t self_tgid;
    uint32_t udp_timeout_seconds;
    uint32_t redirect_ipv4_prefix;
    uint32_t redirect_ipv4_host_mask;
    uint16_t listener_port;
    uint16_t reserved;
    uint8_t redirect_ipv6_prefix[8];
};

_Static_assert(sizeof(struct sb_ebpf_cgroup_control) == 32U, "unexpected cgroup control ABI");

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

struct sb_ebpf_udp_flow_value {
    uint8_t action;
    uint8_t reserved[3];
    uint32_t last_seen_seconds;
    struct sb_ebpf_listener_key listener;
    uint8_t reserved2[4];
};

_Static_assert(sizeof(struct sb_ebpf_listener_key) == 20U, "unexpected redirect key ABI");
_Static_assert(sizeof(struct sb_ebpf_original_dst) == 32U, "unexpected original destination ABI");
_Static_assert(offsetof(struct sb_ebpf_original_dst, socket_cookie) == 24U, "unexpected socket cookie ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_peer_key) == 8U, "unexpected UDP peer key ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_peer_value) == 20U, "unexpected UDP peer value ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_flow_key) == 32U, "unexpected UDP flow key ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_flow_value) == 32U, "unexpected UDP flow value ABI");

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

struct sb_ebpf_map_spec {
    const char *name;
    enum bpf_map_type type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t flags;
    int *fd;
};

struct sb_ebpf_program_descriptor {
    const char *name;
    enum bpf_prog_type type;
    enum bpf_attach_type attach_type;
    int *fd;
};

typedef int (*sb_ebpf_map_fd_resolver)(const char *name, void *context);

struct sb_ebpf_cgroup_runtime {
    char error_stage[SB_EBPF_ERROR_STAGE_SIZE];
    int cgroup_fd;
    int control_map_fd;
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
    int ipv6_available_map_fd;
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
    bool enable_tcp;
    bool enable_udp;
    bool include_uid_policy;
    bool exclude_uid_policy;
    bool bypass_ipv4_policy;
    bool bypass_ipv6_policy;
    bool auto_ipv6;
    uint32_t socket_bypass_map_capacity;
    uint32_t attached_programs;
};

struct sb_ebpf_shared_network_runtime {
    char error_stage[SB_EBPF_ERROR_STAGE_SIZE];
    int control_map_fd;
    int original_to_token_map_fd;
    int bypass_flow_map_fd;
    int reply_map_fd;
    int listener_map_fd;
    int host_ipv4_map_fd;
    int host_ipv6_map_fd;
    int include_source_ipv4_map_fd;
    int include_source_ipv6_map_fd;
    int exclude_source_ipv4_map_fd;
    int exclude_source_ipv6_map_fd;
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
    bool auto_ipv6,
    uint32_t include_uid_entries,
    uint32_t exclude_uid_entries,
    uint32_t tcp_redirect_map_capacity,
    uint32_t udp_redirect_map_capacity,
    uint32_t socket_bypass_map_capacity,
    struct sb_ebpf_cgroup_runtime *runtime);
int sb_ebpf_cgroup_load_programs(
    struct sb_ebpf_cgroup_runtime *runtime,
    const uint8_t *object,
    size_t object_size,
    uint16_t listen_port,
    uint32_t self_tgid,
    bool enable_ipv4,
    bool hijack_dns,
    uint32_t udp_timeout_seconds,
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
int sb_ebpf_load_object_program(
    const uint8_t *object,
    size_t object_size,
    const char *section_name,
    const struct sb_ebpf_program_descriptor *program,
    sb_ebpf_map_fd_resolver resolve_map,
    void *resolve_context,
    bool log_error);
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
int sb_ebpf_update_map(
    int map_fd,
    const void *key,
    const void *value,
    uint64_t flags);
bool sb_ebpf_map_capacity_valid(uint32_t capacity);
int sb_ebpf_create_maps(
    const struct sb_ebpf_map_spec *specs,
    size_t spec_count,
    const char **failed_name);
int sb_ebpf_close_fd(int *fd);
int sb_ebpf_close_fds(int **fds, size_t fd_count);
void sb_ebpf_set_error_stage(char *destination, const char *stage);
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
