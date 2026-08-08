// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef SING_BOX_EBPF_RUNTIME_H
#define SING_BOX_EBPF_RUNTIME_H

#include "abi.h"

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SB_EBPF_DEFAULT_CGROUP_PATH "/sys/fs/cgroup"
#define SB_EBPF_MAX_POLICY_MAP_ENTRIES 4096U
#define SB_EBPF_MAX_BYPASS_CIDR_MAP_ENTRIES 65536U
#define SB_EBPF_MAX_CONFIGURABLE_MAP_ENTRIES 1048576U
#define SB_EBPF_ERROR_STAGE_SIZE 64U
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

enum sb_ebpf_cgroup_program_slot {
    SB_EBPF_CGROUP_PROGRAM_CONNECT4,
    SB_EBPF_CGROUP_PROGRAM_UDP4_SENDMSG,
    SB_EBPF_CGROUP_PROGRAM_UDP4_RECVMSG,
    SB_EBPF_CGROUP_PROGRAM_CONNECT6,
    SB_EBPF_CGROUP_PROGRAM_UDP6_SENDMSG,
    SB_EBPF_CGROUP_PROGRAM_UDP6_RECVMSG,
    SB_EBPF_CGROUP_PROGRAM_SOCKET_RELEASE,
    SB_EBPF_CGROUP_PROGRAM_COUNT,
};

typedef int (*sb_ebpf_map_fd_resolver)(const char *name, void *context);

struct sb_ebpf_map_binding {
    const char *name;
    size_t fd_offset;
};

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
    int uid_policy_map_fd;
    int bypass_ipv4_cidr_map_fd;
    int bypass_ipv6_cidr_map_fd;
    int ipv6_available_map_fd;
    int program_fds[SB_EBPF_CGROUP_PROGRAM_COUNT];
    bool socket_release_supported;
    bool self_bypass_tgid;
    bool enable_tcp;
    bool enable_udp;
    bool uid_policy;
    bool uid_default_bypass;
    bool exclude_android_dns_tether;
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
    int fragment_map_fd;
    int host_ipv4_map_fd;
    int host_ipv6_map_fd;
    int include_source_ipv4_map_fd;
    int include_source_ipv6_map_fd;
    int exclude_source_ipv4_map_fd;
    int exclude_source_ipv6_map_fd;
    int include_source_mac_map_fd;
    int exclude_source_mac_map_fd;
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
    uint32_t uid_policy_entries,
    bool uid_default_bypass,
    bool exclude_android_dns_tether,
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
int sb_ebpf_cgroup_probe_self_tgid(
    struct sb_ebpf_cgroup_runtime *runtime,
    uint32_t *self_tgid);

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
int sb_ebpf_resolve_map_fd(
    const char *name,
    const void *runtime,
    const struct sb_ebpf_map_binding *bindings,
    size_t binding_count);
int sb_ebpf_shared_network_prepare(
    const uint8_t *object,
    size_t object_size,
    int bypass_ipv4_map_fd,
    int bypass_ipv6_map_fd,
    uint32_t proxy_capacity,
    uint32_t bypass_capacity,
    uint32_t fragment_capacity,
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
int sb_ebpf_lookup_map(int map_fd, const void *key, void *value);
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
