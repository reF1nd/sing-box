// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "runtime.h"
#include "shared_network.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1U
#endif

static void shared_network_init(struct sb_ebpf_shared_network_runtime *runtime) {
    memset(runtime, 0xff, sizeof(*runtime));
    runtime->error_stage[0] = '\0';
}

int sb_ebpf_shared_network_prepare(
    const uint8_t *object,
    size_t object_size,
    int bypass_ipv4_map_fd,
    int bypass_ipv6_map_fd,
    uint32_t proxy_capacity,
    uint32_t bypass_capacity,
    uint32_t fragment_capacity,
    struct sb_ebpf_shared_network_runtime *runtime) {
    if (object == NULL || object_size == 0U || runtime == NULL ||
        !sb_ebpf_map_capacity_valid(proxy_capacity) ||
        !sb_ebpf_map_capacity_valid(bypass_capacity) ||
        !sb_ebpf_map_capacity_valid(fragment_capacity)) {
        errno = EINVAL;
        return -1;
    }
    shared_network_init(runtime);
    const struct sb_ebpf_map_spec maps[] = {
        {"control", BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(struct sb_shared_control),
         1U, 0U, &runtime->control_map_fd},
        {"original-to-token", BPF_MAP_TYPE_HASH, sizeof(struct sb_shared_original_key),
         sizeof(struct sb_shared_token_value), proxy_capacity, 0U, &runtime->original_to_token_map_fd},
        {"bypass flow", BPF_MAP_TYPE_LRU_HASH, sizeof(struct sb_shared_original_key),
         sizeof(struct sb_shared_bypass_flow_value), bypass_capacity, 0U, &runtime->bypass_flow_map_fd},
        {"reply lookup", BPF_MAP_TYPE_HASH, sizeof(struct sb_shared_reply_key),
         sizeof(struct sb_shared_reply_value), proxy_capacity, 0U, &runtime->reply_map_fd},
        {"listener lookup", BPF_MAP_TYPE_HASH, sizeof(struct sb_shared_listener_key),
         sizeof(struct sb_shared_original_value), proxy_capacity, 0U, &runtime->listener_map_fd},
        {"fragment flow", BPF_MAP_TYPE_LRU_HASH, sizeof(struct sb_shared_fragment_key),
         sizeof(struct sb_shared_fragment_value), fragment_capacity, 0U, &runtime->fragment_map_fd},
        {"host IPv4", BPF_MAP_TYPE_LPM_TRIE, sizeof(struct sb_ebpf_ipv4_cidr_lpm_key),
         sizeof(uint8_t), 256U, BPF_F_NO_PREALLOC, &runtime->host_ipv4_map_fd},
        {"host IPv6", BPF_MAP_TYPE_LPM_TRIE, sizeof(struct sb_ebpf_ipv6_cidr_lpm_key),
         sizeof(uint8_t), 256U, BPF_F_NO_PREALLOC, &runtime->host_ipv6_map_fd},
        {"include source IPv4", BPF_MAP_TYPE_LPM_TRIE, sizeof(struct sb_ebpf_ipv4_cidr_lpm_key),
         sizeof(uint8_t), SB_SHARED_SOURCE_CIDR_MAP_ENTRIES, BPF_F_NO_PREALLOC,
         &runtime->include_source_ipv4_map_fd},
        {"include source IPv6", BPF_MAP_TYPE_LPM_TRIE, sizeof(struct sb_ebpf_ipv6_cidr_lpm_key),
         sizeof(uint8_t), SB_SHARED_SOURCE_CIDR_MAP_ENTRIES, BPF_F_NO_PREALLOC,
         &runtime->include_source_ipv6_map_fd},
        {"exclude source IPv4", BPF_MAP_TYPE_LPM_TRIE, sizeof(struct sb_ebpf_ipv4_cidr_lpm_key),
         sizeof(uint8_t), SB_SHARED_SOURCE_CIDR_MAP_ENTRIES, BPF_F_NO_PREALLOC,
         &runtime->exclude_source_ipv4_map_fd},
        {"exclude source IPv6", BPF_MAP_TYPE_LPM_TRIE, sizeof(struct sb_ebpf_ipv6_cidr_lpm_key),
         sizeof(uint8_t), SB_SHARED_SOURCE_CIDR_MAP_ENTRIES, BPF_F_NO_PREALLOC,
         &runtime->exclude_source_ipv6_map_fd},
        {"include source MAC", BPF_MAP_TYPE_HASH, sizeof(struct sb_shared_mac_key),
         sizeof(uint8_t), SB_SHARED_SOURCE_MAC_MAP_ENTRIES, 0U,
         &runtime->include_source_mac_map_fd},
        {"exclude source MAC", BPF_MAP_TYPE_HASH, sizeof(struct sb_shared_mac_key),
         sizeof(uint8_t), SB_SHARED_SOURCE_MAC_MAP_ENTRIES, 0U,
         &runtime->exclude_source_mac_map_fd},
        {"scratch", BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(uint32_t), sizeof(struct sb_shared_scratch),
         1U, 0U, &runtime->scratch_map_fd},
        {"fallback IPv4 bypass", BPF_MAP_TYPE_LPM_TRIE, sizeof(struct sb_ebpf_ipv4_cidr_lpm_key),
         sizeof(uint8_t), bypass_ipv4_map_fd < 0 ? SB_EBPF_MAX_BYPASS_CIDR_MAP_ENTRIES : 0U,
         BPF_F_NO_PREALLOC, &runtime->fallback_bypass_ipv4_map_fd},
        {"fallback IPv6 bypass", BPF_MAP_TYPE_LPM_TRIE, sizeof(struct sb_ebpf_ipv6_cidr_lpm_key),
         sizeof(uint8_t), bypass_ipv6_map_fd < 0 ? SB_EBPF_MAX_BYPASS_CIDR_MAP_ENTRIES : 0U,
         BPF_F_NO_PREALLOC, &runtime->fallback_bypass_ipv6_map_fd},
    };
    const char *failed_map = NULL;
    if (sb_ebpf_create_maps(maps, sizeof(maps) / sizeof(maps[0]), &failed_map) != 0) {
        sb_ebpf_set_error_stage(runtime->error_stage, failed_map);
        goto fail;
    }
    if (bypass_ipv4_map_fd < 0) bypass_ipv4_map_fd = runtime->fallback_bypass_ipv4_map_fd;
    if (bypass_ipv6_map_fd < 0) bypass_ipv6_map_fd = runtime->fallback_bypass_ipv6_map_fd;
    sb_ebpf_set_error_stage(runtime->error_stage, "load shared-network programs");
    if (sb_ebpf_load_shared_network_programs(
            object,
            object_size,
            bypass_ipv4_map_fd,
            bypass_ipv6_map_fd,
            runtime) != 0) {
        goto fail;
    }
    sb_ebpf_set_error_stage(runtime->error_stage, NULL);
    return 0;

fail: {
        int saved_errno = errno;
        (void)sb_ebpf_shared_network_close(runtime);
        errno = saved_errno;
        return -1;
    }
}

int sb_ebpf_shared_network_close(struct sb_ebpf_shared_network_runtime *runtime) {
    if (runtime == NULL) return 0;
    int *runtime_fds[] = {
        &runtime->egress_prog_fd,
        &runtime->ingress_prog_fd,
        &runtime->scratch_map_fd,
        &runtime->fallback_bypass_ipv6_map_fd,
        &runtime->fallback_bypass_ipv4_map_fd,
        &runtime->exclude_source_ipv6_map_fd,
        &runtime->exclude_source_ipv4_map_fd,
        &runtime->exclude_source_mac_map_fd,
        &runtime->include_source_mac_map_fd,
        &runtime->include_source_ipv6_map_fd,
        &runtime->include_source_ipv4_map_fd,
        &runtime->host_ipv6_map_fd,
        &runtime->host_ipv4_map_fd,
        &runtime->listener_map_fd,
        &runtime->fragment_map_fd,
        &runtime->reply_map_fd,
        &runtime->bypass_flow_map_fd,
        &runtime->original_to_token_map_fd,
        &runtime->control_map_fd,
    };
    return sb_ebpf_close_fds(runtime_fds, sizeof(runtime_fds) / sizeof(runtime_fds[0]));
}
