// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf.h"
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
}

static int shared_network_close_fd(int *fd) {
    if (fd == NULL || *fd < 0) return 0;
    int value = *fd;
    *fd = -1;
    return close(value);
}

static int shared_network_create_lpm4(uint32_t max_entries) {
    return sb_ebpf_create_map(
        BPF_MAP_TYPE_LPM_TRIE,
        sizeof(struct sb_ebpf_ipv4_cidr_lpm_key),
        sizeof(uint8_t),
        max_entries,
        BPF_F_NO_PREALLOC);
}

static int shared_network_create_lpm6(uint32_t max_entries) {
    return sb_ebpf_create_map(
        BPF_MAP_TYPE_LPM_TRIE,
        sizeof(struct sb_ebpf_ipv6_cidr_lpm_key),
        sizeof(uint8_t),
        max_entries,
        BPF_F_NO_PREALLOC);
}

int sb_ebpf_shared_network_prepare(
    const uint8_t *object,
    size_t object_size,
    int bypass_ipv4_map_fd,
    int bypass_ipv6_map_fd,
    uint32_t map_capacity,
    struct sb_ebpf_shared_network_runtime *runtime) {
    if (object == NULL || object_size == 0U || runtime == NULL ||
        map_capacity == 0U || map_capacity > SB_EBPF_MAX_CONFIGURABLE_MAP_ENTRIES) {
        errno = EINVAL;
        return -1;
    }
    shared_network_init(runtime);
    const char *stage = "create control map";
    runtime->control_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_ARRAY,
        sizeof(uint32_t),
        sizeof(struct sb_shared_control),
        1U,
        0U);
    stage = "create original-to-token map";
    runtime->original_to_token_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_HASH,
        sizeof(struct sb_shared_original_key),
        sizeof(struct sb_shared_token_value),
        map_capacity,
        0U);
    stage = "create bypass flow map";
    runtime->bypass_flow_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_LRU_HASH,
        sizeof(struct sb_shared_original_key),
        sizeof(struct sb_shared_bypass_flow_value),
        map_capacity,
        0U);
    stage = "create reply lookup map";
    runtime->reply_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_HASH,
        sizeof(struct sb_shared_reply_key),
        sizeof(struct sb_shared_reply_value),
        map_capacity,
        0U);
    stage = "create listener lookup map";
    runtime->listener_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_HASH,
        sizeof(struct sb_shared_listener_key),
        sizeof(struct sb_shared_original_value),
        map_capacity,
        0U);
    stage = "create host maps";
    runtime->host_ipv4_map_fd = shared_network_create_lpm4(256U);
    runtime->host_ipv6_map_fd = shared_network_create_lpm6(256U);
    stage = "create scratch map";
    runtime->scratch_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_PERCPU_ARRAY,
        sizeof(uint32_t),
        sizeof(struct sb_shared_scratch),
        1U,
        0U);
    if (runtime->control_map_fd < 0 ||
        runtime->original_to_token_map_fd < 0 ||
        runtime->bypass_flow_map_fd < 0 ||
        runtime->reply_map_fd < 0 ||
        runtime->listener_map_fd < 0 ||
        runtime->host_ipv4_map_fd < 0 ||
        runtime->host_ipv6_map_fd < 0 ||
        runtime->scratch_map_fd < 0) {
        goto fail;
    }
    if (bypass_ipv4_map_fd < 0) {
        stage = "create fallback IPv4 bypass map";
        runtime->fallback_bypass_ipv4_map_fd = shared_network_create_lpm4(
            SB_EBPF_MAX_BYPASS_CIDR_MAP_ENTRIES);
        if (runtime->fallback_bypass_ipv4_map_fd < 0) goto fail;
        bypass_ipv4_map_fd = runtime->fallback_bypass_ipv4_map_fd;
    }
    if (bypass_ipv6_map_fd < 0) {
        stage = "create fallback IPv6 bypass map";
        runtime->fallback_bypass_ipv6_map_fd = shared_network_create_lpm6(
            SB_EBPF_MAX_BYPASS_CIDR_MAP_ENTRIES);
        if (runtime->fallback_bypass_ipv6_map_fd < 0) goto fail;
        bypass_ipv6_map_fd = runtime->fallback_bypass_ipv6_map_fd;
    }
    stage = "load shared-network programs";
    if (sb_ebpf_load_shared_network_programs(
            object,
            object_size,
            bypass_ipv4_map_fd,
            bypass_ipv6_map_fd,
            runtime) != 0) {
        goto fail;
    }
    return 0;

fail: {
        int saved_errno = errno;
        fprintf(stderr, "shared-network stage '%s' failed: errno=%d\n", stage, saved_errno);
        (void)sb_ebpf_shared_network_close(runtime);
        errno = saved_errno;
        return -1;
    }
}

int sb_ebpf_shared_network_close(struct sb_ebpf_shared_network_runtime *runtime) {
    if (runtime == NULL) return 0;
    int result = 0;
#define CLOSE_SHARED_FD(FD) \
    do { \
        if (shared_network_close_fd(&(FD)) != 0 && result == 0) result = -1; \
    } while (0)
    CLOSE_SHARED_FD(runtime->egress_prog_fd);
    CLOSE_SHARED_FD(runtime->ingress_prog_fd);
    CLOSE_SHARED_FD(runtime->scratch_map_fd);
    CLOSE_SHARED_FD(runtime->fallback_bypass_ipv6_map_fd);
    CLOSE_SHARED_FD(runtime->fallback_bypass_ipv4_map_fd);
    CLOSE_SHARED_FD(runtime->host_ipv6_map_fd);
    CLOSE_SHARED_FD(runtime->host_ipv4_map_fd);
    CLOSE_SHARED_FD(runtime->listener_map_fd);
    CLOSE_SHARED_FD(runtime->reply_map_fd);
    CLOSE_SHARED_FD(runtime->bypass_flow_map_fd);
    CLOSE_SHARED_FD(runtime->original_to_token_map_fd);
    CLOSE_SHARED_FD(runtime->control_map_fd);
#undef CLOSE_SHARED_FD
    return result;
}
