// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "singbox_ebpf.h"
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

static int shared_network_create_lpm4(void) {
    return sb_ebpf_create_map(
        BPF_MAP_TYPE_LPM_TRIE,
        sizeof(struct sb_ebpf_ipv4_cidr_lpm_key),
        sizeof(uint8_t),
        256U,
        BPF_F_NO_PREALLOC);
}

static int shared_network_create_lpm6(void) {
    return sb_ebpf_create_map(
        BPF_MAP_TYPE_LPM_TRIE,
        sizeof(struct sb_ebpf_ipv6_cidr_lpm_key),
        sizeof(uint8_t),
        256U,
        BPF_F_NO_PREALLOC);
}

int sb_ebpf_shared_network_prepare(
    const uint8_t *object,
    size_t object_size,
    int bypass_ipv4_map_fd,
    int bypass_ipv6_map_fd,
    struct sb_ebpf_shared_network_runtime *runtime) {
    if (object == NULL || object_size == 0U || runtime == NULL) {
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
        BPF_MAP_TYPE_LRU_HASH,
        sizeof(struct sb_shared_original_key),
        sizeof(struct sb_shared_token_value),
        SB_SHARED_NETWORK_MAP_ENTRIES,
        0U);
    stage = "create token-to-original map";
    runtime->token_to_original_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_LRU_HASH,
        sizeof(struct sb_shared_reverse_key),
        sizeof(struct sb_shared_reverse_value),
        SB_SHARED_NETWORK_MAP_ENTRIES,
        0U);
    stage = "create redirect map";
    runtime->redirect_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_LRU_HASH,
        sizeof(struct sb_shared_redirect_key),
        sizeof(struct sb_shared_original_dst),
        SB_SHARED_NETWORK_MAP_ENTRIES,
        0U);
    stage = "create host maps";
    runtime->host_ipv4_map_fd = shared_network_create_lpm4();
    runtime->host_ipv6_map_fd = shared_network_create_lpm6();
    stage = "create scratch map";
    runtime->scratch_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_PERCPU_ARRAY,
        sizeof(uint32_t),
        sizeof(struct sb_shared_scratch),
        1U,
        0U);
    if (runtime->control_map_fd < 0 ||
        runtime->original_to_token_map_fd < 0 ||
        runtime->token_to_original_map_fd < 0 ||
        runtime->redirect_map_fd < 0 ||
        runtime->host_ipv4_map_fd < 0 ||
        runtime->host_ipv6_map_fd < 0 ||
        runtime->scratch_map_fd < 0) {
        goto fail;
    }
    if (bypass_ipv4_map_fd < 0) {
        stage = "create fallback IPv4 bypass map";
        runtime->fallback_bypass_ipv4_map_fd = shared_network_create_lpm4();
        if (runtime->fallback_bypass_ipv4_map_fd < 0) goto fail;
        bypass_ipv4_map_fd = runtime->fallback_bypass_ipv4_map_fd;
    }
    if (bypass_ipv6_map_fd < 0) {
        stage = "create fallback IPv6 bypass map";
        runtime->fallback_bypass_ipv6_map_fd = shared_network_create_lpm6();
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
    CLOSE_SHARED_FD(runtime->redirect_map_fd);
    CLOSE_SHARED_FD(runtime->token_to_original_map_fd);
    CLOSE_SHARED_FD(runtime->original_to_token_map_fd);
    CLOSE_SHARED_FD(runtime->control_map_fd);
#undef CLOSE_SHARED_FD
    return result;
}
