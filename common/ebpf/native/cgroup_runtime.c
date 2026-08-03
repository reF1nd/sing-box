// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Included by cgroup.c to keep the native cgroup backend in one translation unit.

static int create_redirect_map(uint32_t max_entries, bool use_lru) {
    return sb_ebpf_create_map(
        (enum bpf_map_type)(use_lru ? SB_EBPF_LRU_HASH_MAP_TYPE : SB_EBPF_HASH_MAP_TYPE),
        sizeof(struct sb_ebpf_listener_key),
        sizeof(struct sb_ebpf_original_dst),
        max_entries,
        0U);
}

static int create_udp_peer_map(uint32_t max_entries) {
    return sb_ebpf_create_map(
        (enum bpf_map_type)SB_EBPF_LRU_HASH_MAP_TYPE,
        sizeof(struct sb_ebpf_udp_peer_key),
        sizeof(struct sb_ebpf_udp_peer_value),
        max_entries,
        0U);
}

static int create_udp_token_map(uint32_t max_entries, bool use_lru) {
    return sb_ebpf_create_map(
        (enum bpf_map_type)(use_lru ? SB_EBPF_LRU_HASH_MAP_TYPE : SB_EBPF_HASH_MAP_TYPE),
        sizeof(uint64_t),
        sizeof(struct sb_ebpf_listener_key),
        max_entries,
        0U);
}

static int create_udp_flow_map(uint32_t max_entries) {
    return sb_ebpf_create_map(
        (enum bpf_map_type)SB_EBPF_LRU_HASH_MAP_TYPE,
        sizeof(struct sb_ebpf_udp_flow_key),
        sizeof(struct sb_ebpf_listener_key),
        max_entries,
        0U);
}

static int create_bypass_socket_cookie_map(uint32_t max_entries) {
    return sb_ebpf_create_map(
        (enum bpf_map_type)SB_EBPF_LRU_HASH_MAP_TYPE,
        sizeof(uint64_t),
        sizeof(uint8_t),
        max_entries,
        0U);
}

static int create_uid_policy_map(uint32_t max_entries) {
    if (max_entries == 0U) return -1;
    return sb_ebpf_create_map(
        (enum bpf_map_type)SB_EBPF_LPM_TRIE_MAP_TYPE,
        sizeof(struct sb_ebpf_uid_lpm_key),
        sizeof(uint8_t),
        max_entries,
        BPF_F_NO_PREALLOC);
}

static int create_bypass_cidr_map(bool enabled, uint32_t key_size) {
    if (!enabled) return -1;
    return sb_ebpf_create_map(
        (enum bpf_map_type)SB_EBPF_LPM_TRIE_MAP_TYPE,
        key_size,
        sizeof(uint8_t),
        SB_EBPF_MAX_BYPASS_CIDR_MAP_ENTRIES,
        BPF_F_NO_PREALLOC);
}

static int open_cgroup_path(const char *path) {
    const char *actual = path != NULL && path[0] != '\0' ? path : SB_EBPF_DEFAULT_CGROUP_PATH;
    return open(actual, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

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
	struct sb_ebpf_cgroup_runtime *runtime) {
    if (runtime == NULL || (!enable_tcp && !enable_udp) ||
        include_uid_entries > SB_EBPF_MAX_POLICY_MAP_ENTRIES ||
        exclude_uid_entries > SB_EBPF_MAX_POLICY_MAP_ENTRIES ||
        tcp_redirect_map_capacity == 0U ||
        tcp_redirect_map_capacity > SB_EBPF_MAX_CONFIGURABLE_MAP_ENTRIES ||
        udp_redirect_map_capacity == 0U ||
        udp_redirect_map_capacity > SB_EBPF_MAX_CONFIGURABLE_MAP_ENTRIES ||
        socket_bypass_map_capacity == 0U ||
        socket_bypass_map_capacity > SB_EBPF_MAX_CONFIGURABLE_MAP_ENTRIES) {
        errno = EINVAL;
        return -1;
    }

    init_runtime(runtime);
    int socket_release_support = enable_udp ? probe_socket_release_support() : 0;
    if (socket_release_support < 0) {
        goto prepare_fail;
    }
    runtime->socket_release_supported = socket_release_support > 0;
    bool use_udp_lru_fallback = enable_udp && !runtime->socket_release_supported;
    runtime->tcp_redirect_map_fd = enable_tcp
        ? create_redirect_map(tcp_redirect_map_capacity, false)
        : -1;
    runtime->udp_redirect_map_fd = enable_udp
        ? create_redirect_map(udp_redirect_map_capacity, use_udp_lru_fallback)
        : -1;
    runtime->udp_token_map_fd = enable_udp
        ? create_udp_token_map(udp_redirect_map_capacity, use_udp_lru_fallback)
        : -1;
    runtime->udp_peer_map_fd = enable_udp
        ? create_udp_peer_map(udp_redirect_map_capacity)
        : -1;
    /* This cache is an optimization. Keep the original path on older kernels. */
    runtime->udp_flow_map_fd = enable_udp && runtime->socket_release_supported
        ? create_udp_flow_map(udp_redirect_map_capacity)
        : -1;
    runtime->bypass_socket_cookie_map_fd = create_bypass_socket_cookie_map(
        socket_bypass_map_capacity);
    runtime->include_uid_map_fd = create_uid_policy_map(include_uid_entries);
    runtime->exclude_uid_map_fd = create_uid_policy_map(exclude_uid_entries);
    runtime->bypass_ipv4_cidr_map_fd = create_bypass_cidr_map(
        enable_bypass_ipv4_cidr, sizeof(struct sb_ebpf_ipv4_cidr_lpm_key));
    runtime->bypass_ipv6_cidr_map_fd = create_bypass_cidr_map(
        enable_bypass_ipv6_cidr, sizeof(struct sb_ebpf_ipv6_cidr_lpm_key));
    if ((enable_tcp && runtime->tcp_redirect_map_fd < 0) ||
        (enable_udp && runtime->udp_redirect_map_fd < 0) ||
        (enable_udp && (runtime->udp_token_map_fd < 0 || runtime->udp_peer_map_fd < 0)) ||
        runtime->bypass_socket_cookie_map_fd < 0 ||
        (include_uid_entries > 0U && runtime->include_uid_map_fd < 0) ||
        (exclude_uid_entries > 0U && runtime->exclude_uid_map_fd < 0) ||
        (enable_bypass_ipv4_cidr && runtime->bypass_ipv4_cidr_map_fd < 0) ||
        (enable_bypass_ipv6_cidr && runtime->bypass_ipv6_cidr_map_fd < 0)) {
        goto prepare_fail;
    }

    runtime->cgroup_fd = open_cgroup_path(cgroup_path);
    if (runtime->cgroup_fd < 0) {
        goto prepare_fail;
    }
    if (flock(runtime->cgroup_fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK) {
            errno = EBUSY;
        }
        goto prepare_fail;
    }
    if (sb_ebpf_detach_owned_progs(runtime->cgroup_fd) < 0) {
        goto prepare_fail;
    }

    return 0;

prepare_fail:
    {
        int saved = errno;
        (void)sb_ebpf_cgroup_close(runtime);
        errno = saved;
    }
    return -1;
}

static int attach_runtime_program(
    struct sb_ebpf_cgroup_runtime *runtime,
    int prog_fd,
    enum bpf_attach_type attach_type,
    uint32_t attached_flag) {
    if (prog_fd < 0) return 0;
    if (sb_ebpf_attach_prog(runtime->cgroup_fd, prog_fd, attach_type) < 0) return -1;
    runtime->attached_programs |= attached_flag;
    return 0;
}

int sb_ebpf_cgroup_attach(struct sb_ebpf_cgroup_runtime *runtime) {
    if (runtime == NULL || runtime->cgroup_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (runtime->attached_programs != 0U) {
        errno = EALREADY;
        return -1;
    }
    if (!runtime_has_programs(runtime)) {
        errno = EINVAL;
        return -1;
    }
    if (attach_runtime_program(runtime, runtime->connect4_prog_fd,
            BPF_CGROUP_INET4_CONNECT, SB_EBPF_ATTACHED_CONNECT4) < 0 ||
        attach_runtime_program(runtime, runtime->udp4_sendmsg_prog_fd,
            BPF_CGROUP_UDP4_SENDMSG, SB_EBPF_ATTACHED_UDP4_SENDMSG) < 0 ||
        attach_runtime_program(runtime, runtime->udp4_recvmsg_prog_fd,
            BPF_CGROUP_UDP4_RECVMSG, SB_EBPF_ATTACHED_UDP4_RECVMSG) < 0 ||
        attach_runtime_program(runtime, runtime->connect6_prog_fd,
            BPF_CGROUP_INET6_CONNECT, SB_EBPF_ATTACHED_CONNECT6) < 0 ||
        attach_runtime_program(runtime, runtime->udp6_sendmsg_prog_fd,
            BPF_CGROUP_UDP6_SENDMSG, SB_EBPF_ATTACHED_UDP6_SENDMSG) < 0 ||
        attach_runtime_program(runtime, runtime->udp6_recvmsg_prog_fd,
            BPF_CGROUP_UDP6_RECVMSG, SB_EBPF_ATTACHED_UDP6_RECVMSG) < 0 ||
        attach_runtime_program(runtime, runtime->connect6_v4mapped_prog_fd,
            BPF_CGROUP_INET6_CONNECT, SB_EBPF_ATTACHED_CONNECT6_V4MAPPED) < 0 ||
        attach_runtime_program(runtime, runtime->udp6_v4mapped_sendmsg_prog_fd,
            BPF_CGROUP_UDP6_SENDMSG, SB_EBPF_ATTACHED_UDP6_V4MAPPED_SENDMSG) < 0 ||
        attach_runtime_program(runtime, runtime->udp6_v4mapped_recvmsg_prog_fd,
            BPF_CGROUP_UDP6_RECVMSG, SB_EBPF_ATTACHED_UDP6_V4MAPPED_RECVMSG) < 0 ||
        attach_runtime_program(runtime, runtime->socket_release_prog_fd,
            BPF_CGROUP_INET_SOCK_RELEASE, SB_EBPF_ATTACHED_SOCKET_RELEASE) < 0) {
        int saved = errno;
        (void)sb_ebpf_cgroup_close(runtime);
        errno = saved;
        return -1;
    }
    return 0;
}

static void remember_close_error(int *result, int *saved_errno) {
    if (*result == 0) {
        *result = -1;
        *saved_errno = errno;
    }
}

static void detach_runtime_program(
    struct sb_ebpf_cgroup_runtime *runtime,
    int prog_fd,
    enum bpf_attach_type attach_type,
    uint32_t attached_flag,
    int *result,
    int *saved_errno) {
    if ((runtime->attached_programs & attached_flag) == 0U) return;
    if (sb_ebpf_detach_prog(runtime->cgroup_fd, prog_fd, attach_type) == 0 ||
        errno == ENOENT || errno == ESRCH) {
        runtime->attached_programs &= ~attached_flag;
        return;
    }
    remember_close_error(result, saved_errno);
}

static void close_runtime_fd(int *fd, int *result, int *saved_errno) {
    if (close_fd(fd) != 0) remember_close_error(result, saved_errno);
}

int sb_ebpf_cgroup_close(struct sb_ebpf_cgroup_runtime *runtime) {
    if (runtime == NULL) return 0;
    int result = 0;
    int saved_errno = 0;
    if (runtime->cgroup_fd >= 0) {
        detach_runtime_program(runtime, runtime->socket_release_prog_fd,
            BPF_CGROUP_INET_SOCK_RELEASE, SB_EBPF_ATTACHED_SOCKET_RELEASE, &result, &saved_errno);
        detach_runtime_program(runtime, runtime->udp6_recvmsg_prog_fd,
            BPF_CGROUP_UDP6_RECVMSG, SB_EBPF_ATTACHED_UDP6_RECVMSG, &result, &saved_errno);
        detach_runtime_program(runtime, runtime->udp6_sendmsg_prog_fd,
            BPF_CGROUP_UDP6_SENDMSG, SB_EBPF_ATTACHED_UDP6_SENDMSG, &result, &saved_errno);
        detach_runtime_program(runtime, runtime->udp6_v4mapped_recvmsg_prog_fd,
            BPF_CGROUP_UDP6_RECVMSG, SB_EBPF_ATTACHED_UDP6_V4MAPPED_RECVMSG, &result, &saved_errno);
        detach_runtime_program(runtime, runtime->udp6_v4mapped_sendmsg_prog_fd,
            BPF_CGROUP_UDP6_SENDMSG, SB_EBPF_ATTACHED_UDP6_V4MAPPED_SENDMSG, &result, &saved_errno);
        detach_runtime_program(runtime, runtime->connect6_prog_fd,
            BPF_CGROUP_INET6_CONNECT, SB_EBPF_ATTACHED_CONNECT6, &result, &saved_errno);
        detach_runtime_program(runtime, runtime->connect6_v4mapped_prog_fd,
            BPF_CGROUP_INET6_CONNECT, SB_EBPF_ATTACHED_CONNECT6_V4MAPPED, &result, &saved_errno);
        detach_runtime_program(runtime, runtime->udp4_recvmsg_prog_fd,
            BPF_CGROUP_UDP4_RECVMSG, SB_EBPF_ATTACHED_UDP4_RECVMSG, &result, &saved_errno);
        detach_runtime_program(runtime, runtime->udp4_sendmsg_prog_fd,
            BPF_CGROUP_UDP4_SENDMSG, SB_EBPF_ATTACHED_UDP4_SENDMSG, &result, &saved_errno);
        detach_runtime_program(runtime, runtime->connect4_prog_fd,
            BPF_CGROUP_INET4_CONNECT, SB_EBPF_ATTACHED_CONNECT4, &result, &saved_errno);
    } else if (runtime->attached_programs != 0U) {
        errno = EBADF;
        remember_close_error(&result, &saved_errno);
    }
    if (runtime->attached_programs != 0U) {
        errno = saved_errno;
        return -1;
    }
    close_runtime_fd(&runtime->socket_release_prog_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->udp6_v4mapped_recvmsg_prog_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->udp6_recvmsg_prog_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->udp4_recvmsg_prog_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->udp6_v4mapped_sendmsg_prog_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->udp6_sendmsg_prog_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->udp4_sendmsg_prog_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->connect6_v4mapped_prog_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->connect6_prog_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->connect4_prog_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->exclude_uid_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->include_uid_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->bypass_ipv6_cidr_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->bypass_ipv4_cidr_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->bypass_socket_cookie_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->udp_peer_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->udp_flow_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->udp_token_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->udp_redirect_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->tcp_redirect_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->cgroup_fd, &result, &saved_errno);
    if (result != 0) errno = saved_errno;
    return result;
}
