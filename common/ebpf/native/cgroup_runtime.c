// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Included by cgroup.c to keep the native cgroup backend in one translation unit.

static int create_bypass_socket_cookie_map(uint32_t max_entries) {
    int fd = -1;
    const struct sb_ebpf_map_spec spec = {
        "socket bypass",
        (enum bpf_map_type)SB_EBPF_LRU_HASH_MAP_TYPE,
        sizeof(uint64_t),
        sizeof(uint8_t),
        max_entries,
        0U,
        &fd,
    };
    return sb_ebpf_create_maps(&spec, 1U, NULL) == 0 ? fd : -1;
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
	bool auto_ipv6,
	uint32_t include_uid_entries,
	uint32_t exclude_uid_entries,
	uint32_t tcp_redirect_map_capacity,
	uint32_t udp_redirect_map_capacity,
	uint32_t socket_bypass_map_capacity,
	struct sb_ebpf_cgroup_runtime *runtime) {
    if (runtime == NULL || (!enable_tcp && !enable_udp) ||
        include_uid_entries > SB_EBPF_MAX_POLICY_MAP_ENTRIES ||
        exclude_uid_entries > SB_EBPF_MAX_POLICY_MAP_ENTRIES ||
        !sb_ebpf_map_capacity_valid(tcp_redirect_map_capacity) ||
        !sb_ebpf_map_capacity_valid(udp_redirect_map_capacity) ||
        !sb_ebpf_map_capacity_valid(socket_bypass_map_capacity)) {
        errno = EINVAL;
        return -1;
    }

    init_runtime(runtime);
    sb_ebpf_set_error_stage(runtime->error_stage, "probe socket release");
    int socket_release_support = enable_udp ? probe_socket_release_support() : 0;
    if (socket_release_support < 0) {
        goto prepare_fail;
    }
    runtime->socket_release_supported = socket_release_support > 0;
    runtime->enable_tcp = enable_tcp;
    runtime->enable_udp = enable_udp;
    runtime->include_uid_policy = include_uid_entries > 0U;
    runtime->exclude_uid_policy = exclude_uid_entries > 0U;
    runtime->bypass_ipv4_policy = enable_bypass_ipv4_cidr;
    runtime->bypass_ipv6_policy = enable_bypass_ipv6_cidr;
    runtime->auto_ipv6 = auto_ipv6;
    bool use_udp_lru_fallback = enable_udp && !runtime->socket_release_supported;
    const struct sb_ebpf_map_spec maps[] = {
        {"control", (enum bpf_map_type)SB_EBPF_ARRAY_MAP_TYPE,
         sizeof(uint32_t), sizeof(struct sb_ebpf_cgroup_control),
         1U, 0U, &runtime->control_map_fd},
        {"TCP redirect", (enum bpf_map_type)SB_EBPF_HASH_MAP_TYPE,
         sizeof(struct sb_ebpf_listener_key), sizeof(struct sb_ebpf_original_dst),
         enable_tcp ? tcp_redirect_map_capacity : 1U, 0U, &runtime->tcp_redirect_map_fd},
        {"UDP redirect", (enum bpf_map_type)(use_udp_lru_fallback
             ? SB_EBPF_LRU_HASH_MAP_TYPE : SB_EBPF_HASH_MAP_TYPE),
         sizeof(struct sb_ebpf_listener_key), sizeof(struct sb_ebpf_original_dst),
         enable_udp ? udp_redirect_map_capacity : 1U, 0U, &runtime->udp_redirect_map_fd},
        {"UDP token", (enum bpf_map_type)(use_udp_lru_fallback
             ? SB_EBPF_LRU_HASH_MAP_TYPE : SB_EBPF_HASH_MAP_TYPE),
         sizeof(uint64_t), sizeof(struct sb_ebpf_listener_key),
         enable_udp ? udp_redirect_map_capacity : 1U, 0U, &runtime->udp_token_map_fd},
        {"UDP peer", (enum bpf_map_type)SB_EBPF_LRU_HASH_MAP_TYPE,
         sizeof(struct sb_ebpf_udp_peer_key), sizeof(struct sb_ebpf_udp_peer_value),
         enable_udp ? udp_redirect_map_capacity : 1U, 0U, &runtime->udp_peer_map_fd},
        /* This cache is an optimization. Keep the original path on older kernels. */
        {"UDP flow", (enum bpf_map_type)SB_EBPF_LRU_HASH_MAP_TYPE,
         sizeof(struct sb_ebpf_udp_flow_key), sizeof(struct sb_ebpf_udp_flow_value),
         enable_udp && runtime->socket_release_supported ? udp_redirect_map_capacity : 1U,
         0U, &runtime->udp_flow_map_fd},
        {"include UID", (enum bpf_map_type)SB_EBPF_LPM_TRIE_MAP_TYPE,
         sizeof(struct sb_ebpf_uid_lpm_key), sizeof(uint8_t), include_uid_entries > 0U ? include_uid_entries : 1U,
         BPF_F_NO_PREALLOC, &runtime->include_uid_map_fd},
        {"exclude UID", (enum bpf_map_type)SB_EBPF_LPM_TRIE_MAP_TYPE,
         sizeof(struct sb_ebpf_uid_lpm_key), sizeof(uint8_t), exclude_uid_entries > 0U ? exclude_uid_entries : 1U,
         BPF_F_NO_PREALLOC, &runtime->exclude_uid_map_fd},
        {"IPv4 bypass CIDR", (enum bpf_map_type)SB_EBPF_LPM_TRIE_MAP_TYPE,
         sizeof(struct sb_ebpf_ipv4_cidr_lpm_key), sizeof(uint8_t),
         SB_EBPF_MAX_BYPASS_CIDR_MAP_ENTRIES,
         BPF_F_NO_PREALLOC, &runtime->bypass_ipv4_cidr_map_fd},
        {"IPv6 bypass CIDR", (enum bpf_map_type)SB_EBPF_LPM_TRIE_MAP_TYPE,
         sizeof(struct sb_ebpf_ipv6_cidr_lpm_key), sizeof(uint8_t),
         SB_EBPF_MAX_BYPASS_CIDR_MAP_ENTRIES,
         BPF_F_NO_PREALLOC, &runtime->bypass_ipv6_cidr_map_fd},
        {"IPv6 availability", (enum bpf_map_type)SB_EBPF_ARRAY_MAP_TYPE,
         sizeof(uint32_t), sizeof(uint32_t), 1U,
         0U, &runtime->ipv6_available_map_fd},
    };
    const char *failed_map = NULL;
    if (sb_ebpf_create_maps(maps, ARRAY_SIZE(maps), &failed_map) != 0) {
        sb_ebpf_set_error_stage(runtime->error_stage, failed_map);
        goto prepare_fail;
    }
    runtime->socket_bypass_map_capacity = socket_bypass_map_capacity;

    sb_ebpf_set_error_stage(runtime->error_stage, "open cgroup");
    runtime->cgroup_fd = open_cgroup_path(cgroup_path);
    if (runtime->cgroup_fd < 0) {
        goto prepare_fail;
    }
    sb_ebpf_set_error_stage(runtime->error_stage, "lock cgroup");
    if (flock(runtime->cgroup_fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK) {
            errno = EBUSY;
        }
        goto prepare_fail;
    }
    if (sb_ebpf_detach_owned_progs(runtime->cgroup_fd) < 0) {
        sb_ebpf_set_error_stage(runtime->error_stage, "detach stale cgroup programs");
        goto prepare_fail;
    }

    sb_ebpf_set_error_stage(runtime->error_stage, NULL);
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
    const struct sb_ebpf_program_descriptor *program,
    uint32_t attached_flag) {
    if (program == NULL || program->fd == NULL || *program->fd < 0) return 0;
    if (sb_ebpf_attach_prog(
            runtime->cgroup_fd,
            *program->fd,
            program->attach_type) < 0) {
        sb_ebpf_set_error_stage(runtime->error_stage, program->name);
        return -1;
    }
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
    struct attach_spec {
        struct sb_ebpf_program_descriptor program;
        uint32_t attached_flag;
    } programs[] = {
        {{"sb_ebpf_conn4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT,
          &runtime->connect4_prog_fd}, SB_EBPF_ATTACHED_CONNECT4},
        {{"sb_ebpf_udp4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_SENDMSG,
          &runtime->udp4_sendmsg_prog_fd}, SB_EBPF_ATTACHED_UDP4_SENDMSG},
        {{"sb_ebpf_urcv4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_RECVMSG,
          &runtime->udp4_recvmsg_prog_fd}, SB_EBPF_ATTACHED_UDP4_RECVMSG},
        {{"sb_ebpf_conn6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_CONNECT,
          &runtime->connect6_prog_fd}, SB_EBPF_ATTACHED_CONNECT6},
        {{"sb_ebpf_udp6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_SENDMSG,
          &runtime->udp6_sendmsg_prog_fd}, SB_EBPF_ATTACHED_UDP6_SENDMSG},
        {{"sb_ebpf_urcv6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_RECVMSG,
          &runtime->udp6_recvmsg_prog_fd}, SB_EBPF_ATTACHED_UDP6_RECVMSG},
        {{"sb_ebpf_c6v4m", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_CONNECT,
          &runtime->connect6_v4mapped_prog_fd}, SB_EBPF_ATTACHED_CONNECT6_V4MAPPED},
        {{"sb_ebpf_u6v4m", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_SENDMSG,
          &runtime->udp6_v4mapped_sendmsg_prog_fd}, SB_EBPF_ATTACHED_UDP6_V4MAPPED_SENDMSG},
        {{"sb_ebpf_ur6v4m", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_RECVMSG,
          &runtime->udp6_v4mapped_recvmsg_prog_fd}, SB_EBPF_ATTACHED_UDP6_V4MAPPED_RECVMSG},
        {{"sb_ebpf_rel", BPF_PROG_TYPE_CGROUP_SOCK, BPF_CGROUP_INET_SOCK_RELEASE,
          &runtime->socket_release_prog_fd}, SB_EBPF_ATTACHED_SOCKET_RELEASE},
    };
    for (size_t index = 0U; index < ARRAY_SIZE(programs); ++index) {
        if (attach_runtime_program(
                runtime,
                &programs[index].program,
                programs[index].attached_flag) < 0) {
            int saved = errno;
            (void)sb_ebpf_cgroup_close(runtime);
            errno = saved;
            return -1;
        }
    }
    sb_ebpf_set_error_stage(runtime->error_stage, NULL);
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
    int *runtime_fds[] = {
        &runtime->socket_release_prog_fd,
        &runtime->udp6_v4mapped_recvmsg_prog_fd,
        &runtime->udp6_recvmsg_prog_fd,
        &runtime->udp4_recvmsg_prog_fd,
        &runtime->udp6_v4mapped_sendmsg_prog_fd,
        &runtime->udp6_sendmsg_prog_fd,
        &runtime->udp4_sendmsg_prog_fd,
        &runtime->connect6_v4mapped_prog_fd,
        &runtime->connect6_prog_fd,
        &runtime->connect4_prog_fd,
        &runtime->exclude_uid_map_fd,
        &runtime->include_uid_map_fd,
        &runtime->bypass_ipv6_cidr_map_fd,
        &runtime->ipv6_available_map_fd,
        &runtime->bypass_ipv4_cidr_map_fd,
        &runtime->bypass_socket_cookie_map_fd,
        &runtime->udp_peer_map_fd,
        &runtime->udp_flow_map_fd,
        &runtime->udp_token_map_fd,
        &runtime->udp_redirect_map_fd,
        &runtime->tcp_redirect_map_fd,
        &runtime->control_map_fd,
        &runtime->cgroup_fd,
    };
    if (sb_ebpf_close_fds(runtime_fds, ARRAY_SIZE(runtime_fds)) != 0) {
        remember_close_error(&result, &saved_errno);
    }
    if (result != 0) errno = saved_errno;
    return result;
}
