// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Included by cgroup.c. Experimental BPF C object loading path.

struct cgroup_program_definition {
    const char *tgid_section;
    const char *cookie_section;
    const char *tgid_tcp_section;
    const char *cookie_tcp_section;
    const char *tgid_udp_section;
    const char *cookie_udp_section;
    const char *mapped_tgid_section;
    const char *mapped_cookie_section;
    const char *mapped_tgid_tcp_section;
    const char *mapped_cookie_tcp_section;
    const char *mapped_tgid_udp_section;
    const char *mapped_cookie_udp_section;
    const char *name;
    enum bpf_prog_type type;
    enum bpf_attach_type attach_type;
};

static const struct cgroup_program_definition cgroup_programs[SB_EBPF_CGROUP_PROGRAM_COUNT] = {
    [SB_EBPF_CGROUP_PROGRAM_CONNECT4] = {
        "cgroup/connect4_tgid", "cgroup/connect4_cookie",
        "cgroup/connect4_tgid_tcp", "cgroup/connect4_cookie_tcp",
        "cgroup/connect4_tgid_udp", "cgroup/connect4_cookie_udp",
        NULL, NULL, NULL, NULL, NULL, NULL, "sb_ebpf_conn4",
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT},
    [SB_EBPF_CGROUP_PROGRAM_UDP4_SENDMSG] = {
        "cgroup/sendmsg4_tgid", "cgroup/sendmsg4_cookie",
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "sb_ebpf_udp4",
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_SENDMSG},
    [SB_EBPF_CGROUP_PROGRAM_UDP4_RECVMSG] = {
        "cgroup/recvmsg4", "cgroup/recvmsg4",
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "sb_ebpf_urcv4",
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_RECVMSG},
    [SB_EBPF_CGROUP_PROGRAM_CONNECT6] = {
        "cgroup/connect6_tgid", "cgroup/connect6_cookie",
        "cgroup/connect6_tgid_tcp", "cgroup/connect6_cookie_tcp",
        "cgroup/connect6_tgid_udp", "cgroup/connect6_cookie_udp",
        "cgroup/connect6_mapped_tgid", "cgroup/connect6_mapped_cookie",
        "cgroup/connect6_mapped_tgid_tcp", "cgroup/connect6_mapped_cookie_tcp",
        "cgroup/connect6_mapped_tgid_udp", "cgroup/connect6_mapped_cookie_udp", "sb_ebpf_conn6",
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_CONNECT},
    [SB_EBPF_CGROUP_PROGRAM_UDP6_SENDMSG] = {
        "cgroup/sendmsg6_tgid", "cgroup/sendmsg6_cookie",
        NULL, NULL, NULL, NULL, "cgroup/sendmsg6_mapped_tgid", "cgroup/sendmsg6_mapped_cookie",
        NULL, NULL, NULL, NULL, "sb_ebpf_udp6",
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_SENDMSG},
    [SB_EBPF_CGROUP_PROGRAM_UDP6_RECVMSG] = {
        "cgroup/recvmsg6", "cgroup/recvmsg6",
        NULL, NULL, NULL, NULL, "cgroup/recvmsg6_mapped", "cgroup/recvmsg6_mapped",
        NULL, NULL, NULL, NULL, "sb_ebpf_urcv6",
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_RECVMSG},
    [SB_EBPF_CGROUP_PROGRAM_SOCKET_RELEASE] = {
        "cgroup/release_tgid", "cgroup/release_cookie",
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "sb_ebpf_rel",
        BPF_PROG_TYPE_CGROUP_SOCK, BPF_CGROUP_INET_SOCK_RELEASE},
};

static bool cgroup_program_enabled(
    enum sb_ebpf_cgroup_program_slot slot,
    const struct sb_ebpf_cgroup_runtime *runtime,
    bool enable_ipv4,
    bool enable_ipv6) {
    switch (slot) {
        case SB_EBPF_CGROUP_PROGRAM_CONNECT4:
            return enable_ipv4;
        case SB_EBPF_CGROUP_PROGRAM_UDP4_SENDMSG:
        case SB_EBPF_CGROUP_PROGRAM_UDP4_RECVMSG:
            return enable_ipv4 && runtime->enable_udp;
        case SB_EBPF_CGROUP_PROGRAM_CONNECT6:
            return enable_ipv4 || enable_ipv6;
        case SB_EBPF_CGROUP_PROGRAM_UDP6_SENDMSG:
        case SB_EBPF_CGROUP_PROGRAM_UDP6_RECVMSG:
            return (enable_ipv4 || enable_ipv6) && runtime->enable_udp;
        case SB_EBPF_CGROUP_PROGRAM_SOCKET_RELEASE:
            return runtime->enable_udp && runtime->socket_release_supported;
        default:
            return false;
    }
}

static bool runtime_has_programs(const struct sb_ebpf_cgroup_runtime *runtime) {
    for (size_t slot = 0U; slot < SB_EBPF_CGROUP_PROGRAM_COUNT; ++slot) {
        if (runtime->program_fds[slot] >= 0) return true;
    }
    return false;
}

static void close_runtime_programs(struct sb_ebpf_cgroup_runtime *runtime) {
    for (size_t slot = SB_EBPF_CGROUP_PROGRAM_COUNT; slot > 0U; --slot) {
        (void)sb_ebpf_close_fd(&runtime->program_fds[slot - 1U]);
    }
}

static int probe_socket_release_support(void) {
    const struct bpf_insn insns[] = {
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_EXIT_INSN(),
    };
    int fd = sb_ebpf_load_prog(
        insns,
        ARRAY_SIZE(insns),
        "sb_rel_probe",
        BPF_PROG_TYPE_CGROUP_SOCK,
        BPF_CGROUP_INET_SOCK_RELEASE,
        false);
    if (fd >= 0) {
        if (sb_ebpf_close_fd(&fd) != 0) return -1;
        return 1;
    }
    if (errno == EINVAL || errno == ENOTSUP || errno == EOPNOTSUPP) {
        errno = 0;
        return 0;
    }
    return -1;
}

int sb_ebpf_cgroup_probe_self_tgid(
    struct sb_ebpf_cgroup_runtime *runtime,
    uint32_t *self_tgid) {
    if (runtime == NULL || self_tgid == NULL || runtime->cgroup_fd < 0 ||
        runtime_has_programs(runtime)) {
        errno = EINVAL;
        return -1;
    }
    *self_tgid = 0U;
    int map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_ARRAY,
        sizeof(uint32_t),
        sizeof(uint32_t),
        1U,
        0U);
    if (map_fd < 0) return 0;
    const struct bpf_insn instructions[] = {
        BPF_ST_MEM_W(BPF_REG_10, -4, 0),
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ADD64_IMM(BPF_REG_2, -4),
        BPF_CALL_HELPER(BPF_FUNC_map_lookup_elem),
        {.code = BPF_JMP | BPF_JEQ | BPF_K, .dst_reg = BPF_REG_0, .off = 4, .imm = 0},
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
        BPF_CALL_HELPER(BPF_FUNC_get_current_pid_tgid),
        BPF_RSH64_IMM(BPF_REG_0, 32),
        BPF_STX_MEM_W(BPF_REG_6, BPF_REG_0, 0),
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_EXIT_INSN(),
    };
    int program_fd = sb_ebpf_load_prog(
        instructions,
        ARRAY_SIZE(instructions),
        "sb_tgid_probe",
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        BPF_CGROUP_INET4_CONNECT,
        false);
    if (program_fd < 0) {
        (void)sb_ebpf_close_fd(&map_fd);
        return 0;
    }
    bool attached = sb_ebpf_attach_prog(
        runtime->cgroup_fd,
        program_fd,
        BPF_CGROUP_INET4_CONNECT) == 0;
    if (attached) {
        int socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
        if (socket_fd >= 0) {
            const struct sockaddr_in destination = {
                .sin_family = AF_INET,
                .sin_port = htons(9U),
                .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
            };
            (void)connect(
                socket_fd,
                (const struct sockaddr *)&destination,
                sizeof(destination));
            (void)sb_ebpf_close_fd(&socket_fd);
        }
        uint32_t key = 0U;
        (void)sb_ebpf_lookup_map(map_fd, &key, self_tgid);
    }
    int detach_result = 0;
    int detach_errno = 0;
    if (attached && sb_ebpf_detach_prog(
            runtime->cgroup_fd,
            program_fd,
            BPF_CGROUP_INET4_CONNECT) != 0) {
        detach_result = -1;
        detach_errno = errno;
    }
    (void)sb_ebpf_close_fd(&program_fd);
    (void)sb_ebpf_close_fd(&map_fd);
    if (detach_result != 0) {
        errno = detach_errno;
        return -1;
    }
    return 0;
}

static int cgroup_object_map_fd(const char *name, void *context) {
    static const struct sb_ebpf_map_binding bindings[] = {
#define MAP_BINDING(NAME, FIELD) {NAME, offsetof(struct sb_ebpf_cgroup_runtime, FIELD)}
        MAP_BINDING("cgroup_control", control_map_fd),
        MAP_BINDING("cgroup_tcp_redirect", tcp_redirect_map_fd),
        MAP_BINDING("cgroup_udp_redirect", udp_redirect_map_fd),
        MAP_BINDING("cgroup_udp_token", udp_token_map_fd),
        MAP_BINDING("cgroup_udp_peer", udp_peer_map_fd),
        MAP_BINDING("cgroup_udp_flow", udp_flow_map_fd),
        MAP_BINDING("cgroup_socket_bypass", bypass_socket_cookie_map_fd),
        MAP_BINDING("cgroup_uid_policy", uid_policy_map_fd),
        MAP_BINDING("cgroup_bypass_ipv4", bypass_ipv4_cidr_map_fd),
        MAP_BINDING("cgroup_bypass_ipv6", bypass_ipv6_cidr_map_fd),
        MAP_BINDING("cgroup_ipv6_available", ipv6_available_map_fd),
#undef MAP_BINDING
    };
    return sb_ebpf_resolve_map_fd(name, context, bindings, ARRAY_SIZE(bindings));
}

static int load_cgroup_object_programs(
    struct sb_ebpf_cgroup_runtime *runtime,
    const uint8_t *object,
    size_t object_size,
    bool tgid_mode,
    bool enable_ipv4,
    bool enable_ipv6,
    bool log_error) {
    for (size_t slot = 0U; slot < SB_EBPF_CGROUP_PROGRAM_COUNT; ++slot) {
        if (!cgroup_program_enabled(slot, runtime, enable_ipv4, enable_ipv6)) continue;
        const struct cgroup_program_definition *definition = &cgroup_programs[slot];
        bool mapped_only = !enable_ipv6 && definition->mapped_tgid_section != NULL;
        const char *section;
        bool tcp_only = runtime->enable_tcp && !runtime->enable_udp;
        bool udp_only = !runtime->enable_tcp && runtime->enable_udp;
        if (mapped_only) {
            if (tcp_only && definition->mapped_tgid_tcp_section != NULL) {
                section = tgid_mode
                    ? definition->mapped_tgid_tcp_section
                    : definition->mapped_cookie_tcp_section;
            } else if (udp_only && definition->mapped_tgid_udp_section != NULL) {
                section = tgid_mode
                    ? definition->mapped_tgid_udp_section
                    : definition->mapped_cookie_udp_section;
            } else {
                section = tgid_mode
                    ? definition->mapped_tgid_section
                    : definition->mapped_cookie_section;
            }
        } else {
            if (tcp_only && definition->tgid_tcp_section != NULL) {
                section = tgid_mode
                    ? definition->tgid_tcp_section
                    : definition->cookie_tcp_section;
            } else if (udp_only && definition->tgid_udp_section != NULL) {
                section = tgid_mode
                    ? definition->tgid_udp_section
                    : definition->cookie_udp_section;
            } else {
                section = tgid_mode
                    ? definition->tgid_section
                    : definition->cookie_section;
            }
        }
        struct sb_ebpf_program_descriptor program = {
            definition->name,
            definition->type,
            definition->attach_type,
            &runtime->program_fds[slot],
        };
        *program.fd = sb_ebpf_load_object_program(
            object,
            object_size,
            section,
            &program,
            cgroup_object_map_fd,
            runtime,
            log_error);
        if (*program.fd < 0) {
            sb_ebpf_set_error_stage(runtime->error_stage, program.name);
            close_runtime_programs(runtime);
            return -1;
        }
    }
    sb_ebpf_set_error_stage(runtime->error_stage, NULL);
    return 0;
}

static int update_cgroup_control(
    struct sb_ebpf_cgroup_runtime *runtime,
    uint16_t listen_port,
    uint32_t self_tgid,
    bool enable_ipv4,
    bool hijack_dns,
    uint32_t udp_timeout_seconds,
    const uint8_t redirect_ipv4[4],
    uint32_t redirect_ipv4_prefix_bits,
    bool enable_ipv6,
    const uint8_t redirect_ipv6[16]) {
    struct sb_ebpf_cgroup_control control;
    memset(&control, 0, sizeof(control));
    if (runtime->enable_tcp) control.flags |= SB_EBPF_CGROUP_FLAG_TCP;
    if (runtime->enable_udp) control.flags |= SB_EBPF_CGROUP_FLAG_UDP;
    if (enable_ipv4) control.flags |= SB_EBPF_CGROUP_FLAG_IPV4;
    if (enable_ipv6) control.flags |= SB_EBPF_CGROUP_FLAG_IPV6;
    if (hijack_dns) control.flags |= SB_EBPF_CGROUP_FLAG_HIJACK_DNS;
    if (runtime->uid_policy) control.flags |= SB_EBPF_CGROUP_FLAG_UID_POLICY;
    if (runtime->uid_default_bypass) control.flags |= SB_EBPF_CGROUP_FLAG_UID_DEFAULT_BYPASS;
    if (runtime->exclude_android_dns_tether) {
        control.flags |= SB_EBPF_CGROUP_FLAG_EXCLUDE_ANDROID_DNS_TETHER;
    }
    if (runtime->bypass_ipv4_policy) control.flags |= SB_EBPF_CGROUP_FLAG_BYPASS_IPV4;
    if (runtime->bypass_ipv6_policy) control.flags |= SB_EBPF_CGROUP_FLAG_BYPASS_IPV6;
    if (runtime->auto_ipv6) control.flags |= SB_EBPF_CGROUP_FLAG_AUTO_IPV6;
    if (runtime->enable_udp && runtime->socket_release_supported) {
        control.flags |= SB_EBPF_CGROUP_FLAG_UDP_FLOW;
    }
    control.self_tgid = self_tgid;
    control.udp_timeout_seconds = udp_timeout_seconds;
    control.redirect_ipv4_prefix = ipv4_redirect_prefix(
        redirect_ipv4,
        redirect_ipv4_prefix_bits);
    control.redirect_ipv4_host_mask = ipv4_redirect_host_mask(redirect_ipv4_prefix_bits);
    control.listener_port = listen_port;
    if (redirect_ipv6 != NULL) {
        memcpy(control.redirect_ipv6_prefix, redirect_ipv6, sizeof(control.redirect_ipv6_prefix));
    }
    uint32_t key = 0U;
    return sb_ebpf_update_map(runtime->control_map_fd, &key, &control, 0U);
}

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
    uint32_t redirect_ipv6_prefix_bits) {
    if (runtime == NULL || object == NULL || object_size == 0U ||
        runtime->cgroup_fd < 0 || runtime->control_map_fd < 0 || listen_port == 0U ||
        (!enable_ipv4 && !enable_ipv6) ||
        (enable_ipv4 && (redirect_ipv4 == NULL || redirect_ipv4_prefix_bits < 8U ||
                         redirect_ipv4_prefix_bits > 10U)) ||
        (enable_ipv6 && (redirect_ipv6 == NULL || redirect_ipv6_prefix_bits != 64U))) {
        errno = EINVAL;
        return -1;
    }
    if (runtime_has_programs(runtime)) {
        errno = EALREADY;
        return -1;
    }
    bool enable_udp = runtime->enable_udp;
    if (enable_udp && udp_timeout_seconds == 0U) {
        errno = EINVAL;
        return -1;
    }
    bool try_tgid = self_tgid != 0U;
    if (update_cgroup_control(
            runtime, listen_port, try_tgid ? self_tgid : 0U, enable_ipv4, hijack_dns,
            udp_timeout_seconds, redirect_ipv4, redirect_ipv4_prefix_bits,
            enable_ipv6, redirect_ipv6) != 0) {
        sb_ebpf_set_error_stage(runtime->error_stage, "cgroup control map");
        return -1;
    }
    if (try_tgid && load_cgroup_object_programs(
            runtime, object, object_size, true, enable_ipv4, enable_ipv6,
            false) == 0) {
        runtime->self_bypass_tgid = true;
        return 0;
    }
    runtime->bypass_socket_cookie_map_fd = create_bypass_socket_cookie_map(
        runtime->socket_bypass_map_capacity);
    if (runtime->bypass_socket_cookie_map_fd < 0) {
        sb_ebpf_set_error_stage(runtime->error_stage, "socket bypass map");
        return -1;
    }
    if (update_cgroup_control(
            runtime, listen_port, 0U, enable_ipv4, hijack_dns, udp_timeout_seconds,
            redirect_ipv4, redirect_ipv4_prefix_bits, enable_ipv6, redirect_ipv6) != 0) {
        sb_ebpf_set_error_stage(runtime->error_stage, "cgroup control map fallback");
        goto fail;
    }
    if (load_cgroup_object_programs(
            runtime, object, object_size, false, enable_ipv4, enable_ipv6,
            true) != 0) {
        goto fail;
    }
    runtime->self_bypass_tgid = false;
    return 0;

fail: {
        int saved_errno = errno;
        close_runtime_programs(runtime);
        errno = saved_errno;
        return -1;
    }
}
