// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Included by cgroup.c. Experimental BPF C object loading path.

static bool runtime_has_programs(const struct sb_ebpf_cgroup_runtime *runtime) {
    return runtime->connect4_prog_fd >= 0 || runtime->connect6_prog_fd >= 0 ||
        runtime->udp4_sendmsg_prog_fd >= 0 || runtime->udp6_sendmsg_prog_fd >= 0 ||
        runtime->udp4_recvmsg_prog_fd >= 0 || runtime->udp6_recvmsg_prog_fd >= 0 ||
        runtime->socket_release_prog_fd >= 0;
}

static void close_runtime_programs(struct sb_ebpf_cgroup_runtime *runtime) {
    int *program_fds[] = {
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
    };
    (void)sb_ebpf_close_fds(program_fds, ARRAY_SIZE(program_fds));
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

static int cgroup_object_map_fd(const char *name, void *context) {
    const struct sb_ebpf_cgroup_runtime *runtime = context;
    if (name == NULL || runtime == NULL) {
        errno = EINVAL;
        return -1;
    }
#define RESOLVE_MAP(NAME, FIELD) if (strcmp(name, NAME) == 0) return runtime->FIELD
    RESOLVE_MAP("cgroup_control", control_map_fd);
    RESOLVE_MAP("cgroup_tcp_redirect", tcp_redirect_map_fd);
    RESOLVE_MAP("cgroup_udp_redirect", udp_redirect_map_fd);
    RESOLVE_MAP("cgroup_udp_token", udp_token_map_fd);
    RESOLVE_MAP("cgroup_udp_peer", udp_peer_map_fd);
    RESOLVE_MAP("cgroup_udp_flow", udp_flow_map_fd);
    RESOLVE_MAP("cgroup_socket_bypass", bypass_socket_cookie_map_fd);
    RESOLVE_MAP("cgroup_include_uid", include_uid_map_fd);
    RESOLVE_MAP("cgroup_exclude_uid", exclude_uid_map_fd);
    RESOLVE_MAP("cgroup_bypass_ipv4", bypass_ipv4_cidr_map_fd);
    RESOLVE_MAP("cgroup_bypass_ipv6", bypass_ipv6_cidr_map_fd);
    RESOLVE_MAP("cgroup_ipv6_available", ipv6_available_map_fd);
#undef RESOLVE_MAP
    errno = ENOENT;
    return -1;
}

struct cgroup_object_program_spec {
    const char *tgid_section;
    const char *cookie_section;
    bool enabled;
    struct sb_ebpf_program_descriptor program;
};

static int load_cgroup_object_programs(
    struct sb_ebpf_cgroup_runtime *runtime,
    const uint8_t *object,
    size_t object_size,
    bool tgid_mode,
    bool enable_ipv4,
    bool enable_ipv6,
    bool enable_udp,
    bool log_error) {
    struct cgroup_object_program_spec programs[] = {
        {"cgroup/connect4_tgid", "cgroup/connect4_cookie", enable_ipv4,
         {"sb_ebpf_conn4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT,
          &runtime->connect4_prog_fd}},
        {"cgroup/sendmsg4_tgid", "cgroup/sendmsg4_cookie", enable_ipv4 && enable_udp,
         {"sb_ebpf_udp4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_SENDMSG,
          &runtime->udp4_sendmsg_prog_fd}},
        {"cgroup/recvmsg4", "cgroup/recvmsg4", enable_ipv4 && enable_udp,
         {"sb_ebpf_urcv4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_RECVMSG,
          &runtime->udp4_recvmsg_prog_fd}},
        {"cgroup/connect6_tgid", "cgroup/connect6_cookie", enable_ipv4 || enable_ipv6,
         {"sb_ebpf_conn6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_CONNECT,
          &runtime->connect6_prog_fd}},
        {"cgroup/sendmsg6_tgid", "cgroup/sendmsg6_cookie", (enable_ipv4 || enable_ipv6) && enable_udp,
         {"sb_ebpf_udp6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_SENDMSG,
          &runtime->udp6_sendmsg_prog_fd}},
        {"cgroup/recvmsg6", "cgroup/recvmsg6", (enable_ipv4 || enable_ipv6) && enable_udp,
         {"sb_ebpf_urcv6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_RECVMSG,
          &runtime->udp6_recvmsg_prog_fd}},
        {"cgroup/release_tgid", "cgroup/release_cookie",
         enable_udp && runtime->socket_release_supported,
         {"sb_ebpf_rel", BPF_PROG_TYPE_CGROUP_SOCK, BPF_CGROUP_INET_SOCK_RELEASE,
          &runtime->socket_release_prog_fd}},
    };
    for (size_t index = 0U; index < ARRAY_SIZE(programs); ++index) {
        struct cgroup_object_program_spec *spec = &programs[index];
        if (!spec->enabled) continue;
        const char *section = tgid_mode ? spec->tgid_section : spec->cookie_section;
        *spec->program.fd = sb_ebpf_load_object_program(
            object,
            object_size,
            section,
            &spec->program,
            cgroup_object_map_fd,
            runtime,
            log_error);
        if (*spec->program.fd < 0) {
            sb_ebpf_set_error_stage(runtime->error_stage, spec->program.name);
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
    if (runtime->include_uid_policy) control.flags |= SB_EBPF_CGROUP_FLAG_INCLUDE_UID;
    if (runtime->exclude_uid_policy) control.flags |= SB_EBPF_CGROUP_FLAG_EXCLUDE_UID;
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
            enable_udp, false) == 0) {
        runtime->self_bypass_tgid = true;
        return 0;
    }
    if (!try_tgid) {
        runtime->bypass_socket_cookie_map_fd = create_bypass_socket_cookie_map(
            runtime->socket_bypass_map_capacity);
    } else {
        runtime->bypass_socket_cookie_map_fd = create_bypass_socket_cookie_map(
            runtime->socket_bypass_map_capacity);
    }
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
            enable_udp, true) != 0) {
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
