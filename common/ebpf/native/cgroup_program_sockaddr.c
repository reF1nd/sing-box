// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Included by cgroup_program.c. Connect and UDP sendmsg program builders.

static int build_ipv4_sock_addr_prog(
    const struct sb_ebpf_cgroup_config *config,
    uint32_t self_tgid,
    int include_uid_map_fd,
    int exclude_uid_map_fd,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_flow_map_fd,
    int udp_peer_map_fd,
    int bypass_socket_cookie_map_fd,
    int bypass_ipv4_cidr_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit_self_tgid_bypass(&b, self_tgid, bypass_jumps, &bypass_jump_count);
    emit_socket_cookie_bypass(&b, bypass_socket_cookie_map_fd, bypass_jumps, &bypass_jump_count);
    emit_inbound_network_filter(
        &b, config, protocol, protocol_from_context, bypass_jumps, &bypass_jump_count);
    emit_uid_policy_filter(
        &b, include_uid_map_fd, exclude_uid_map_fd, bypass_jumps, &bypass_jump_count);
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit_dns_off_bypass(
        &b, config, protocol, protocol_from_context, BPF_REG_8,
        bypass_jumps, &bypass_jump_count);
    emit_udp_system_service_bypass(
        &b, protocol, protocol_from_context, BPF_REG_8, bypass_jumps, &bypass_jump_count);
    // Connected UDP send() may not hit UDP_SENDMSG on Android kernels, so CONNECT must continue interception.
    // This can expose the redirect peer via getpeername(), but it avoids direct UDP leakage.
    if (attach_type == BPF_CGROUP_INET4_CONNECT && protocol_from_context) {
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        size_t tcp_connect = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SB_EBPF_PROTO_TCP, 0));
        bypass_jumps[bypass_jump_count++] =
            emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
        emit_udp_connected_state_reset(
            &b, udp_redirect_map_fd, udp_token_map_fd, udp_peer_map_fd);
        emit_udp_peer_cache_update(&b, udp_peer_map_fd, false, bypass_jumps, &bypass_jump_count);
        patch_jump(&b, tcp_connect, b.count);
    }
    if (attach_type == BPF_CGROUP_UDP4_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_udp_connected_token_restore_v4(
            &b, udp_token_map_fd, listen_port, allow_jumps, &allow_jump_count);
        emit_udp_flow_cache_restore_v4(
            &b, udp_flow_map_fd, listen_port, allow_jumps, &allow_jump_count);
        emit_udp_peer_cache_restore_v4(&b, udp_peer_map_fd);
    }
    size_t dns_hijack_jumps[2];
    size_t dns_hijack_jump_count = 0;
    emit_dns_hijack_jumps(
        &b, config, protocol, protocol_from_context, BPF_REG_8,
        dns_hijack_jumps, &dns_hijack_jump_count);
    emit_ipv4_destination_bypass(&b, bypass_jumps, &bypass_jump_count);
    emit_ipv4_cidr_bypass(
        &b, bypass_ipv4_cidr_map_fd, BPF_REG_7, bypass_jumps, &bypass_jump_count);
    for (size_t i = 0; i < dns_hijack_jump_count; ++i) {
        patch_jump(&b, dns_hijack_jumps[i], b.count);
    }
    emit_redirect_update_and_rewrite_by_protocol(
        &b,
        config,
        tcp_redirect_map_fd,
        udp_redirect_map_fd,
        udp_token_map_fd,
        udp_flow_map_fd,
        protocol,
        protocol_from_context,
        listen_port,
        drop_jumps,
        &drop_jump_count);
    size_t allow_label = emit_exit(&b, 1);
    size_t drop_label = emit_exit(&b, 0);

    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    for (size_t i = 0; i < allow_jump_count; ++i) {
        patch_jump(&b, allow_jumps[i], allow_label);
    }
    for (size_t i = 0; i < drop_jump_count; ++i) {
        patch_jump(&b, drop_jumps[i], drop_label);
    }

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return sb_ebpf_load_prog(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        log_error);
}

static int build_ipv6_sock_addr_prog(
    const struct sb_ebpf_cgroup_config *config,
    uint32_t self_tgid,
    int include_uid_map_fd,
    int exclude_uid_map_fd,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_flow_map_fd,
    int udp_peer_map_fd,
    int bypass_socket_cookie_map_fd,
    int bypass_ipv4_cidr_map_fd,
    int bypass_ipv6_cidr_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit_self_tgid_bypass(&b, self_tgid, bypass_jumps, &bypass_jump_count);
    emit_socket_cookie_bypass(&b, bypass_socket_cookie_map_fd, bypass_jumps, &bypass_jump_count);
    emit_inbound_network_filter(
        &b, config, protocol, protocol_from_context, bypass_jumps, &bypass_jump_count);
    emit_uid_policy_filter(
        &b, include_uid_map_fd, exclude_uid_map_fd, bypass_jumps, &bypass_jump_count);
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit_dns_off_bypass(
        &b, config, protocol, protocol_from_context, BPF_REG_5,
        bypass_jumps, &bypass_jump_count);
    emit_udp_system_service_bypass(
        &b, protocol, protocol_from_context, BPF_REG_5, bypass_jumps, &bypass_jump_count);
    if (attach_type == BPF_CGROUP_UDP6_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_udp_connected_token_restore_v6(
            &b, udp_token_map_fd, listen_port, allow_jumps, &allow_jump_count);
        emit_udp_flow_cache_restore_v6(
            &b, udp_flow_map_fd, listen_port, allow_jumps, &allow_jump_count);
    }
    bool emitted_v4mapped_branch = false;
    if (config->disable_ipv4) {
        size_t not_mapped_jumps[3];
        size_t not_mapped_jump_count = 0;
        emit_ipv4_mapped_ipv6_check_jumps(&b, not_mapped_jumps, &not_mapped_jump_count);
        allow_jumps[allow_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        for (size_t i = 0; i < not_mapped_jump_count; ++i) {
            patch_jump(&b, not_mapped_jumps[i], b.count);
        }
    } else {
        emitted_v4mapped_branch = emit_ipv4_mapped_ipv6_branch(
            &b,
            config,
            tcp_redirect_map_fd,
            udp_redirect_map_fd,
            udp_token_map_fd,
            udp_flow_map_fd,
            udp_peer_map_fd,
            bypass_ipv4_cidr_map_fd,
            protocol,
            protocol_from_context,
            listen_port,
            attach_type,
            bypass_jumps,
            &bypass_jump_count,
            drop_jumps,
            &drop_jump_count,
            allow_jumps,
            &allow_jump_count);
    }
    if (emitted_v4mapped_branch) {
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    }
    // Connected UDP send() may not hit UDP_SENDMSG on Android kernels. Rewrite at CONNECT so all
    // packets reach the inbound listener; UDP6_SENDMSG remains a fallback for sendmsg() callers.
    if (attach_type == BPF_CGROUP_INET6_CONNECT && protocol_from_context) {
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        size_t tcp_connect = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SB_EBPF_PROTO_TCP, 0));
        bypass_jumps[bypass_jump_count++] =
            emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
        emit_udp_connected_state_reset(
            &b, udp_redirect_map_fd, udp_token_map_fd, udp_peer_map_fd);
        emit_udp_peer_cache_update(&b, udp_peer_map_fd, true, bypass_jumps, &bypass_jump_count);
        // map_update_elem() invalidates R1-R5. Reload the destination before the common
        // IPv6 interception path reads the address and port registers.
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
        patch_jump(&b, tcp_connect, b.count);
    }
    if (attach_type == BPF_CGROUP_UDP6_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_udp_peer_cache_restore_v6(&b, udp_peer_map_fd);
    }
    size_t dns_hijack_jumps[2];
    size_t dns_hijack_jump_count = 0;
    emit_dns_hijack_jumps(
        &b, config, protocol, protocol_from_context, BPF_REG_5,
        dns_hijack_jumps, &dns_hijack_jump_count);
    emit_ipv6_destination_bypass(&b, bypass_jumps, &bypass_jump_count);
    emit_ipv6_cidr_bypass(
        &b, bypass_ipv6_cidr_map_fd, bypass_jumps, &bypass_jump_count);
    for (size_t i = 0; i < dns_hijack_jump_count; ++i) {
        patch_jump(&b, dns_hijack_jumps[i], b.count);
    }
    emit_redirect_update_and_rewrite_v6_by_protocol(
        &b,
        config,
        tcp_redirect_map_fd,
        udp_redirect_map_fd,
        udp_token_map_fd,
        udp_flow_map_fd,
        protocol,
        protocol_from_context,
        listen_port,
        drop_jumps,
        &drop_jump_count);
    size_t allow_label = emit_exit(&b, 1);
    size_t drop_label = emit_exit(&b, 0);

    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    for (size_t i = 0; i < allow_jump_count; ++i) {
        patch_jump(&b, allow_jumps[i], allow_label);
    }
    for (size_t i = 0; i < drop_jump_count; ++i) {
        patch_jump(&b, drop_jumps[i], drop_label);
    }

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return sb_ebpf_load_prog(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        log_error);
}

static int build_ipv4_mapped_ipv6_sock_addr_prog(
    const struct sb_ebpf_cgroup_config *config,
    uint32_t self_tgid,
    int include_uid_map_fd,
    int exclude_uid_map_fd,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_flow_map_fd,
    int udp_peer_map_fd,
    int bypass_socket_cookie_map_fd,
    int bypass_ipv4_cidr_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit_self_tgid_bypass(&b, self_tgid, bypass_jumps, &bypass_jump_count);
    emit_socket_cookie_bypass(&b, bypass_socket_cookie_map_fd, bypass_jumps, &bypass_jump_count);
    emit_inbound_network_filter(
        &b, config, protocol, protocol_from_context, bypass_jumps, &bypass_jump_count);
    emit_uid_policy_filter(
        &b, include_uid_map_fd, exclude_uid_map_fd, bypass_jumps, &bypass_jump_count);
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit_dns_off_bypass(
        &b, config, protocol, protocol_from_context, BPF_REG_5,
        bypass_jumps, &bypass_jump_count);
    emit_udp_system_service_bypass(
        &b, protocol, protocol_from_context, BPF_REG_5, bypass_jumps, &bypass_jump_count);
    if (attach_type == BPF_CGROUP_UDP6_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_udp_connected_token_restore_v6(
            &b, udp_token_map_fd, listen_port, allow_jumps, &allow_jump_count);
        emit_udp_flow_cache_restore_v6(
            &b, udp_flow_map_fd, listen_port, allow_jumps, &allow_jump_count);
    }
    (void)emit_ipv4_mapped_ipv6_branch(
        &b,
        config,
        tcp_redirect_map_fd,
        udp_redirect_map_fd,
        udp_token_map_fd,
        udp_flow_map_fd,
        udp_peer_map_fd,
        bypass_ipv4_cidr_map_fd,
        protocol,
        protocol_from_context,
        listen_port,
        attach_type,
        bypass_jumps,
        &bypass_jump_count,
        drop_jumps,
        &drop_jump_count,
        allow_jumps,
        &allow_jump_count);
    size_t allow_label = emit_exit(&b, 1);
    size_t drop_label = emit_exit(&b, 0);

    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    for (size_t i = 0; i < allow_jump_count; ++i) {
        patch_jump(&b, allow_jumps[i], allow_label);
    }
    for (size_t i = 0; i < drop_jump_count; ++i) {
        patch_jump(&b, drop_jumps[i], drop_label);
    }

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return sb_ebpf_load_prog(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        log_error);
}
