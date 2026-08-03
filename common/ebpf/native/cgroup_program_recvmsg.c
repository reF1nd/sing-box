// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Included by cgroup_program.c. UDP recvmsg, socket-release, and compatibility builders.

static int build_udp4_recvmsg_prog(
    const struct sb_ebpf_cgroup_config *config,
    int udp_redirect_map_fd,
    const char *name) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[8];
    size_t bypass_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));

    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_2, 32));
    uint32_t redirect_host_mask = ipv4_redirect_host_mask(config->redirect_ipv4_prefix_bits);
    uint32_t redirect_network_mask = ~redirect_host_mask;
    uint32_t redirect_prefix = ipv4_redirect_prefix(
        config->redirect_ipv4_prefix,
        config->redirect_ipv4_prefix_bits);
    emit(&b, BPF_ALU64_IMM_OP(BPF_AND, BPF_REG_2, redirect_network_mask));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, redirect_prefix, 0));

    emit_zero_region(&b, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_listener_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, family), AF_INET));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, protocol), SB_EBPF_PROTO_UDP));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, listener_port)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, token_addr)));

    emit_ld_map_fd(&b, BPF_REG_1, udp_redirect_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr)));
    emit(&b, BPF_LDX_MEM(BPF_H, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_port)));

    size_t allow_label = emit_exit(&b, 1);
    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
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
        BPF_CGROUP_UDP4_RECVMSG,
        true);
}

static int build_udp6_recvmsg_prog(
    const struct sb_ebpf_cgroup_config *config,
    int udp_redirect_map_fd,
    const char *name) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[8];
    size_t bypass_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit_ipv4_mapped_ipv6_check_jumps(&b, bypass_jumps, &bypass_jump_count);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_4));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_2, 32));
    uint32_t redirect_host_mask = ipv4_redirect_host_mask(config->redirect_ipv4_prefix_bits);
    uint32_t redirect_network_mask = ~redirect_host_mask;
    uint32_t redirect_prefix = ipv4_redirect_prefix(
        config->redirect_ipv4_prefix,
        config->redirect_ipv4_prefix_bits);
    emit(&b, BPF_ALU64_IMM_OP(BPF_AND, BPF_REG_2, redirect_network_mask));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, redirect_prefix, 0));

    emit_zero_region(&b, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_listener_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, family), AF_INET));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, protocol), SB_EBPF_PROTO_UDP));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_5, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, listener_port)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, token_addr)));

    emit_ld_map_fd(&b, BPF_REG_1, udp_redirect_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr)));
    emit(&b, BPF_LDX_MEM(BPF_H, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit_ctx_st32(&b, offsetof(struct bpf_sock_addr, user_ip6), 0);
    emit_ctx_st32(&b, offsetof(struct bpf_sock_addr, user_ip6) + 4, 0);
    emit_ctx_st32(&b, offsetof(struct bpf_sock_addr, user_ip6) + 8, 0xffff0000U);
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_port)));
    size_t v4mapped_allow = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t ipv6_lookup_label = b.count;
    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], ipv6_lookup_label);
    }
    bypass_jump_count = 0;

    emit_zero_region(&b, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_listener_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, family), AF_INET6));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, protocol), SB_EBPF_PROTO_UDP));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_7, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_7, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, listener_port)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, token_addr)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, token_addr) + 4));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, token_addr) + 8));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, token_addr) + 12));

    emit_ld_map_fd(&b, BPF_REG_1, udp_redirect_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, addr) + 12));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_4, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_original_dst, port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_7, 16));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_port)));

    size_t allow_label = emit_exit(&b, 1);
    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    patch_jump(&b, v4mapped_allow, allow_label);

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return sb_ebpf_load_prog(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        BPF_CGROUP_UDP6_RECVMSG,
        true);
}

static int build_socket_release_prog(
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_peer_map_fd,
    int bypass_socket_cookie_map_fd,
    const char *name) {
    if (udp_redirect_map_fd < 0 || udp_token_map_fd < 0 || udp_peer_map_fd < 0) {
        errno = EINVAL;
        return -1;
    }

    struct bpf_builder b = {0};
    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit(&b, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(&b, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_COOKIE_KEY));

    emit_ld_map_fd(&b, BPF_REG_1, udp_token_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_token = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_udp_redirect_delete_from_reg(&b, udp_redirect_map_fd, BPF_REG_0);
    patch_jump(&b, no_token, b.count);

    emit_ld_map_fd(&b, BPF_REG_1, udp_token_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_delete_elem));
    emit_ld_map_fd(&b, BPF_REG_1, udp_peer_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_delete_elem));
    if (bypass_socket_cookie_map_fd >= 0) {
        emit_ld_map_fd(&b, BPF_REG_1, bypass_socket_cookie_map_fd);
        emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
        emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_delete_elem));
    }

    size_t allow_label = emit_exit(&b, 1);
    patch_jump(&b, no_cookie, allow_label);
    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return sb_ebpf_load_prog(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK,
        BPF_CGROUP_INET_SOCK_RELEASE,
        true);
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
        if (close(fd) != 0) return -1;
        return 1;
    }
    if (errno == EINVAL || errno == ENOTSUP || errno == EOPNOTSUPP) {
        errno = 0;
        return 0;
    }
    return -1;
}
