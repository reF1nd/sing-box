// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Included by cgroup_program.c. Destination policy and address rewrite emitters.

static void emit_ipv4_destination_bypass(
    struct bpf_builder *builder,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 32));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_2));
    emit(builder, BPF_ALU64_IMM_OP(BPF_RSH, BPF_REG_3, 24));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 127, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JGE, BPF_REG_3, 224, 0));
}

static void emit_udp_system_service_bypass(
    struct bpf_builder *builder,
    uint8_t protocol,
    bool protocol_from_context,
    int port_reg,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    size_t not_udp = 0;
    if (protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        not_udp = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    } else if (protocol != SB_EBPF_PROTO_UDP) {
        return;
    }
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, port_reg, htons(67), 0));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, port_reg, htons(68), 0));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, port_reg, htons(546), 0));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, port_reg, htons(547), 0));
    if (protocol_from_context) {
        patch_jump(builder, not_udp, builder->count);
    }
}

static void emit_ipv4_mapped_ipv6_check_jumps(
    struct bpf_builder *builder,
    size_t *not_mapped_jumps,
    size_t *not_mapped_jump_count) {
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    not_mapped_jumps[(*not_mapped_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    not_mapped_jumps[(*not_mapped_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 32));
    not_mapped_jumps[(*not_mapped_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0x0000ffffU, 0));
}

static void emit_ipv6_destination_bypass(
    struct bpf_builder *builder,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    size_t not_zero_or_loopback = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_4));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_3, 32));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 1, 0));
    patch_jump(builder, not_zero_or_loopback, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 32));
    emit(builder, BPF_ALU64_IMM_OP(BPF_RSH, BPF_REG_2, 24));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0xff, 0));

}

static void emit_redirect_update_and_rewrite(
    struct bpf_builder *builder,
    const struct sb_ebpf_cgroup_config *config,
    int redirect_map_fd,
    int udp_token_map_fd,
    int udp_flow_map_fd,
    uint8_t protocol,
    bool connected_udp,
    uint16_t listen_port,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    uint32_t redirect_prefix = ipv4_redirect_prefix(
        config->redirect_ipv4_prefix,
        config->redirect_ipv4_prefix_bits);
    uint32_t redirect_host_mask = ipv4_redirect_host_mask(config->redirect_ipv4_prefix_bits);
    emit(builder, BPF_MOV64_IMM(BPF_REG_5, protocol));

    emit_zero_region(builder, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_listener_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct sb_ebpf_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, listener_port), listen_port));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, protocol)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr)));
    emit_connected_udp_original_flag(builder, connected_udp);
    emit_original_socket_cookie(
        builder,
        protocol == SB_EBPF_PROTO_TCP || connected_udp || udp_flow_map_fd >= 0);
    emit_ipv4_redirect_token(
        builder,
        redirect_prefix,
        redirect_host_mask,
        redirect_map_fd,
        drop_jumps,
        drop_jump_count);
    if (connected_udp) {
        emit_udp_token_update(
            builder,
            redirect_map_fd,
            udp_token_map_fd,
            drop_jumps,
            drop_jump_count);
    }
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip4)));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
    if (protocol == SB_EBPF_PROTO_UDP && !connected_udp) {
        emit_udp_flow_cache_update(builder, udp_flow_map_fd);
    }
}

static void emit_redirect_update_and_rewrite_by_protocol(
    struct bpf_builder *builder,
    const struct sb_ebpf_cgroup_config *config,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_flow_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    if (!protocol_from_context) {
        emit_redirect_update_and_rewrite(
            builder,
            config,
            protocol == SB_EBPF_PROTO_UDP ? udp_redirect_map_fd : tcp_redirect_map_fd,
            udp_token_map_fd,
            udp_flow_map_fd,
            protocol,
            false,
            listen_port,
            drop_jumps,
            drop_jump_count);
        return;
    }
    if (tcp_redirect_map_fd < 0) {
        emit_redirect_update_and_rewrite(
            builder, config, udp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
            SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    if (udp_redirect_map_fd < 0) {
        emit_redirect_update_and_rewrite(
            builder, config, tcp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
            SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
    size_t udp_branch = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SOCK_DGRAM, 0));
    emit_redirect_update_and_rewrite(
        builder, config, tcp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
        SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
    size_t done = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    patch_jump(builder, udp_branch, builder->count);
    emit_redirect_update_and_rewrite(
        builder, config, udp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
        SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
    patch_jump(builder, done, builder->count);
}

static void emit_redirect_update_and_rewrite_v6(
    struct bpf_builder *builder,
    const struct sb_ebpf_cgroup_config *config,
    int redirect_map_fd,
    int udp_token_map_fd,
    int udp_flow_map_fd,
    uint8_t protocol,
    bool connected_udp,
    uint16_t listen_port,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    uint32_t prefix0 = ipv6_redirect_word(config->redirect_ipv6_prefix, 0U);
    uint32_t prefix1 = ipv6_redirect_word(config->redirect_ipv6_prefix, 4U);

    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_SAVED_V6_LAST_WORD));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_5, STACK_SAVED_PORT));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_SAVED_V6_WORD1));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_SAVED_V6_WORD2));

    emit(builder, BPF_MOV64_IMM(BPF_REG_5, protocol));

    emit_zero_region(builder, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_listener_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct sb_ebpf_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, family), AF_INET6));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, listener_port), listen_port));
    emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, token_addr), prefix0));
    emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, token_addr) + 4, prefix1));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, family), AF_INET6));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, protocol)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, STACK_SAVED_PORT));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_4, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_4, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, port)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, STACK_SAVED_V6_LAST_WORD));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, STACK_SAVED_V6_WORD1));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, STACK_SAVED_V6_WORD2));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr) + 12));
    emit_connected_udp_original_flag(builder, connected_udp);
    emit_original_socket_cookie(
        builder,
        protocol == SB_EBPF_PROTO_TCP || connected_udp || udp_flow_map_fd >= 0);
    emit_ipv6_redirect_token(
        builder, redirect_map_fd, drop_jumps, drop_jump_count);
    if (connected_udp) {
        emit_udp_token_update(
            builder,
            redirect_map_fd,
            udp_token_map_fd,
            drop_jumps,
            drop_jump_count);
    }
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6), prefix0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 4, prefix1);
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
    if (protocol == SB_EBPF_PROTO_UDP && !connected_udp) {
        emit_udp_flow_cache_update(builder, udp_flow_map_fd);
    }
}

static void emit_redirect_update_and_rewrite_v6_by_protocol(
    struct bpf_builder *builder,
    const struct sb_ebpf_cgroup_config *config,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_flow_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    if (!protocol_from_context) {
        emit_redirect_update_and_rewrite_v6(
            builder,
            config,
            protocol == SB_EBPF_PROTO_UDP ? udp_redirect_map_fd : tcp_redirect_map_fd,
            udp_token_map_fd,
            udp_flow_map_fd,
            protocol,
            false,
            listen_port,
            drop_jumps,
            drop_jump_count);
        return;
    }
    if (tcp_redirect_map_fd < 0) {
        emit_redirect_update_and_rewrite_v6(
            builder, config, udp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
            SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    if (udp_redirect_map_fd < 0) {
        emit_redirect_update_and_rewrite_v6(
            builder, config, tcp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
            SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
    size_t udp_branch = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SOCK_DGRAM, 0));
    emit_redirect_update_and_rewrite_v6(
        builder, config, tcp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
        SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
    size_t done = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    patch_jump(builder, udp_branch, builder->count);
    emit_redirect_update_and_rewrite_v6(
        builder, config, udp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
        SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
    patch_jump(builder, done, builder->count);
}

static void emit_ipv4_mapped_redirect_update_and_rewrite(
    struct bpf_builder *builder,
    const struct sb_ebpf_cgroup_config *config,
    int redirect_map_fd,
    int udp_token_map_fd,
    int udp_flow_map_fd,
    uint8_t protocol,
    bool connected_udp,
    uint16_t listen_port,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    uint32_t redirect_prefix = ipv4_redirect_prefix(
        config->redirect_ipv4_prefix,
        config->redirect_ipv4_prefix_bits);
    uint32_t redirect_host_mask = ipv4_redirect_host_mask(config->redirect_ipv4_prefix_bits);
    emit(builder, BPF_MOV64_IMM(BPF_REG_5, protocol));

    emit_zero_region(builder, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_listener_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct sb_ebpf_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, listener_port), listen_port));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, protocol)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr)));
    emit_connected_udp_original_flag(builder, connected_udp);
    emit_original_socket_cookie(
        builder,
        protocol == SB_EBPF_PROTO_TCP || connected_udp || udp_flow_map_fd >= 0);
    emit_ipv4_redirect_token(
        builder,
        redirect_prefix,
        redirect_host_mask,
        redirect_map_fd,
        drop_jumps,
        drop_jump_count);
    if (connected_udp) {
        emit_udp_token_update(
            builder,
            redirect_map_fd,
            udp_token_map_fd,
            drop_jumps,
            drop_jump_count);
    }
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6), 0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 4, 0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 8, 0xffff0000U);
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
    if (protocol == SB_EBPF_PROTO_UDP && !connected_udp) {
        emit_udp_flow_cache_update(builder, udp_flow_map_fd);
    }
}

static void emit_ipv4_mapped_redirect_update_and_rewrite_by_protocol(
    struct bpf_builder *builder,
    const struct sb_ebpf_cgroup_config *config,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_flow_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    if (!protocol_from_context) {
        emit_ipv4_mapped_redirect_update_and_rewrite(
            builder,
            config,
            protocol == SB_EBPF_PROTO_UDP ? udp_redirect_map_fd : tcp_redirect_map_fd,
            udp_token_map_fd,
            udp_flow_map_fd,
            protocol,
            false,
            listen_port,
            drop_jumps,
            drop_jump_count);
        return;
    }
    if (tcp_redirect_map_fd < 0) {
        emit_ipv4_mapped_redirect_update_and_rewrite(
            builder, config, udp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
            SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    if (udp_redirect_map_fd < 0) {
        emit_ipv4_mapped_redirect_update_and_rewrite(
            builder, config, tcp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
            SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
    size_t udp_branch = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SOCK_DGRAM, 0));
    emit_ipv4_mapped_redirect_update_and_rewrite(
        builder, config, tcp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
        SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
    size_t done = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    patch_jump(builder, udp_branch, builder->count);
    emit_ipv4_mapped_redirect_update_and_rewrite(
        builder, config, udp_redirect_map_fd, udp_token_map_fd, udp_flow_map_fd,
        SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
    patch_jump(builder, done, builder->count);
}

static void emit_ipv4_mapped_redirect_from_regs(
    struct bpf_builder *builder,
    const struct sb_ebpf_cgroup_config *config,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_flow_map_fd,
    int bypass_ipv4_cidr_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    size_t *bypass_jumps,
    size_t *bypass_jump_count,
    size_t *drop_jumps,
    size_t *drop_jump_count,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    emit_udp_flow_cache_restore_v4mapped(
        builder,
        protocol == SB_EBPF_PROTO_UDP && !protocol_from_context ? udp_flow_map_fd : -1,
        listen_port,
        allow_jumps,
        allow_jump_count);
    size_t dns_hijack_jumps[2];
    size_t dns_hijack_jump_count = 0;
    emit_dns_hijack_jumps(
        builder,
        config,
        protocol,
        protocol_from_context,
        BPF_REG_8,
        dns_hijack_jumps,
        &dns_hijack_jump_count);
    emit_ipv4_destination_bypass(builder, bypass_jumps, bypass_jump_count);
    emit_ipv4_cidr_bypass(
        builder, bypass_ipv4_cidr_map_fd, BPF_REG_7, bypass_jumps, bypass_jump_count);
    for (size_t i = 0; i < dns_hijack_jump_count; ++i) {
        patch_jump(builder, dns_hijack_jumps[i], builder->count);
    }
    emit_ipv4_mapped_redirect_update_and_rewrite_by_protocol(
        builder,
        config,
        tcp_redirect_map_fd,
        udp_redirect_map_fd,
        udp_token_map_fd,
        udp_flow_map_fd,
        protocol,
        protocol_from_context,
        listen_port,
        drop_jumps,
        drop_jump_count);
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
}

static bool emit_ipv4_mapped_ipv6_branch(
    struct bpf_builder *builder,
    const struct sb_ebpf_cgroup_config *config,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_flow_map_fd,
    int udp_peer_map_fd,
    int bypass_ipv4_cidr_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    size_t *bypass_jumps,
    size_t *bypass_jump_count,
    size_t *drop_jumps,
    size_t *drop_jump_count,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    size_t continue_jumps[8];
    size_t continue_jump_count = 0;
    size_t mapped_jumps[2];
    size_t mapped_jump_count = 0;

    if (attach_type == BPF_CGROUP_UDP6_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_ipv4_mapped_ipv6_check_jumps(builder, continue_jumps, &continue_jump_count);
        emit(builder, BPF_MOV64_REG(BPF_REG_7, BPF_REG_4));
        emit(builder, BPF_MOV64_REG(BPF_REG_8, BPF_REG_5));
        mapped_jumps[mapped_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        for (size_t i = 0; i < continue_jump_count; ++i) {
            patch_jump(builder, continue_jumps[i], builder->count);
        }
        continue_jump_count = 0;

        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
        emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
        emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
        emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_7, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_8, 0));
        emit_udp_peer_cache_restore_v4(builder, udp_peer_map_fd);
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, 0, 0));
        mapped_jumps[mapped_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    } else if (attach_type == BPF_CGROUP_INET6_CONNECT && protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_2));
        size_t tcp_connect = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SB_EBPF_PROTO_TCP, 0));
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
        patch_jump(builder, tcp_connect, builder->count);
        emit_ipv4_mapped_ipv6_check_jumps(builder, continue_jumps, &continue_jump_count);
        emit(builder, BPF_MOV64_REG(BPF_REG_7, BPF_REG_4));
        emit(builder, BPF_MOV64_REG(BPF_REG_8, BPF_REG_5));
        size_t tcp_destination = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, SB_EBPF_PROTO_TCP, 0));
        emit_udp_connected_state_reset(
            builder, udp_redirect_map_fd, udp_token_map_fd, udp_peer_map_fd);
        emit_udp_peer_cache_update_v4(
            builder,
            udp_peer_map_fd,
            (int)offsetof(struct bpf_sock_addr, user_ip6) + 12,
            bypass_jumps,
            bypass_jump_count);
        patch_jump(builder, tcp_destination, builder->count);
    } else {
        return false;
    }

    size_t mapped_label = builder->count;
    for (size_t i = 0; i < mapped_jump_count; ++i) {
        patch_jump(builder, mapped_jumps[i], mapped_label);
    }
    emit_ipv4_mapped_redirect_from_regs(
        builder,
        config,
        tcp_redirect_map_fd,
        udp_redirect_map_fd,
        udp_token_map_fd,
        udp_flow_map_fd,
        bypass_ipv4_cidr_map_fd,
        protocol,
        protocol_from_context,
        listen_port,
        bypass_jumps,
        bypass_jump_count,
        drop_jumps,
        drop_jump_count,
        allow_jumps,
        allow_jump_count);
    size_t continue_label = builder->count;
    for (size_t i = 0; i < continue_jump_count; ++i) {
        patch_jump(builder, continue_jumps[i], continue_label);
    }
    return true;
}
