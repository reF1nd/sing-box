// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Included by cgroup_program.c. Generic instruction, policy, and token emitters.

static void emit(struct bpf_builder *builder, struct bpf_insn insn) {
    if (builder->count < ARRAY_SIZE(builder->insns)) {
        builder->insns[builder->count++] = insn;
    } else {
        builder->overflow = true;
    }
}

static size_t emit_jump(struct bpf_builder *builder, struct bpf_insn insn) {
    size_t index = builder->count;
    emit(builder, insn);
    return index;
}

static void patch_jump(struct bpf_builder *builder, size_t jump_index, size_t target_index) {
    if (jump_index >= ARRAY_SIZE(builder->insns) || target_index <= jump_index ||
        target_index - jump_index - 1U > INT16_MAX) {
        builder->overflow = true;
        return;
    }
    builder->insns[jump_index].off = (int16_t)(target_index - jump_index - 1U);
}

static void emit_ld_map_fd(struct bpf_builder *builder, int dst_reg, int map_fd) {
    emit(builder, (struct bpf_insn){
        .code = BPF_LD | BPF_DW | BPF_IMM,
        .dst_reg = (uint8_t)dst_reg,
        .src_reg = BPF_PSEUDO_MAP_FD,
        .imm = map_fd,
    });
    emit(builder, (struct bpf_insn){.code = 0, .imm = 0});
}

static void emit_ctx_st32(struct bpf_builder *builder, int offset, uint32_t imm) {
    emit(builder, BPF_MOV64_IMM(BPF_REG_0, imm));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, offset));
}

static size_t emit_exit(struct bpf_builder *builder, int result) {
    size_t label = builder->count;
    emit(builder, BPF_MOV64_IMM(BPF_REG_0, result));
    emit(builder, BPF_EXIT_INSN());
    return label;
}

static void emit_inbound_network_filter(
    struct bpf_builder *builder,
    const struct sb_ebpf_cgroup_config *config,
    uint8_t protocol,
    bool protocol_from_context,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    uint8_t network = config->inbound_network;
    if (network == SB_EBPF_NETWORK_BOTH) return;
    if (protocol_from_context) {
        uint8_t allowed_protocol = network == SB_EBPF_NETWORK_TCP
            ? SB_EBPF_PROTO_TCP
            : SB_EBPF_PROTO_UDP;
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        bypass_jumps[(*bypass_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, allowed_protocol, 0));
    } else if ((protocol == SB_EBPF_PROTO_TCP && !(network & SB_EBPF_NETWORK_TCP)) ||
               (protocol == SB_EBPF_PROTO_UDP && !(network & SB_EBPF_NETWORK_UDP))) {
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    }
}

static void emit_dns_port_jumps(
    struct bpf_builder *builder,
    uint8_t protocol,
    bool protocol_from_context,
    int port_reg,
    size_t *target_jumps,
    size_t *target_jump_count) {
    if (!protocol_from_context) {
        if (protocol == SB_EBPF_PROTO_TCP || protocol == SB_EBPF_PROTO_UDP) {
            target_jumps[(*target_jump_count)++] =
                emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, port_reg, htons(53), 0));
        }
        return;
    }

    emit(builder, BPF_LDX_MEM(
        BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
    size_t tcp = emit_jump(
        builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SB_EBPF_PROTO_TCP, 0));
    size_t other = emit_jump(
        builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    patch_jump(builder, tcp, builder->count);
    target_jumps[(*target_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, port_reg, htons(53), 0));
    patch_jump(builder, other, builder->count);
}

static void emit_dns_off_bypass(
    struct bpf_builder *builder,
    const struct sb_ebpf_cgroup_config *config,
    uint8_t protocol,
    bool protocol_from_context,
    int port_reg,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (config->hijack_dns) return;
    emit_dns_port_jumps(
        builder,
        protocol,
        protocol_from_context,
        port_reg,
        bypass_jumps,
        bypass_jump_count);
}

static void emit_dns_hijack_jumps(
    struct bpf_builder *builder,
    const struct sb_ebpf_cgroup_config *config,
    uint8_t protocol,
    bool protocol_from_context,
    int port_reg,
    size_t *hijack_jumps,
    size_t *hijack_jump_count) {
    if (!config->hijack_dns) return;
    emit_dns_port_jumps(
        builder,
        protocol,
        protocol_from_context,
        port_reg,
        hijack_jumps,
        hijack_jump_count);
}

static void emit_zero_region(struct bpf_builder *builder, int base_off, size_t size) {
    for (size_t off = 0; off < size; off += sizeof(uint32_t)) {
        emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, (int16_t)(base_off + (int)off), 0));
    }
}

static void emit_udp_redirect_delete_from_stack(
    struct bpf_builder *builder,
    int udp_redirect_map_fd);

static void emit_udp_redirect_delete_from_reg(
    struct bpf_builder *builder,
    int udp_redirect_map_fd,
    int key_reg) {
    for (size_t offset = 0; offset < sizeof(struct sb_ebpf_listener_key); offset += sizeof(uint32_t)) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, key_reg, (int16_t)offset));
        emit(builder, BPF_STX_MEM(
            BPF_W,
            BPF_REG_10,
            BPF_REG_2,
            STACK_REDIRECT_KEY + (int)offset));
    }
    emit_udp_redirect_delete_from_stack(builder, udp_redirect_map_fd);
}

static void emit_udp_redirect_delete_from_stack(
    struct bpf_builder *builder,
    int udp_redirect_map_fd) {
    emit_ld_map_fd(builder, BPF_REG_1, udp_redirect_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_delete_elem));
}

static void emit_original_socket_cookie(
    struct bpf_builder *builder,
    bool enabled) {
    if (!enabled) return;
    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    emit(builder, BPF_STX_MEM(
        BPF_DW,
        BPF_REG_10,
        BPF_REG_0,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, socket_cookie)));
}

static void emit_udp_connected_state_reset(
    struct bpf_builder *builder,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_peer_map_fd) {
    if (udp_redirect_map_fd < 0 || udp_token_map_fd < 0) return;

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_COOKIE_KEY));

    emit_ld_map_fd(builder, BPF_REG_1, udp_token_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_token = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_udp_redirect_delete_from_reg(builder, udp_redirect_map_fd, BPF_REG_0);
    patch_jump(builder, no_token, builder->count);

    emit_ld_map_fd(builder, BPF_REG_1, udp_token_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_delete_elem));
    if (udp_peer_map_fd >= 0) {
        emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_delete_elem));
    }
    patch_jump(builder, no_cookie, builder->count);
}

static void emit_udp_token_update(
    struct bpf_builder *builder,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    if (udp_token_map_fd < 0) {
        emit_udp_redirect_delete_from_stack(builder, udp_redirect_map_fd);
        drop_jumps[(*drop_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        return;
    }

    emit(builder, BPF_LDX_MEM(
        BPF_DW,
        BPF_REG_2,
        BPF_REG_10,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, socket_cookie)));
    size_t missing_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, STACK_COOKIE_KEY));
    emit_ld_map_fd(builder, BPF_REG_1, udp_token_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_REDIRECT_KEY));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
    size_t updated = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    size_t failure_label = builder->count;
    patch_jump(builder, missing_cookie, failure_label);
    emit_udp_redirect_delete_from_stack(builder, udp_redirect_map_fd);
    drop_jumps[(*drop_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    patch_jump(builder, updated, builder->count);
}

static void emit_mix32(struct bpf_builder *builder, int value_reg, int temp_reg) {
    emit(builder, BPF_MOV32_REG(temp_reg, value_reg));
    emit(builder, BPF_ALU32_IMM_OP(BPF_RSH, temp_reg, 16));
    emit(builder, BPF_ALU32_REG_OP(BPF_XOR, value_reg, temp_reg));
    emit(builder, BPF_ALU32_IMM_OP(BPF_MUL, value_reg, 0x7feb352dU));
    emit(builder, BPF_MOV32_REG(temp_reg, value_reg));
    emit(builder, BPF_ALU32_IMM_OP(BPF_RSH, temp_reg, 15));
    emit(builder, BPF_ALU32_REG_OP(BPF_XOR, value_reg, temp_reg));
    emit(builder, BPF_ALU32_IMM_OP(BPF_MUL, value_reg, 0x846ca68bU));
    emit(builder, BPF_MOV32_REG(temp_reg, value_reg));
    emit(builder, BPF_ALU32_IMM_OP(BPF_RSH, temp_reg, 16));
    emit(builder, BPF_ALU32_REG_OP(BPF_XOR, value_reg, temp_reg));
}

static void emit_redirect_candidate(
    struct bpf_builder *builder,
    int redirect_map_fd,
    bool ipv6,
    size_t *next_jumps,
    size_t *next_jump_count,
    size_t *success_jumps,
    size_t *success_jump_count) {
    emit_ld_map_fd(builder, BPF_REG_1, redirect_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t missing = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    size_t collision_jumps[sizeof(struct sb_ebpf_original_dst) / sizeof(uint32_t)];
    size_t collision_jump_count = 0;
    const int ipv4_offsets[] = {
        0,
        (int)offsetof(struct sb_ebpf_original_dst, addr),
        (int)offsetof(struct sb_ebpf_original_dst, flags),
        (int)offsetof(struct sb_ebpf_original_dst, socket_cookie),
        (int)offsetof(struct sb_ebpf_original_dst, socket_cookie) + 4,
    };
    size_t compare_count = ipv6
        ? sizeof(struct sb_ebpf_original_dst) / sizeof(uint32_t)
        : ARRAY_SIZE(ipv4_offsets);
    for (size_t index = 0; index < compare_count; ++index) {
        int offset = ipv6 ? (int)(index * sizeof(uint32_t)) : ipv4_offsets[index];
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_0, (int16_t)offset));
        emit(builder, BPF_LDX_MEM(
            BPF_W,
            BPF_REG_3,
            BPF_REG_10,
            STACK_ORIGINAL_DST + (int)offset));
        collision_jumps[collision_jump_count++] =
            emit_jump(builder, BPF_JMP_REG_OP(BPF_JNE, BPF_REG_2, BPF_REG_3, 0));
    }
    success_jumps[(*success_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    patch_jump(builder, missing, builder->count);
    emit_ld_map_fd(builder, BPF_REG_1, redirect_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_ORIGINAL_DST));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_NOEXIST));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
    size_t inserted = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    next_jumps[(*next_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t inserted_label = builder->count;
    patch_jump(builder, inserted, inserted_label);
    success_jumps[(*success_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t collision_label = builder->count;
    for (size_t index = 0; index < collision_jump_count; ++index) {
        patch_jump(builder, collision_jumps[index], collision_label);
    }
    next_jumps[(*next_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
}

static void emit_ipv4_redirect_token(
    struct bpf_builder *builder,
    uint32_t redirect_prefix,
    uint32_t redirect_host_mask,
    int redirect_map_fd,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    emit(builder, BPF_MOV32_REG(BPF_REG_8, BPF_REG_7));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, STACK_ORIGINAL_DST));
    emit(builder, BPF_ALU32_REG_OP(BPF_XOR, BPF_REG_8, BPF_REG_2));
    emit(builder, BPF_LDX_MEM(
        BPF_W,
        BPF_REG_2,
        BPF_REG_10,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, flags)));
    emit(builder, BPF_ALU32_REG_OP(BPF_XOR, BPF_REG_8, BPF_REG_2));
    emit(builder, BPF_LDX_MEM(
        BPF_W,
        BPF_REG_2,
        BPF_REG_10,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, socket_cookie)));
    emit(builder, BPF_ALU32_REG_OP(BPF_XOR, BPF_REG_8, BPF_REG_2));
    emit(builder, BPF_LDX_MEM(
        BPF_W,
        BPF_REG_2,
        BPF_REG_10,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, socket_cookie) + 4));
    emit(builder, BPF_ALU32_REG_OP(BPF_XOR, BPF_REG_8, BPF_REG_2));
    emit_mix32(builder, BPF_REG_8, BPF_REG_2);

    size_t success_jumps[SB_EBPF_REDIRECT_TOKEN_ATTEMPTS * 2U];
    size_t success_jump_count = 0;
    for (size_t attempt = 0; attempt < SB_EBPF_REDIRECT_TOKEN_ATTEMPTS; ++attempt) {
        emit(builder, BPF_MOV32_REG(BPF_REG_9, BPF_REG_8));
        emit(builder, BPF_ALU32_IMM_OP(BPF_AND, BPF_REG_9, redirect_host_mask));
        emit(builder, BPF_ALU32_IMM_OP(BPF_OR, BPF_REG_9, redirect_prefix));
        emit(builder, BPF_ENDIAN_OP(BPF_REG_9, 32));
        emit(builder, BPF_STX_MEM(
            BPF_W,
            BPF_REG_10,
            BPF_REG_9,
            STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, token_addr)));

        size_t next_jumps[8];
        size_t next_jump_count = 0;
        emit_redirect_candidate(
            builder,
            redirect_map_fd,
            false,
            next_jumps,
            &next_jump_count,
            success_jumps,
            &success_jump_count);
        size_t next_label = builder->count;
        for (size_t i = 0; i < next_jump_count; ++i) {
            patch_jump(builder, next_jumps[i], next_label);
        }
        if (attempt + 1U < SB_EBPF_REDIRECT_TOKEN_ATTEMPTS) {
            emit(builder, BPF_ALU32_IMM_OP(BPF_ADD, BPF_REG_8, 0x9e3779b9U));
        } else {
            drop_jumps[(*drop_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        }
    }
    size_t success_label = builder->count;
    for (size_t i = 0; i < success_jump_count; ++i) {
        patch_jump(builder, success_jumps[i], success_label);
    }
}

static void emit_ipv6_redirect_token(
    struct bpf_builder *builder,
    int redirect_map_fd,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_10, STACK_ORIGINAL_DST));
    emit(builder, BPF_LDX_MEM(
        BPF_W,
        BPF_REG_9,
        BPF_REG_10,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr) + 4));
    const int seed8_offsets[] = {
        (int)offsetof(struct sb_ebpf_original_dst, addr),
        (int)offsetof(struct sb_ebpf_original_dst, addr) + 8,
        (int)offsetof(struct sb_ebpf_original_dst, flags),
        (int)offsetof(struct sb_ebpf_original_dst, socket_cookie),
    };
    const int seed9_offsets[] = {
        (int)offsetof(struct sb_ebpf_original_dst, addr) + 12,
        0,
        (int)offsetof(struct sb_ebpf_original_dst, socket_cookie) + 4,
    };
    for (size_t i = 0; i < ARRAY_SIZE(seed8_offsets); ++i) {
        emit(builder, BPF_LDX_MEM(
            BPF_W,
            BPF_REG_2,
            BPF_REG_10,
            STACK_ORIGINAL_DST + seed8_offsets[i]));
        emit(builder, BPF_ALU32_REG_OP(BPF_XOR, BPF_REG_8, BPF_REG_2));
    }
    for (size_t i = 0; i < ARRAY_SIZE(seed9_offsets); ++i) {
        emit(builder, BPF_LDX_MEM(
            BPF_W,
            BPF_REG_2,
            BPF_REG_10,
            STACK_ORIGINAL_DST + seed9_offsets[i]));
        emit(builder, BPF_ALU32_REG_OP(BPF_XOR, BPF_REG_9, BPF_REG_2));
    }
    emit(builder, BPF_ALU32_IMM_OP(BPF_XOR, BPF_REG_9, 0x85ebca6bU));
    emit_mix32(builder, BPF_REG_8, BPF_REG_2);
    emit_mix32(builder, BPF_REG_9, BPF_REG_2);

    size_t success_jumps[SB_EBPF_REDIRECT_TOKEN_ATTEMPTS * 2U];
    size_t success_jump_count = 0;
    for (size_t attempt = 0; attempt < SB_EBPF_REDIRECT_TOKEN_ATTEMPTS; ++attempt) {
        emit(builder, BPF_STX_MEM(
            BPF_W,
            BPF_REG_10,
            BPF_REG_8,
            STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, token_addr) + 8));
        emit(builder, BPF_STX_MEM(
            BPF_W,
            BPF_REG_10,
            BPF_REG_9,
            STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_listener_key, token_addr) + 12));

        size_t next_jumps[8];
        size_t next_jump_count = 0;
        emit_redirect_candidate(
            builder,
            redirect_map_fd,
            true,
            next_jumps,
            &next_jump_count,
            success_jumps,
            &success_jump_count);
        size_t next_label = builder->count;
        for (size_t i = 0; i < next_jump_count; ++i) {
            patch_jump(builder, next_jumps[i], next_label);
        }
        if (attempt + 1U < SB_EBPF_REDIRECT_TOKEN_ATTEMPTS) {
            emit(builder, BPF_ALU32_IMM_OP(BPF_ADD, BPF_REG_8, 0x9e3779b9U));
            emit(builder, BPF_ALU32_IMM_OP(BPF_ADD, BPF_REG_9, 0x7f4a7c15U));
        } else {
            drop_jumps[(*drop_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        }
    }
    size_t success_label = builder->count;
    for (size_t i = 0; i < success_jump_count; ++i) {
        patch_jump(builder, success_jumps[i], success_label);
    }
}

static void emit_self_tgid_bypass(
    struct bpf_builder *builder,
    uint32_t self_tgid,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (self_tgid == 0U) return;

    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_current_pid_tgid));
    emit(builder, BPF_ALU64_IMM_OP(BPF_RSH, BPF_REG_0, 32));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, self_tgid, 0));
}

static void emit_socket_cookie_bypass(
    struct bpf_builder *builder,
    int bypass_socket_cookie_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (bypass_socket_cookie_map_fd < 0) return;

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_COOKIE_KEY));
    emit_ld_map_fd(builder, BPF_REG_1, bypass_socket_cookie_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    patch_jump(builder, no_cookie, builder->count);
}

static void emit_uid_policy_filter(
    struct bpf_builder *builder,
    int include_uid_map_fd,
    int exclude_uid_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (include_uid_map_fd < 0 && exclude_uid_map_fd < 0) return;

    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_current_uid_gid));
    emit(builder, BPF_MOV32_REG(BPF_REG_2, BPF_REG_0));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 32));
    emit(builder, BPF_ST_MEM(
        BPF_W,
        BPF_REG_10,
        STACK_UID_KEY + (int)offsetof(struct sb_ebpf_uid_lpm_key, prefixlen),
        32));
    emit(builder, BPF_STX_MEM(
        BPF_W,
        BPF_REG_10,
        BPF_REG_2,
        STACK_UID_KEY + (int)offsetof(struct sb_ebpf_uid_lpm_key, uid)));

    if (exclude_uid_map_fd >= 0) {
        emit_ld_map_fd(builder, BPF_REG_1, exclude_uid_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UID_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    }
    if (include_uid_map_fd >= 0) {
        emit_ld_map_fd(builder, BPF_REG_1, include_uid_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UID_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    }
}

static void emit_ipv4_cidr_bypass(
    struct bpf_builder *builder,
    int bypass_ipv4_cidr_map_fd,
    int address_reg,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (bypass_ipv4_cidr_map_fd < 0) return;

    emit_zero_region(builder, STACK_BYPASS_CIDR_KEY, sizeof(struct sb_ebpf_ipv4_cidr_lpm_key));
    emit(builder, BPF_ST_MEM(
        BPF_W,
        BPF_REG_10,
        STACK_BYPASS_CIDR_KEY + (int)offsetof(struct sb_ebpf_ipv4_cidr_lpm_key, prefixlen),
        32));
    emit(builder, BPF_STX_MEM(
        BPF_W,
        BPF_REG_10,
        address_reg,
        STACK_BYPASS_CIDR_KEY + (int)offsetof(struct sb_ebpf_ipv4_cidr_lpm_key, addr)));
    emit_ld_map_fd(builder, BPF_REG_1, bypass_ipv4_cidr_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_BYPASS_CIDR_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
}

static void emit_ipv6_cidr_bypass(
    struct bpf_builder *builder,
    int bypass_ipv6_cidr_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (bypass_ipv6_cidr_map_fd < 0) return;

    emit_zero_region(builder, STACK_BYPASS_CIDR_KEY, sizeof(struct sb_ebpf_ipv6_cidr_lpm_key));
    emit(builder, BPF_ST_MEM(
        BPF_W,
        BPF_REG_10,
        STACK_BYPASS_CIDR_KEY + (int)offsetof(struct sb_ebpf_ipv6_cidr_lpm_key, prefixlen),
        128));
    emit(builder, BPF_STX_MEM(
        BPF_W, BPF_REG_10, BPF_REG_7,
        STACK_BYPASS_CIDR_KEY + (int)offsetof(struct sb_ebpf_ipv6_cidr_lpm_key, addr)));
    emit(builder, BPF_STX_MEM(
        BPF_W, BPF_REG_10, BPF_REG_8,
        STACK_BYPASS_CIDR_KEY + (int)offsetof(struct sb_ebpf_ipv6_cidr_lpm_key, addr) + 4));
    emit(builder, BPF_STX_MEM(
        BPF_W, BPF_REG_10, BPF_REG_9,
        STACK_BYPASS_CIDR_KEY + (int)offsetof(struct sb_ebpf_ipv6_cidr_lpm_key, addr) + 8));
    emit(builder, BPF_STX_MEM(
        BPF_W, BPF_REG_10, BPF_REG_4,
        STACK_BYPASS_CIDR_KEY + (int)offsetof(struct sb_ebpf_ipv6_cidr_lpm_key, addr) + 12));
    emit_ld_map_fd(builder, BPF_REG_1, bypass_ipv6_cidr_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_BYPASS_CIDR_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(
        BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(
        BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
}
