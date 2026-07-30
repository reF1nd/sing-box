// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "singbox_ebpf.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
/* Android NDK headers expose these map types as enums, not preprocessor macros. */
#define SB_EBPF_LRU_HASH_MAP_TYPE 9U
#define SB_EBPF_LPM_TRIE_MAP_TYPE 11U
#define SB_EBPF_HASH_MAP_TYPE 1U
#define SB_EBPF_ARRAY_MAP_TYPE 2U
#define SB_EBPF_REDIRECT_TOKEN_ATTEMPTS 4U

#define SB_EBPF_ATTACHED_CONNECT4 (1U << 0U)
#define SB_EBPF_ATTACHED_CONNECT6 (1U << 1U)
#define SB_EBPF_ATTACHED_CONNECT6_V4MAPPED (1U << 2U)
#define SB_EBPF_ATTACHED_UDP4_SENDMSG (1U << 3U)
#define SB_EBPF_ATTACHED_UDP6_SENDMSG (1U << 4U)
#define SB_EBPF_ATTACHED_UDP6_V4MAPPED_SENDMSG (1U << 5U)
#define SB_EBPF_ATTACHED_UDP4_RECVMSG (1U << 6U)
#define SB_EBPF_ATTACHED_UDP6_RECVMSG (1U << 7U)
#define SB_EBPF_ATTACHED_UDP6_V4MAPPED_RECVMSG (1U << 8U)
#define SB_EBPF_ATTACHED_SOCKET_RELEASE (1U << 9U)

#define BPF_ALU64_IMM_OP(OP, DST, IMM) ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_K, .dst_reg = DST, .imm = (int32_t)(IMM)})
#define BPF_ALU64_REG_OP(OP, DST, SRC) ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_X, .dst_reg = DST, .src_reg = SRC})
#define BPF_ALU32_IMM_OP(OP, DST, IMM) ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_K, .dst_reg = DST, .imm = (int32_t)(IMM)})
#define BPF_ALU32_REG_OP(OP, DST, SRC) ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_X, .dst_reg = DST, .src_reg = SRC})
#define BPF_MOV64_REG(DST, SRC) BPF_ALU64_REG_OP(BPF_MOV, DST, SRC)
#define BPF_MOV64_IMM(DST, IMM) BPF_ALU64_IMM_OP(BPF_MOV, DST, IMM)
#define BPF_MOV32_REG(DST, SRC) BPF_ALU32_REG_OP(BPF_MOV, DST, SRC)
#define BPF_ST_MEM(SIZE, DST, OFF, IMM) ((struct bpf_insn){.code = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, .dst_reg = DST, .off = OFF, .imm = (int32_t)(IMM)})
#define BPF_STX_MEM(SIZE, DST, SRC, OFF) ((struct bpf_insn){.code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, .dst_reg = DST, .src_reg = SRC, .off = OFF})
#define BPF_STX_XADD(SIZE, DST, SRC, OFF) ((struct bpf_insn){.code = BPF_STX | BPF_SIZE(SIZE) | BPF_XADD, .dst_reg = DST, .src_reg = SRC, .off = OFF})
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) ((struct bpf_insn){.code = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, .dst_reg = DST, .src_reg = SRC, .off = OFF})
#define BPF_JMP_IMM_OP(OP, DST, IMM, OFF) ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_K, .dst_reg = DST, .off = OFF, .imm = (int32_t)(IMM)})
#define BPF_JMP_REG_OP(OP, DST, SRC, OFF) ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_X, .dst_reg = DST, .src_reg = SRC, .off = OFF})
#define BPF_CALL_FUNC(FUNC) ((struct bpf_insn){.code = BPF_JMP | BPF_CALL, .imm = FUNC})
#define BPF_EXIT_INSN() ((struct bpf_insn){.code = BPF_JMP | BPF_EXIT})
#define BPF_ENDIAN_OP(DST, SIZE) ((struct bpf_insn){.code = BPF_ALU | BPF_END | BPF_TO_BE, .dst_reg = DST, .imm = SIZE})

enum {
    STACK_IFINDEX_KEY = -8,
    STACK_REDIRECT_KEY = -96,
    STACK_ORIGINAL_DST = -144,
    STACK_UDP_PEER_KEY = -168,
    STACK_UDP_PEER_VALUE = -192,
    STACK_SAVED_V6_LAST_WORD = -200,
    STACK_SAVED_PORT = -204,
    STACK_SAVED_V6_WORD1 = -212,
    STACK_SAVED_V6_WORD2 = -216,
    STACK_COOKIE_KEY = -232,
    STACK_UID_KEY = -240,
    STACK_BYPASS_CIDR_KEY = -272,
    STACK_STATS_KEY = -280,
};

struct bpf_builder {
    struct bpf_insn insns[2048];
    size_t count;
    bool overflow;
};

static int close_fd(int *fd) {
    if (fd == NULL || *fd < 0) return 0;
    int value = *fd;
    *fd = -1;
    return close(value);
}

static uint32_t ipv4_redirect_host_mask(uint32_t prefix_bits) {
    if (prefix_bits > 32U) return 0U;
    if (prefix_bits == 0U) return UINT32_MAX;
    if (prefix_bits == 32U) return 0U;
    return UINT32_MAX >> prefix_bits;
}

static uint32_t ipv4_redirect_prefix(const uint8_t prefix[4], uint32_t prefix_bits) {
    if (prefix == NULL || prefix_bits > 32U) return 0U;
    uint32_t address = 0U;
    memcpy(&address, prefix, sizeof(address));
    return ntohl(address) & ~ipv4_redirect_host_mask(prefix_bits);
}

static uint32_t ipv6_redirect_word(const uint8_t prefix[16], size_t offset) {
    if (prefix == NULL || offset > 12U) return 0U;
    uint32_t value = 0U;
    memcpy(&value, prefix + offset, sizeof(value));
    return value;
}

static void init_runtime(struct sb_ebpf_inbound_runtime *runtime) {
    memset(runtime, -1, sizeof(*runtime));
    runtime->attached_programs = 0U;
}

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
    const struct sb_ebpf_inbound_config *config,
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
    const struct sb_ebpf_inbound_config *config,
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
    const struct sb_ebpf_inbound_config *config,
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

static int create_redirect_map(uint32_t max_entries) {
    return sb_ebpf_create_map(
        (enum bpf_map_type)SB_EBPF_HASH_MAP_TYPE,
        sizeof(struct sb_ebpf_redirect_key),
        sizeof(struct sb_ebpf_original_dst),
        max_entries,
        0U);
}

static int create_stats_map(void) {
    return sb_ebpf_create_map(
        (enum bpf_map_type)SB_EBPF_ARRAY_MAP_TYPE,
        sizeof(uint32_t),
        sizeof(uint64_t),
        SB_EBPF_STATS_COUNT,
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

static int create_udp_token_map(uint32_t max_entries) {
    return sb_ebpf_create_map(
        (enum bpf_map_type)SB_EBPF_HASH_MAP_TYPE,
        sizeof(uint64_t),
        sizeof(struct sb_ebpf_redirect_key),
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

static void emit_zero_region(struct bpf_builder *builder, int base_off, size_t size) {
    for (size_t off = 0; off < size; off += sizeof(uint32_t)) {
        emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, (int16_t)(base_off + (int)off), 0));
    }
}

static void emit_stat_increment(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    enum sb_ebpf_stat_index index) {
    if (config->stats_map_fd < 0) return;
    emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_STATS_KEY, index));
    emit_ld_map_fd(builder, BPF_REG_1, config->stats_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_STATS_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t missing = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_MOV64_IMM(BPF_REG_1, 1));
    emit(builder, BPF_STX_XADD(BPF_DW, BPF_REG_0, BPF_REG_1, 0));
    patch_jump(builder, missing, builder->count);
}

static void emit_udp_redirect_delete_from_stack(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int udp_redirect_map_fd);

static void emit_udp_redirect_delete_from_reg(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int udp_redirect_map_fd,
    int key_reg) {
    for (size_t offset = 0; offset < sizeof(struct sb_ebpf_redirect_key); offset += sizeof(uint32_t)) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, key_reg, (int16_t)offset));
        emit(builder, BPF_STX_MEM(
            BPF_W,
            BPF_REG_10,
            BPF_REG_2,
            STACK_REDIRECT_KEY + (int)offset));
    }
    emit_udp_redirect_delete_from_stack(builder, config, udp_redirect_map_fd);
}

static void emit_udp_redirect_delete_from_stack(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int udp_redirect_map_fd) {
    emit_ld_map_fd(builder, BPF_REG_1, udp_redirect_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_REDIRECT_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_delete_elem));
    size_t delete_failed = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    emit_stat_increment(builder, config, SB_EBPF_STAT_UDP_REDIRECT_DELETES);
    patch_jump(builder, delete_failed, builder->count);
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

static void emit_original_uid(struct bpf_builder *builder) {
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_current_uid_gid));
    emit(builder, BPF_STX_MEM(
        BPF_W,
        BPF_REG_10,
        BPF_REG_0,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, uid)));
}

static void emit_udp_connected_state_reset(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
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
    emit_udp_redirect_delete_from_reg(builder, config, udp_redirect_map_fd, BPF_REG_0);
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
    const struct sb_ebpf_inbound_config *config,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    if (udp_token_map_fd < 0) {
        emit_udp_redirect_delete_from_stack(builder, config, udp_redirect_map_fd);
        emit_stat_increment(builder, config, SB_EBPF_STAT_MAP_UPDATE_FAILURES);
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
    emit_stat_increment(builder, config, SB_EBPF_STAT_MAP_UPDATE_FAILURES);
    emit_udp_redirect_delete_from_stack(builder, config, udp_redirect_map_fd);
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
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    enum sb_ebpf_stat_index entry_stat_index,
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
        (int)offsetof(struct sb_ebpf_original_dst, uid),
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
    emit_stat_increment(builder, config, SB_EBPF_STAT_MAP_UPDATE_FAILURES);
    next_jumps[(*next_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t inserted_label = builder->count;
    patch_jump(builder, inserted, inserted_label);
    emit_stat_increment(builder, config, entry_stat_index);
    success_jumps[(*success_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t collision_label = builder->count;
    for (size_t index = 0; index < collision_jump_count; ++index) {
        patch_jump(builder, collision_jumps[index], collision_label);
    }
    emit_stat_increment(builder, config, SB_EBPF_STAT_TOKEN_COLLISIONS);
    next_jumps[(*next_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
}

static void emit_ipv4_redirect_token(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    uint32_t redirect_prefix,
    uint32_t redirect_host_mask,
    int redirect_map_fd,
    enum sb_ebpf_stat_index entry_stat_index,
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
    emit(builder, BPF_LDX_MEM(
        BPF_W,
        BPF_REG_2,
        BPF_REG_10,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, uid)));
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
            STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr)));

        size_t next_jumps[8];
        size_t next_jump_count = 0;
        emit_redirect_candidate(
            builder,
            config,
            redirect_map_fd,
            entry_stat_index,
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
            emit_stat_increment(builder, config, SB_EBPF_STAT_REDIRECT_DROPS);
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
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    enum sb_ebpf_stat_index entry_stat_index,
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
        (int)offsetof(struct sb_ebpf_original_dst, uid),
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
            STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 8));
        emit(builder, BPF_STX_MEM(
            BPF_W,
            BPF_REG_10,
            BPF_REG_9,
            STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 12));

        size_t next_jumps[8];
        size_t next_jump_count = 0;
        emit_redirect_candidate(
            builder,
            config,
            redirect_map_fd,
            entry_stat_index,
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
            emit_stat_increment(builder, config, SB_EBPF_STAT_REDIRECT_DROPS);
            drop_jumps[(*drop_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        }
    }
    size_t success_label = builder->count;
    for (size_t i = 0; i < success_jump_count; ++i) {
        patch_jump(builder, success_jumps[i], success_label);
    }
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

static void emit_connected_udp_original_flag(
    struct bpf_builder *builder,
    bool connected_udp) {
    if (!connected_udp) return;
    emit(builder, BPF_ST_MEM(
        BPF_B,
        BPF_REG_10,
        STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, flags),
        SB_EBPF_ORIGINAL_DST_FLAG_CONNECTED_UDP));
}

static void emit_udp_peer_cache_update_v4(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct sb_ebpf_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, family), AF_INET));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, protocol), SB_EBPF_PROTO_UDP));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr)));

    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

static void emit_udp_peer_cache_update_v4mapped(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct sb_ebpf_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, family), AF_INET));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, protocol), SB_EBPF_PROTO_UDP));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr)));

    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

static void emit_udp_peer_cache_update_v6(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_5, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));

    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct sb_ebpf_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, family), AF_INET6));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, protocol), SB_EBPF_PROTO_UDP));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_5, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_UDP_PEER_VALUE + (int)offsetof(struct sb_ebpf_udp_peer_value, addr) + 12));

    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

static void emit_udp_peer_cache_update(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    bool ipv6,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (ipv6) {
        emit_udp_peer_cache_update_v6(builder, udp_peer_map_fd, bypass_jumps, bypass_jump_count);
    } else {
        emit_udp_peer_cache_update_v4(builder, udp_peer_map_fd, bypass_jumps, bypass_jump_count);
    }
}

static void emit_udp_peer_cache_restore_v4(
    struct bpf_builder *builder,
    int udp_peer_map_fd) {
    if (udp_peer_map_fd < 0) return;

    size_t missing_ip = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    size_t has_complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_8, 0, 0));
    patch_jump(builder, missing_ip, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, family)));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, protocol)));
    size_t wrong_proto = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr)));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, port)));

    size_t done = builder->count;
    patch_jump(builder, has_complete_peer, done);
    patch_jump(builder, no_cookie, done);
    patch_jump(builder, no_peer, done);
    patch_jump(builder, wrong_family, done);
    patch_jump(builder, wrong_proto, done);
}

static void emit_udp_peer_cache_restore_v6(
    struct bpf_builder *builder,
    int udp_peer_map_fd) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    size_t missing_addr = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    size_t has_complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_5, 0, 0));
    patch_jump(builder, missing_addr, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct sb_ebpf_udp_peer_key));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct sb_ebpf_udp_peer_key, cookie)));
    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, family)));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET6, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, protocol)));
    size_t wrong_proto = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, addr) + 12));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_5, BPF_REG_0, offsetof(struct sb_ebpf_udp_peer_value, port)));
    size_t restored_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t fallback = builder->count;
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    size_t done = builder->count;
    patch_jump(builder, restored_peer, done);
    patch_jump(builder, has_complete_peer, done);
    patch_jump(builder, no_cookie, fallback);
    patch_jump(builder, no_peer, fallback);
    patch_jump(builder, wrong_family, fallback);
    patch_jump(builder, wrong_proto, fallback);
}

static void emit_udp_connected_token_restore_v4(
    struct bpf_builder *builder,
    int udp_token_map_fd,
    uint16_t listen_port,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    if (udp_token_map_fd < 0) return;

    size_t missing_ip = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    size_t complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_8, 0, 0));
    patch_jump(builder, missing_ip, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_COOKIE_KEY));
    emit_ld_map_fd(builder, BPF_REG_1, udp_token_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_token = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_redirect_key, family)));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_redirect_key, protocol)));
    size_t wrong_protocol = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_redirect_key, redirect_addr)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip4)));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t done = builder->count;
    patch_jump(builder, complete_peer, done);
    patch_jump(builder, no_cookie, done);
    patch_jump(builder, no_token, done);
    patch_jump(builder, wrong_family, done);
    patch_jump(builder, wrong_protocol, done);
}

static void emit_udp_connected_token_restore_v6(
    struct bpf_builder *builder,
    int udp_token_map_fd,
    uint16_t listen_port,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    if (udp_token_map_fd < 0) return;

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    size_t missing_address = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    size_t complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_5, 0, 0));
    patch_jump(builder, missing_address, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_COOKIE_KEY));
    emit_ld_map_fd(builder, BPF_REG_1, udp_token_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_COOKIE_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_token = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_redirect_key, protocol)));
    size_t wrong_protocol = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SB_EBPF_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct sb_ebpf_redirect_key, family)));
    size_t ipv6_token = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, AF_INET6, 0));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_redirect_key, redirect_addr)));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6), 0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 4, 0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 8, 0xffff0000U);
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    patch_jump(builder, ipv6_token, builder->count);
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct sb_ebpf_redirect_key, redirect_addr)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_0, offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 12));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_4, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t done = builder->count;
    patch_jump(builder, complete_peer, done);
    patch_jump(builder, no_cookie, done);
    patch_jump(builder, no_token, done);
    patch_jump(builder, wrong_protocol, done);
    patch_jump(builder, wrong_family, done);
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
}

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
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    int udp_token_map_fd,
    enum sb_ebpf_stat_index entry_stat_index,
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

    emit_zero_region(builder, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct sb_ebpf_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port), listen_port));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, protocol)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr)));
    emit_connected_udp_original_flag(builder, connected_udp);
    emit_original_socket_cookie(builder, protocol == SB_EBPF_PROTO_TCP || connected_udp);
    emit_original_uid(builder);
    emit_ipv4_redirect_token(
        builder,
        config,
        redirect_prefix,
        redirect_host_mask,
        redirect_map_fd,
        entry_stat_index,
        drop_jumps,
        drop_jump_count);
    if (connected_udp) {
        emit_udp_token_update(
            builder,
            config,
            redirect_map_fd,
            udp_token_map_fd,
            drop_jumps,
            drop_jump_count);
    }

    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip4)));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(listen_port));
}

static void emit_redirect_update_and_rewrite_by_protocol(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
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
            protocol == SB_EBPF_PROTO_UDP
                ? SB_EBPF_STAT_UDP_REDIRECT_ENTRIES
                : SB_EBPF_STAT_TCP_REDIRECT_ENTRIES,
            protocol,
            false,
            listen_port,
            drop_jumps,
            drop_jump_count);
        return;
    }
    if (tcp_redirect_map_fd < 0) {
        emit_redirect_update_and_rewrite(
            builder, config, udp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_UDP_REDIRECT_ENTRIES,
            SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    if (udp_redirect_map_fd < 0) {
        emit_redirect_update_and_rewrite(
            builder, config, tcp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_TCP_REDIRECT_ENTRIES,
            SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
    size_t udp_branch = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SOCK_DGRAM, 0));
    emit_redirect_update_and_rewrite(
        builder, config, tcp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_TCP_REDIRECT_ENTRIES,
        SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
    size_t done = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    patch_jump(builder, udp_branch, builder->count);
    emit_redirect_update_and_rewrite(
        builder, config, udp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_UDP_REDIRECT_ENTRIES,
        SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
    patch_jump(builder, done, builder->count);
}

static void emit_redirect_update_and_rewrite_v6(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    int udp_token_map_fd,
    enum sb_ebpf_stat_index entry_stat_index,
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

    emit_zero_region(builder, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct sb_ebpf_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET6));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port), listen_port));
    emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr), prefix0));
    emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 4, prefix1));

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
    emit_original_socket_cookie(builder, protocol == SB_EBPF_PROTO_TCP || connected_udp);
    emit_original_uid(builder);
    emit_ipv6_redirect_token(
        builder, config, redirect_map_fd, entry_stat_index, drop_jumps, drop_jump_count);
    if (connected_udp) {
        emit_udp_token_update(
            builder,
            config,
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
}

static void emit_redirect_update_and_rewrite_v6_by_protocol(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
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
            protocol == SB_EBPF_PROTO_UDP
                ? SB_EBPF_STAT_UDP_REDIRECT_ENTRIES
                : SB_EBPF_STAT_TCP_REDIRECT_ENTRIES,
            protocol,
            false,
            listen_port,
            drop_jumps,
            drop_jump_count);
        return;
    }
    if (tcp_redirect_map_fd < 0) {
        emit_redirect_update_and_rewrite_v6(
            builder, config, udp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_UDP_REDIRECT_ENTRIES,
            SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    if (udp_redirect_map_fd < 0) {
        emit_redirect_update_and_rewrite_v6(
            builder, config, tcp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_TCP_REDIRECT_ENTRIES,
            SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
    size_t udp_branch = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SOCK_DGRAM, 0));
    emit_redirect_update_and_rewrite_v6(
        builder, config, tcp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_TCP_REDIRECT_ENTRIES,
        SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
    size_t done = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    patch_jump(builder, udp_branch, builder->count);
    emit_redirect_update_and_rewrite_v6(
        builder, config, udp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_UDP_REDIRECT_ENTRIES,
        SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
    patch_jump(builder, done, builder->count);
}

static void emit_ipv4_mapped_redirect_update_and_rewrite(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int redirect_map_fd,
    int udp_token_map_fd,
    enum sb_ebpf_stat_index entry_stat_index,
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

    emit_zero_region(builder, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct sb_ebpf_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port), listen_port));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, protocol)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_ORIGINAL_DST + (int)offsetof(struct sb_ebpf_original_dst, addr)));
    emit_connected_udp_original_flag(builder, connected_udp);
    emit_original_socket_cookie(builder, protocol == SB_EBPF_PROTO_TCP || connected_udp);
    emit_original_uid(builder);
    emit_ipv4_redirect_token(
        builder,
        config,
        redirect_prefix,
        redirect_host_mask,
        redirect_map_fd,
        entry_stat_index,
        drop_jumps,
        drop_jump_count);
    if (connected_udp) {
        emit_udp_token_update(
            builder,
            config,
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
}

static void emit_ipv4_mapped_redirect_update_and_rewrite_by_protocol(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
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
            protocol == SB_EBPF_PROTO_UDP
                ? SB_EBPF_STAT_UDP_REDIRECT_ENTRIES
                : SB_EBPF_STAT_TCP_REDIRECT_ENTRIES,
            protocol,
            false,
            listen_port,
            drop_jumps,
            drop_jump_count);
        return;
    }
    if (tcp_redirect_map_fd < 0) {
        emit_ipv4_mapped_redirect_update_and_rewrite(
            builder, config, udp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_UDP_REDIRECT_ENTRIES,
            SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    if (udp_redirect_map_fd < 0) {
        emit_ipv4_mapped_redirect_update_and_rewrite(
            builder, config, tcp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_TCP_REDIRECT_ENTRIES,
            SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
        return;
    }
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
    size_t udp_branch = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SOCK_DGRAM, 0));
    emit_ipv4_mapped_redirect_update_and_rewrite(
        builder, config, tcp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_TCP_REDIRECT_ENTRIES,
        SB_EBPF_PROTO_TCP, false, listen_port, drop_jumps, drop_jump_count);
    size_t done = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    patch_jump(builder, udp_branch, builder->count);
    emit_ipv4_mapped_redirect_update_and_rewrite(
        builder, config, udp_redirect_map_fd, udp_token_map_fd, SB_EBPF_STAT_UDP_REDIRECT_ENTRIES,
        SB_EBPF_PROTO_UDP, true, listen_port, drop_jumps, drop_jump_count);
    patch_jump(builder, done, builder->count);
}

static void emit_ipv4_mapped_redirect_from_regs(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
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
        protocol,
        protocol_from_context,
        listen_port,
        drop_jumps,
        drop_jump_count);
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
}

static bool emit_ipv4_mapped_ipv6_branch(
    struct bpf_builder *builder,
    const struct sb_ebpf_inbound_config *config,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
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
            builder, config, udp_redirect_map_fd, udp_token_map_fd, udp_peer_map_fd);
        emit_udp_peer_cache_update_v4mapped(builder, udp_peer_map_fd, bypass_jumps, bypass_jump_count);
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

static int build_ipv4_sock_addr_prog(
    const struct sb_ebpf_inbound_config *config,
    int include_uid_map_fd,
    int exclude_uid_map_fd,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_peer_map_fd,
    int bypass_socket_cookie_map_fd,
    int bypass_ipv4_cidr_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
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
            &b, config, udp_redirect_map_fd, udp_token_map_fd, udp_peer_map_fd);
        emit_udp_peer_cache_update(&b, udp_peer_map_fd, false, bypass_jumps, &bypass_jump_count);
        patch_jump(&b, tcp_connect, b.count);
    }
    if (attach_type == BPF_CGROUP_UDP4_SENDMSG && protocol == SB_EBPF_PROTO_UDP && !protocol_from_context) {
        emit_udp_connected_token_restore_v4(
            &b, udp_token_map_fd, listen_port, allow_jumps, &allow_jump_count);
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
        true);
}

static int build_ipv6_sock_addr_prog(
    const struct sb_ebpf_inbound_config *config,
    int include_uid_map_fd,
    int exclude_uid_map_fd,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_peer_map_fd,
    int bypass_socket_cookie_map_fd,
    int bypass_ipv4_cidr_map_fd,
    int bypass_ipv6_cidr_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
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
            &b, config, udp_redirect_map_fd, udp_token_map_fd, udp_peer_map_fd);
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
        true);
}

static int build_ipv4_mapped_ipv6_sock_addr_prog(
    const struct sb_ebpf_inbound_config *config,
    int include_uid_map_fd,
    int exclude_uid_map_fd,
    int tcp_redirect_map_fd,
    int udp_redirect_map_fd,
    int udp_token_map_fd,
    int udp_peer_map_fd,
    int bypass_socket_cookie_map_fd,
    int bypass_ipv4_cidr_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t listen_port,
    enum bpf_attach_type attach_type,
    const char *name) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
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
    }
    (void)emit_ipv4_mapped_ipv6_branch(
        &b,
        config,
        tcp_redirect_map_fd,
        udp_redirect_map_fd,
        udp_token_map_fd,
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
        true);
}

static int build_udp4_recvmsg_prog(
    const struct sb_ebpf_inbound_config *config,
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

    emit_zero_region(&b, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol), SB_EBPF_PROTO_UDP));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr)));

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
    const struct sb_ebpf_inbound_config *config,
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

    emit_zero_region(&b, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol), SB_EBPF_PROTO_UDP));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_5, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_5, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr)));

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

    emit_zero_region(&b, STACK_REDIRECT_KEY, sizeof(struct sb_ebpf_redirect_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, family), AF_INET6));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, protocol), SB_EBPF_PROTO_UDP));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_7, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_7, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_port)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 4));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 8));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_REDIRECT_KEY + (int)offsetof(struct sb_ebpf_redirect_key, redirect_addr) + 12));

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
    const struct sb_ebpf_inbound_config *config,
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
    emit_udp_redirect_delete_from_reg(&b, config, udp_redirect_map_fd, BPF_REG_0);
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

static int open_cgroup_path(const char *path) {
    const char *actual = path != NULL && path[0] != '\0' ? path : SB_EBPF_DEFAULT_CGROUP_PATH;
    return open(actual, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

int sb_ebpf_inbound_prepare(
	const char *cgroup_path,
	uint16_t listen_port,
	bool enable_tcp,
	bool enable_udp,
	bool enable_ipv4,
	bool enable_bypass_cidr,
	bool hijack_dns,
	const uint8_t redirect_ipv4[4],
	uint32_t redirect_ipv4_prefix_bits,
	bool enable_ipv6,
	const uint8_t redirect_ipv6[16],
	uint32_t redirect_ipv6_prefix_bits,
	uint32_t include_uid_entries,
	uint32_t exclude_uid_entries,
	struct sb_ebpf_inbound_runtime *runtime) {
    if (runtime == NULL || listen_port == 0U || (!enable_tcp && !enable_udp) ||
        (!enable_ipv4 && !enable_ipv6) ||
        include_uid_entries > SB_EBPF_MAX_POLICY_MAP_ENTRIES ||
        exclude_uid_entries > SB_EBPF_MAX_POLICY_MAP_ENTRIES ||
        (enable_ipv4 && (redirect_ipv4 == NULL ||
                         redirect_ipv4_prefix_bits < 8U ||
                         redirect_ipv4_prefix_bits > 10U)) ||
        (enable_ipv6 && (redirect_ipv6 == NULL || redirect_ipv6_prefix_bits != 64U))) {
        errno = EINVAL;
        return -1;
    }

    init_runtime(runtime);
    struct sb_ebpf_inbound_config config;
    memset(&config, 0, sizeof(config));
    config.inbound_network =
        (enable_tcp ? SB_EBPF_NETWORK_TCP : 0U) |
        (enable_udp ? SB_EBPF_NETWORK_UDP : 0U);
    config.disable_ipv4 = !enable_ipv4;
    config.hijack_dns = hijack_dns;
    if (enable_ipv4) {
        memcpy(config.redirect_ipv4_prefix, redirect_ipv4, sizeof(config.redirect_ipv4_prefix));
        config.redirect_ipv4_prefix_bits = redirect_ipv4_prefix_bits;
    }
    if (enable_ipv6) {
        memcpy(config.redirect_ipv6_prefix, redirect_ipv6, sizeof(config.redirect_ipv6_prefix));
        config.redirect_ipv6_prefix_bits = redirect_ipv6_prefix_bits;
    }
    runtime->tcp_redirect_map_fd = enable_tcp
        ? create_redirect_map(SB_EBPF_MAX_TCP_REDIRECT_MAP_ENTRIES)
        : -1;
    runtime->udp_redirect_map_fd = enable_udp
        ? create_redirect_map(SB_EBPF_MAX_UDP_REDIRECT_MAP_ENTRIES)
        : -1;
    runtime->udp_token_map_fd = enable_udp
        ? create_udp_token_map(SB_EBPF_MAX_UDP_REDIRECT_MAP_ENTRIES)
        : -1;
    runtime->stats_map_fd = create_stats_map();
    config.stats_map_fd = runtime->stats_map_fd;
    runtime->udp_peer_map_fd = enable_udp
        ? create_udp_peer_map(SB_EBPF_MAX_UDP_PEER_MAP_ENTRIES)
        : -1;
    runtime->bypass_socket_cookie_map_fd = create_bypass_socket_cookie_map(
        SB_EBPF_MAX_TCP_REDIRECT_MAP_ENTRIES);
    runtime->include_uid_map_fd = create_uid_policy_map(include_uid_entries);
    runtime->exclude_uid_map_fd = create_uid_policy_map(exclude_uid_entries);
    runtime->bypass_ipv4_cidr_map_fd = create_bypass_cidr_map(
        enable_bypass_cidr, sizeof(struct sb_ebpf_ipv4_cidr_lpm_key));
    runtime->bypass_ipv6_cidr_map_fd = create_bypass_cidr_map(
        enable_bypass_cidr, sizeof(struct sb_ebpf_ipv6_cidr_lpm_key));
    if ((enable_tcp && runtime->tcp_redirect_map_fd < 0) ||
        (enable_udp && runtime->udp_redirect_map_fd < 0) ||
        (enable_udp && (runtime->udp_token_map_fd < 0 || runtime->udp_peer_map_fd < 0)) ||
        runtime->stats_map_fd < 0 ||
        runtime->bypass_socket_cookie_map_fd < 0 ||
        (include_uid_entries > 0U && runtime->include_uid_map_fd < 0) ||
        (exclude_uid_entries > 0U && runtime->exclude_uid_map_fd < 0) ||
        (enable_bypass_cidr &&
         (runtime->bypass_ipv4_cidr_map_fd < 0 || runtime->bypass_ipv6_cidr_map_fd < 0))) {
        goto fail;
    }

    runtime->cgroup_fd = open_cgroup_path(cgroup_path);
    if (runtime->cgroup_fd < 0) {
        goto fail;
    }
    if (flock(runtime->cgroup_fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK) {
            errno = EBUSY;
        }
        goto fail;
    }
    if (sb_ebpf_detach_owned_progs(runtime->cgroup_fd) < 0) {
        goto fail;
    }

    if (enable_ipv4) {
        runtime->connect4_prog_fd = build_ipv4_sock_addr_prog(
            &config,
            runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
            runtime->tcp_redirect_map_fd,
            runtime->udp_redirect_map_fd,
            runtime->udp_token_map_fd,
            runtime->udp_peer_map_fd,
            runtime->bypass_socket_cookie_map_fd,
            runtime->bypass_ipv4_cidr_map_fd,
            SB_EBPF_PROTO_TCP,
            true,
            listen_port,
            BPF_CGROUP_INET4_CONNECT,
            "sb_ebpf_conn4");
        if (enable_udp) {
            runtime->udp4_sendmsg_prog_fd = build_ipv4_sock_addr_prog(
                &config,
                runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
                runtime->tcp_redirect_map_fd,
                runtime->udp_redirect_map_fd,
                runtime->udp_token_map_fd,
                runtime->udp_peer_map_fd,
                runtime->bypass_socket_cookie_map_fd,
                runtime->bypass_ipv4_cidr_map_fd,
                SB_EBPF_PROTO_UDP,
                false,
                listen_port,
                BPF_CGROUP_UDP4_SENDMSG,
                "sb_ebpf_udp4");
            runtime->udp4_recvmsg_prog_fd = build_udp4_recvmsg_prog(
                &config,
                runtime->udp_redirect_map_fd,
                "sb_ebpf_urcv4");
        }
    }
    if (enable_ipv6) {
        runtime->connect6_prog_fd = build_ipv6_sock_addr_prog(
            &config,
            runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
            runtime->tcp_redirect_map_fd,
            runtime->udp_redirect_map_fd,
            runtime->udp_token_map_fd,
            runtime->udp_peer_map_fd,
            runtime->bypass_socket_cookie_map_fd,
            runtime->bypass_ipv4_cidr_map_fd,
            runtime->bypass_ipv6_cidr_map_fd,
            SB_EBPF_PROTO_TCP,
            true,
            listen_port,
            BPF_CGROUP_INET6_CONNECT,
            "sb_ebpf_conn6");
        if (enable_udp) {
            runtime->udp6_sendmsg_prog_fd = build_ipv6_sock_addr_prog(
                &config,
                runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
                runtime->tcp_redirect_map_fd,
                runtime->udp_redirect_map_fd,
                runtime->udp_token_map_fd,
                runtime->udp_peer_map_fd,
                runtime->bypass_socket_cookie_map_fd,
                runtime->bypass_ipv4_cidr_map_fd,
                runtime->bypass_ipv6_cidr_map_fd,
                SB_EBPF_PROTO_UDP,
                false,
                listen_port,
                BPF_CGROUP_UDP6_SENDMSG,
                "sb_ebpf_udp6");
            runtime->udp6_recvmsg_prog_fd = build_udp6_recvmsg_prog(
                &config,
                runtime->udp_redirect_map_fd,
                "sb_ebpf_urcv6");
        }
    } else {
        runtime->connect6_v4mapped_prog_fd = build_ipv4_mapped_ipv6_sock_addr_prog(
            &config,
            runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
            runtime->tcp_redirect_map_fd,
            runtime->udp_redirect_map_fd,
            runtime->udp_token_map_fd,
            runtime->udp_peer_map_fd,
            runtime->bypass_socket_cookie_map_fd,
            runtime->bypass_ipv4_cidr_map_fd,
            SB_EBPF_PROTO_TCP,
            true,
            listen_port,
            BPF_CGROUP_INET6_CONNECT,
            "sb_ebpf_c6v4m");
        if (enable_udp) {
            runtime->udp6_v4mapped_sendmsg_prog_fd = build_ipv4_mapped_ipv6_sock_addr_prog(
                &config,
                runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
                runtime->tcp_redirect_map_fd,
                runtime->udp_redirect_map_fd,
                runtime->udp_token_map_fd,
                runtime->udp_peer_map_fd,
                runtime->bypass_socket_cookie_map_fd,
                runtime->bypass_ipv4_cidr_map_fd,
                SB_EBPF_PROTO_UDP,
                false,
                listen_port,
                BPF_CGROUP_UDP6_SENDMSG,
                "sb_ebpf_u6v4m");
            runtime->udp6_v4mapped_recvmsg_prog_fd = build_udp6_recvmsg_prog(
                &config,
                runtime->udp_redirect_map_fd,
                "sb_ebpf_ur6v4m");
        }
    }
    if (enable_udp) {
        runtime->socket_release_prog_fd = build_socket_release_prog(
            &config,
            runtime->udp_redirect_map_fd,
            runtime->udp_token_map_fd,
            runtime->udp_peer_map_fd,
            runtime->bypass_socket_cookie_map_fd,
            "sb_ebpf_rel");
    }
    if ((enable_ipv4 &&
         (runtime->connect4_prog_fd < 0 ||
          (enable_udp &&
           (runtime->udp4_sendmsg_prog_fd < 0 || runtime->udp4_recvmsg_prog_fd < 0)))) ||
        (enable_ipv6 &&
         (runtime->connect6_prog_fd < 0 ||
          (enable_udp &&
           (runtime->udp6_sendmsg_prog_fd < 0 || runtime->udp6_recvmsg_prog_fd < 0)))) ||
        (!enable_ipv6 &&
         (runtime->connect6_v4mapped_prog_fd < 0 ||
          (enable_udp &&
           (runtime->udp6_v4mapped_sendmsg_prog_fd < 0 ||
             runtime->udp6_v4mapped_recvmsg_prog_fd < 0)))) ||
        (enable_udp && runtime->socket_release_prog_fd < 0)) {
        goto fail;
    }
    return 0;

fail:
    {
        int saved = errno;
        (void)sb_ebpf_inbound_close(runtime);
        errno = saved;
    }
    return -1;
}

static int attach_runtime_program(
    struct sb_ebpf_inbound_runtime *runtime,
    int prog_fd,
    enum bpf_attach_type attach_type,
    uint32_t attached_flag) {
    if (prog_fd < 0) return 0;
    if (sb_ebpf_attach_prog(runtime->cgroup_fd, prog_fd, attach_type) < 0) return -1;
    runtime->attached_programs |= attached_flag;
    return 0;
}

int sb_ebpf_inbound_attach(struct sb_ebpf_inbound_runtime *runtime) {
    if (runtime == NULL || runtime->cgroup_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (runtime->attached_programs != 0U) {
        errno = EALREADY;
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
        (void)sb_ebpf_inbound_close(runtime);
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
    struct sb_ebpf_inbound_runtime *runtime,
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

int sb_ebpf_inbound_close(struct sb_ebpf_inbound_runtime *runtime) {
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
    close_runtime_fd(&runtime->udp_token_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->stats_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->udp_redirect_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->tcp_redirect_map_fd, &result, &saved_errno);
    close_runtime_fd(&runtime->cgroup_fd, &result, &saved_errno);
    if (result != 0) errno = saved_errno;
    return result;
}
