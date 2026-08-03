// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "ebpf.h"

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
    STACK_UDP_FLOW_KEY = -304,
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

static void init_runtime(struct sb_ebpf_cgroup_runtime *runtime) {
    memset(runtime, -1, sizeof(*runtime));
    runtime->socket_release_supported = false;
    runtime->self_bypass_tgid = false;
    runtime->attached_programs = 0U;
}

#include "cgroup_program.c"
#include "cgroup_runtime.c"
