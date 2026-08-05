// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "ebpf.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
/* Android NDK headers expose these map types as enums, not preprocessor macros. */
#define SB_EBPF_LRU_HASH_MAP_TYPE 9U
#define SB_EBPF_LPM_TRIE_MAP_TYPE 11U
#define SB_EBPF_HASH_MAP_TYPE 1U
#define SB_EBPF_ARRAY_MAP_TYPE 2U
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
#define BPF_MOV64_IMM(DST, IMM) BPF_ALU64_IMM_OP(BPF_MOV, DST, IMM)
#define BPF_EXIT_INSN() ((struct bpf_insn){.code = BPF_JMP | BPF_EXIT})

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

static void init_runtime(struct sb_ebpf_cgroup_runtime *runtime) {
    memset(runtime, -1, sizeof(*runtime));
    runtime->error_stage[0] = '\0';
    runtime->socket_release_supported = false;
    runtime->self_bypass_tgid = false;
    runtime->enable_tcp = false;
    runtime->enable_udp = false;
    runtime->include_uid_policy = false;
    runtime->exclude_uid_policy = false;
    runtime->bypass_ipv4_policy = false;
    runtime->bypass_ipv6_policy = false;
    runtime->auto_ipv6 = false;
    runtime->socket_bypass_map_capacity = 0U;
    runtime->attached_programs = 0U;
}

static int create_bypass_socket_cookie_map(uint32_t max_entries);

#include "cgroup_program.c"
#include "cgroup_runtime.c"
