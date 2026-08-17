// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_BPF_COMPAT_H
#define SING_BOX_EBPF_BPF_COMPAT_H

#include <linux/types.h>
#include <stdbool.h>

#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline))
#define NOINLINE static __attribute__((noinline))

/* Legacy map definitions keep the objects usable without kernel BTF/CO-RE. */
struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

#endif
