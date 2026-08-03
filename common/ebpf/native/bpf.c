// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "ebpf.h"

#include <linux/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef BPF_OBJ_NAME_LEN
#define BPF_OBJ_NAME_LEN 16
#endif

#define SB_EBPF_LOG_BUF_SIZE 65536U

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1U
#endif

#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__arm__)
#define __NR_bpf 386
#elif defined(__i386__)
#define __NR_bpf 357
#elif defined(__x86_64__)
#define __NR_bpf 321
#endif
#endif

static long sb_ebpf_bpf_sys(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

int sb_ebpf_create_map(enum bpf_map_type type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, uint32_t flags) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_flags = flags;
    return (int)sb_ebpf_bpf_sys(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int load_prog_once(
    const struct bpf_insn *insns,
    size_t insn_count,
    const char *name,
    enum bpf_prog_type prog_type,
    enum bpf_attach_type expected_attach_type,
    char *log_buf,
    uint32_t log_size,
    uint32_t log_level) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = prog_type;
    attr.insns = (uint64_t)(uintptr_t)insns;
    attr.insn_cnt = (uint32_t)insn_count;
    attr.license = (uint64_t)(uintptr_t)"GPL";
    attr.expected_attach_type = expected_attach_type;
    attr.log_buf = log_level != 0U ? (uint64_t)(uintptr_t)log_buf : 0U;
    attr.log_size = log_level != 0U ? log_size : 0U;
    attr.log_level = log_level;
    if (name != NULL) {
        snprintf(attr.prog_name, BPF_OBJ_NAME_LEN, "%s", name);
    }
    return (int)sb_ebpf_bpf_sys(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int retry_without_verifier_log(
    const struct bpf_insn *insns,
    size_t insn_count,
    const char *name,
    enum bpf_prog_type prog_type,
    enum bpf_attach_type expected_attach_type) {
    return load_prog_once(insns, insn_count, name, prog_type, expected_attach_type, NULL, 0U, 0U);
}

int sb_ebpf_load_prog(
    const struct bpf_insn *insns,
    size_t insn_count,
    const char *name,
    enum bpf_prog_type prog_type,
    enum bpf_attach_type expected_attach_type,
    bool log_error) {
    static char log_buf[SB_EBPF_LOG_BUF_SIZE];
    memset(log_buf, 0, sizeof(log_buf));
    uint32_t log_level = log_error ? 1U : 0U;
    int fd = load_prog_once(
        insns,
        insn_count,
        name,
        prog_type,
        expected_attach_type,
        log_buf,
        sizeof(log_buf),
        log_level);
    if (fd < 0 && log_error && (errno == EAGAIN || errno == ENOSPC)) {
        int log_errno = errno;
        fd = retry_without_verifier_log(
            insns,
            insn_count,
            name,
            prog_type,
            expected_attach_type);
        if (fd >= 0) return fd;
        if (errno == EAGAIN || errno == ENOSPC) {
            errno = log_errno;
        }
    }
    if (fd < 0 && log_error) {
        fprintf(
            stderr,
            "%s load failed: errno=%d (%s)\nverifier log:\n%s\n",
            name == NULL ? "bpf program" : name,
            errno,
            strerror(errno),
            log_buf);
    }
    return fd;
}

int sb_ebpf_attach_prog(int cgroup_fd, int prog_fd, enum bpf_attach_type attach_type) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.target_fd = (uint32_t)cgroup_fd;
    attr.attach_bpf_fd = (uint32_t)prog_fd;
    attr.attach_type = attach_type;
#ifdef BPF_F_ALLOW_MULTI
    attr.attach_flags = BPF_F_ALLOW_MULTI;
#else
    attr.attach_flags = 0U;
#endif
    int result = (int)sb_ebpf_bpf_sys(BPF_PROG_ATTACH, &attr, sizeof(attr));
#ifdef BPF_F_ALLOW_MULTI
    if (result != 0 && (errno == EINVAL || errno == EPERM || errno == ENOTSUP || errno == EOPNOTSUPP)) {
        memset(&attr, 0, sizeof(attr));
        attr.target_fd = (uint32_t)cgroup_fd;
        attr.attach_bpf_fd = (uint32_t)prog_fd;
        attr.attach_type = attach_type;
        attr.attach_flags = 0U;
        result = (int)sb_ebpf_bpf_sys(BPF_PROG_ATTACH, &attr, sizeof(attr));
    }
#endif
    return result;
}

int sb_ebpf_detach_prog(int cgroup_fd, int prog_fd, enum bpf_attach_type attach_type) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.target_fd = (uint32_t)cgroup_fd;
    if (prog_fd >= 0) {
        attr.attach_bpf_fd = (uint32_t)prog_fd;
    }
    attr.attach_type = attach_type;
    return (int)sb_ebpf_bpf_sys(BPF_PROG_DETACH, &attr, sizeof(attr));
}

static int sb_ebpf_prog_fd_by_id(uint32_t prog_id) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_id = prog_id;
    return (int)sb_ebpf_bpf_sys(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
}

#define SB_EBPF_MAX_QUERY_PROGS 64U

struct sb_ebpf_prog_identity {
    uint32_t id;
    uint32_t type;
    char name[BPF_OBJ_NAME_LEN];
    uint8_t tag[BPF_TAG_SIZE];
};

struct sb_ebpf_prog_snapshot_entry {
    int prog_fd;
    struct sb_ebpf_prog_identity identity;
};

struct sb_ebpf_prog_snapshot {
    enum bpf_attach_type queried_attach_type;
    uint32_t prog_count;
    struct sb_ebpf_prog_snapshot_entry entries[SB_EBPF_MAX_QUERY_PROGS];
};

static int sb_ebpf_prog_identity(
    int prog_fd,
    struct sb_ebpf_prog_identity *identity) {
    if (identity == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct bpf_prog_info info;
    memset(&info, 0, sizeof(info));
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = (uint32_t)prog_fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (uint64_t)(uintptr_t)&info;
    if (sb_ebpf_bpf_sys(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) != 0) {
        return -1;
    }
    memset(identity, 0, sizeof(*identity));
    identity->id = info.id;
    identity->type = info.type;
    memcpy(identity->name, info.name, sizeof(identity->name));
    memcpy(identity->tag, info.tag, sizeof(identity->tag));
    return 0;
}

static int sb_ebpf_query_prog_ids(
    int cgroup_fd,
    enum bpf_attach_type attach_type,
    uint32_t *prog_ids,
    uint32_t *prog_count) {
    if (prog_ids == NULL || prog_count == NULL || *prog_count == 0U) {
        errno = EINVAL;
        return -1;
    }
    uint32_t capacity = *prog_count;
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.query.target_fd = (uint32_t)cgroup_fd;
    attr.query.attach_type = attach_type;
    attr.query.prog_cnt = capacity;
    attr.query.prog_ids = (uint64_t)(uintptr_t)prog_ids;
    if (sb_ebpf_bpf_sys(BPF_PROG_QUERY, &attr, sizeof(attr)) != 0) {
        if (errno == ENOSPC || attr.query.prog_cnt > capacity) {
            errno = E2BIG;
        }
        return -1;
    }
    if (attr.query.prog_cnt > capacity) {
        errno = E2BIG;
        return -1;
    }
    *prog_count = attr.query.prog_cnt;
    return 0;
}

static void sb_ebpf_close_prog_snapshot(struct sb_ebpf_prog_snapshot *snapshot) {
    if (snapshot == NULL) return;
    for (uint32_t i = 0; i < snapshot->prog_count; ++i) {
        if (snapshot->entries[i].prog_fd >= 0) {
            close(snapshot->entries[i].prog_fd);
            snapshot->entries[i].prog_fd = -1;
        }
    }
}

static int sb_ebpf_take_prog_snapshot(
    int cgroup_fd,
    enum bpf_attach_type attach_type,
    struct sb_ebpf_prog_snapshot *snapshot) {
    if (snapshot == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    for (size_t i = 0; i < SB_EBPF_MAX_QUERY_PROGS; ++i) {
        snapshot->entries[i].prog_fd = -1;
    }
    snapshot->queried_attach_type = attach_type;

    uint32_t prog_ids[SB_EBPF_MAX_QUERY_PROGS];
    memset(prog_ids, 0, sizeof(prog_ids));
    uint32_t prog_count = SB_EBPF_MAX_QUERY_PROGS;
    if (sb_ebpf_query_prog_ids(cgroup_fd, attach_type, prog_ids, &prog_count) != 0) {
        return -1;
    }
    snapshot->prog_count = prog_count;
    for (uint32_t i = 0; i < prog_count; ++i) {
        int prog_fd = sb_ebpf_prog_fd_by_id(prog_ids[i]);
        if (prog_fd < 0) {
            int saved_errno = errno;
            sb_ebpf_close_prog_snapshot(snapshot);
            errno = saved_errno;
            return -1;
        }
        snapshot->entries[i].prog_fd = prog_fd;
        if (sb_ebpf_prog_identity(prog_fd, &snapshot->entries[i].identity) != 0) {
            int saved_errno = errno;
            sb_ebpf_close_prog_snapshot(snapshot);
            errno = saved_errno;
            return -1;
        }
        if (snapshot->entries[i].identity.id != prog_ids[i]) {
            sb_ebpf_close_prog_snapshot(snapshot);
            errno = ESTALE;
            return -1;
        }
    }
    return 0;
}

static bool sb_ebpf_prog_identity_equal(
    const struct sb_ebpf_prog_identity *left,
    const struct sb_ebpf_prog_identity *right) {
    return left->id == right->id &&
        left->type == right->type &&
        memcmp(left->name, right->name, sizeof(left->name)) == 0 &&
        memcmp(left->tag, right->tag, sizeof(left->tag)) == 0;
}

static bool sb_ebpf_prog_is_owned(const struct sb_ebpf_prog_identity *identity) {
    static const char program_prefix[] = "sb_ebpf_";
    return memcmp(identity->name, program_prefix, sizeof(program_prefix) - 1U) == 0;
}

typedef int (*sb_ebpf_detach_prog_fn)(
    int cgroup_fd,
    int prog_fd,
    enum bpf_attach_type attach_type);

static int sb_ebpf_detach_owned_snapshot_entries(
    int cgroup_fd,
    enum bpf_attach_type attach_type,
    const struct sb_ebpf_prog_snapshot *snapshot,
    sb_ebpf_detach_prog_fn detach_prog) {
    if (snapshot == NULL || detach_prog == NULL) {
        errno = EINVAL;
        return -1;
    }
    for (uint32_t i = 0; i < snapshot->prog_count; ++i) {
        if (sb_ebpf_prog_is_owned(&snapshot->entries[i].identity) &&
            detach_prog(cgroup_fd, snapshot->entries[i].prog_fd, attach_type) != 0) {
            return -1;
        }
    }
    return 0;
}

static int sb_ebpf_detach_named_for_type(int cgroup_fd, enum bpf_attach_type attach_type) {
    struct sb_ebpf_prog_snapshot first;
    struct sb_ebpf_prog_snapshot second;
    if (sb_ebpf_take_prog_snapshot(cgroup_fd, attach_type, &first) != 0) {
        return -1;
    }
    if (sb_ebpf_take_prog_snapshot(cgroup_fd, attach_type, &second) != 0) {
        int saved_errno = errno;
        sb_ebpf_close_prog_snapshot(&first);
        errno = saved_errno;
        return -1;
    }

    int result = 0;
    int saved_errno = 0;
    if (first.queried_attach_type != second.queried_attach_type ||
        first.prog_count != second.prog_count) {
        result = -1;
        saved_errno = ESTALE;
        goto done;
    }
    for (uint32_t i = 0; i < first.prog_count; ++i) {
        if (!sb_ebpf_prog_identity_equal(&first.entries[i].identity, &second.entries[i].identity)) {
            result = -1;
            saved_errno = ESTALE;
            goto done;
        }
    }
    if (sb_ebpf_detach_owned_snapshot_entries(
            cgroup_fd,
            attach_type,
            &first,
            sb_ebpf_detach_prog) != 0) {
        result = -1;
        saved_errno = errno;
        goto done;
    }

done:
    sb_ebpf_close_prog_snapshot(&second);
    sb_ebpf_close_prog_snapshot(&first);
    if (result != 0) errno = saved_errno;
    return result;
}

int sb_ebpf_detach_owned_progs(int cgroup_fd) {
    if (cgroup_fd < 0) {
        errno = EBADF;
        return -1;
    }
    const enum bpf_attach_type attach_types[] = {
        BPF_CGROUP_INET4_CONNECT,
        BPF_CGROUP_UDP4_SENDMSG,
        BPF_CGROUP_UDP4_RECVMSG,
        BPF_CGROUP_INET6_CONNECT,
        BPF_CGROUP_UDP6_SENDMSG,
        BPF_CGROUP_UDP6_RECVMSG,
        BPF_CGROUP_INET_SOCK_RELEASE,
    };
    for (size_t i = 0; i < sizeof(attach_types) / sizeof(attach_types[0]); ++i) {
        if (sb_ebpf_detach_named_for_type(cgroup_fd, attach_types[i]) != 0) {
            if (attach_types[i] == BPF_CGROUP_INET_SOCK_RELEASE &&
                (errno == EINVAL || errno == ENOTSUP || errno == EOPNOTSUPP)) {
                continue;
            }
            return -1;
        }
    }
    return 0;
}
