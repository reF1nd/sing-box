// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "runtime.h"

#include <errno.h>
#include <stddef.h>

struct shared_network_map_context {
    int control_map_fd;
    int original_to_token_map_fd;
    int bypass_flow_map_fd;
    int reply_map_fd;
    int listener_map_fd;
    int fragment_map_fd;
    int host_ipv4_map_fd;
    int host_ipv6_map_fd;
    int include_source_ipv4_map_fd;
    int include_source_ipv6_map_fd;
    int exclude_source_ipv4_map_fd;
    int exclude_source_ipv6_map_fd;
    int include_source_mac_map_fd;
    int exclude_source_mac_map_fd;
    int bypass_ipv4_map_fd;
    int bypass_ipv6_map_fd;
    int scratch_map_fd;
};

static int shared_network_object_map_fd(const char *name, void *context) {
    static const struct sb_ebpf_map_binding bindings[] = {
#define MAP_BINDING(NAME, FIELD) {NAME, offsetof(struct shared_network_map_context, FIELD)}
        MAP_BINDING("shared_control", control_map_fd),
        MAP_BINDING("shared_original_to_token", original_to_token_map_fd),
        MAP_BINDING("shared_bypass_flow", bypass_flow_map_fd),
        MAP_BINDING("shared_reply", reply_map_fd),
        MAP_BINDING("shared_listener", listener_map_fd),
        MAP_BINDING("shared_fragment", fragment_map_fd),
        MAP_BINDING("shared_host_ipv4", host_ipv4_map_fd),
        MAP_BINDING("shared_host_ipv6", host_ipv6_map_fd),
        MAP_BINDING("shared_include_source_ipv4", include_source_ipv4_map_fd),
        MAP_BINDING("shared_include_source_ipv6", include_source_ipv6_map_fd),
        MAP_BINDING("shared_exclude_source_ipv4", exclude_source_ipv4_map_fd),
        MAP_BINDING("shared_exclude_source_ipv6", exclude_source_ipv6_map_fd),
        MAP_BINDING("shared_include_source_mac", include_source_mac_map_fd),
        MAP_BINDING("shared_exclude_source_mac", exclude_source_mac_map_fd),
        MAP_BINDING("shared_bypass_ipv4", bypass_ipv4_map_fd),
        MAP_BINDING("shared_bypass_ipv6", bypass_ipv6_map_fd),
        MAP_BINDING("shared_scratch", scratch_map_fd),
#undef MAP_BINDING
    };
    return sb_ebpf_resolve_map_fd(
        name,
        context,
        bindings,
        sizeof(bindings) / sizeof(bindings[0]));
}

struct shared_network_program_definition {
    const char *section;
    const char *name;
    size_t fd_offset;
};

static const struct shared_network_program_definition shared_network_programs[] = {
    {"classifier/ingress", "sb_share_in",
     offsetof(struct sb_ebpf_shared_network_runtime, ingress_prog_fd)},
    {"classifier/egress", "sb_share_out",
     offsetof(struct sb_ebpf_shared_network_runtime, egress_prog_fd)},
};

int sb_ebpf_load_shared_network_programs(
    const uint8_t *object,
    size_t object_size,
    int bypass_ipv4_map_fd,
    int bypass_ipv6_map_fd,
    struct sb_ebpf_shared_network_runtime *runtime) {
    if (object == NULL || object_size == 0U || runtime == NULL ||
        bypass_ipv4_map_fd < 0 || bypass_ipv6_map_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct shared_network_map_context map_context = {
        .control_map_fd = runtime->control_map_fd,
        .original_to_token_map_fd = runtime->original_to_token_map_fd,
        .bypass_flow_map_fd = runtime->bypass_flow_map_fd,
        .reply_map_fd = runtime->reply_map_fd,
        .listener_map_fd = runtime->listener_map_fd,
        .fragment_map_fd = runtime->fragment_map_fd,
        .host_ipv4_map_fd = runtime->host_ipv4_map_fd,
        .host_ipv6_map_fd = runtime->host_ipv6_map_fd,
        .include_source_ipv4_map_fd = runtime->include_source_ipv4_map_fd,
        .include_source_ipv6_map_fd = runtime->include_source_ipv6_map_fd,
        .exclude_source_ipv4_map_fd = runtime->exclude_source_ipv4_map_fd,
        .exclude_source_ipv6_map_fd = runtime->exclude_source_ipv6_map_fd,
        .include_source_mac_map_fd = runtime->include_source_mac_map_fd,
        .exclude_source_mac_map_fd = runtime->exclude_source_mac_map_fd,
        .bypass_ipv4_map_fd = bypass_ipv4_map_fd,
        .bypass_ipv6_map_fd = bypass_ipv6_map_fd,
        .scratch_map_fd = runtime->scratch_map_fd,
    };
    for (size_t index = 0U;
         index < sizeof(shared_network_programs) / sizeof(shared_network_programs[0]);
         ++index) {
        const struct shared_network_program_definition *definition =
            &shared_network_programs[index];
        int *program_fd = (int *)((uint8_t *)runtime + definition->fd_offset);
        const struct sb_ebpf_program_descriptor program = {
            definition->name,
            BPF_PROG_TYPE_SCHED_CLS,
            (enum bpf_attach_type)0,
            program_fd,
        };
        *program_fd = sb_ebpf_load_object_program(
            object,
            object_size,
            definition->section,
            &program,
            shared_network_object_map_fd,
            &map_context,
            true);
        if (*program_fd < 0) {
            sb_ebpf_set_error_stage(runtime->error_stage, definition->name);
            return -1;
        }
    }
    return 0;
}
