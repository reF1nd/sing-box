// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Included by cgroup.c to keep the native cgroup backend in one translation unit.

#include "cgroup_program_emit.c"
#include "cgroup_program_udp.c"
#include "cgroup_program_redirect.c"
#include "cgroup_program_sockaddr.c"
#include "cgroup_program_recvmsg.c"

static bool runtime_has_programs(const struct sb_ebpf_cgroup_runtime *runtime) {
    return runtime->connect4_prog_fd >= 0 || runtime->connect6_prog_fd >= 0 ||
        runtime->connect6_v4mapped_prog_fd >= 0 || runtime->udp4_sendmsg_prog_fd >= 0 ||
        runtime->udp6_sendmsg_prog_fd >= 0 || runtime->udp6_v4mapped_sendmsg_prog_fd >= 0 ||
        runtime->udp4_recvmsg_prog_fd >= 0 || runtime->udp6_recvmsg_prog_fd >= 0 ||
        runtime->udp6_v4mapped_recvmsg_prog_fd >= 0 || runtime->socket_release_prog_fd >= 0;
}

static void close_runtime_programs(struct sb_ebpf_cgroup_runtime *runtime) {
    (void)close_fd(&runtime->socket_release_prog_fd);
    (void)close_fd(&runtime->udp6_v4mapped_recvmsg_prog_fd);
    (void)close_fd(&runtime->udp6_recvmsg_prog_fd);
    (void)close_fd(&runtime->udp4_recvmsg_prog_fd);
    (void)close_fd(&runtime->udp6_v4mapped_sendmsg_prog_fd);
    (void)close_fd(&runtime->udp6_sendmsg_prog_fd);
    (void)close_fd(&runtime->udp4_sendmsg_prog_fd);
    (void)close_fd(&runtime->connect6_v4mapped_prog_fd);
    (void)close_fd(&runtime->connect6_prog_fd);
    (void)close_fd(&runtime->connect4_prog_fd);
}

static int load_cgroup_program_set(
    struct sb_ebpf_cgroup_runtime *runtime,
    uint16_t listen_port,
    uint32_t self_tgid,
    bool enable_ipv4,
    bool hijack_dns,
    const uint8_t redirect_ipv4[4],
    uint32_t redirect_ipv4_prefix_bits,
    bool enable_ipv6,
    const uint8_t redirect_ipv6[16],
    uint32_t redirect_ipv6_prefix_bits,
    bool log_error) {
    if (runtime == NULL || runtime->cgroup_fd < 0 || listen_port == 0U ||
        (!enable_ipv4 && !enable_ipv6) ||
        (enable_ipv4 && (redirect_ipv4 == NULL ||
                         redirect_ipv4_prefix_bits < 8U ||
                         redirect_ipv4_prefix_bits > 10U)) ||
        (enable_ipv6 && (redirect_ipv6 == NULL || redirect_ipv6_prefix_bits != 64U))) {
        errno = EINVAL;
        return -1;
    }
    if (runtime_has_programs(runtime)) {
        errno = EALREADY;
        return -1;
    }

    bool enable_tcp = runtime->tcp_redirect_map_fd >= 0;
    bool enable_udp = runtime->udp_redirect_map_fd >= 0;
    int sockaddr_bypass_socket_cookie_map_fd = self_tgid == 0U
        ? runtime->bypass_socket_cookie_map_fd
        : -1;
    struct sb_ebpf_cgroup_config config;
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

    if (enable_ipv4) {
        runtime->connect4_prog_fd = build_ipv4_sock_addr_prog(
            &config,
            self_tgid,
            runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
            runtime->tcp_redirect_map_fd,
            runtime->udp_redirect_map_fd,
            runtime->udp_token_map_fd,
            runtime->udp_flow_map_fd,
            runtime->udp_peer_map_fd,
            sockaddr_bypass_socket_cookie_map_fd,
            runtime->bypass_ipv4_cidr_map_fd,
            SB_EBPF_PROTO_TCP,
            true,
            listen_port,
            BPF_CGROUP_INET4_CONNECT,
            "sb_ebpf_conn4",
            log_error);
        if (enable_udp) {
            runtime->udp4_sendmsg_prog_fd = build_ipv4_sock_addr_prog(
                &config,
                self_tgid,
                runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
                runtime->tcp_redirect_map_fd,
                runtime->udp_redirect_map_fd,
                runtime->udp_token_map_fd,
                runtime->udp_flow_map_fd,
                runtime->udp_peer_map_fd,
                sockaddr_bypass_socket_cookie_map_fd,
                runtime->bypass_ipv4_cidr_map_fd,
                SB_EBPF_PROTO_UDP,
                false,
                listen_port,
                BPF_CGROUP_UDP4_SENDMSG,
                "sb_ebpf_udp4",
                log_error);
            runtime->udp4_recvmsg_prog_fd = build_udp4_recvmsg_prog(
                &config,
                runtime->udp_redirect_map_fd,
                "sb_ebpf_urcv4");
        }
    }
    if (enable_ipv6) {
        runtime->connect6_prog_fd = build_ipv6_sock_addr_prog(
            &config,
            self_tgid,
            runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
            runtime->tcp_redirect_map_fd,
            runtime->udp_redirect_map_fd,
            runtime->udp_token_map_fd,
            runtime->udp_flow_map_fd,
            runtime->udp_peer_map_fd,
            sockaddr_bypass_socket_cookie_map_fd,
            runtime->bypass_ipv4_cidr_map_fd,
            runtime->bypass_ipv6_cidr_map_fd,
            SB_EBPF_PROTO_TCP,
            true,
            listen_port,
            BPF_CGROUP_INET6_CONNECT,
            "sb_ebpf_conn6",
            log_error);
        if (enable_udp) {
            runtime->udp6_sendmsg_prog_fd = build_ipv6_sock_addr_prog(
                &config,
                self_tgid,
                runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
                runtime->tcp_redirect_map_fd,
                runtime->udp_redirect_map_fd,
                runtime->udp_token_map_fd,
                runtime->udp_flow_map_fd,
                runtime->udp_peer_map_fd,
                sockaddr_bypass_socket_cookie_map_fd,
                runtime->bypass_ipv4_cidr_map_fd,
                runtime->bypass_ipv6_cidr_map_fd,
                SB_EBPF_PROTO_UDP,
                false,
                listen_port,
                BPF_CGROUP_UDP6_SENDMSG,
                "sb_ebpf_udp6",
                log_error);
            runtime->udp6_recvmsg_prog_fd = build_udp6_recvmsg_prog(
                &config,
                runtime->udp_redirect_map_fd,
                "sb_ebpf_urcv6");
        }
    } else {
        runtime->connect6_v4mapped_prog_fd = build_ipv4_mapped_ipv6_sock_addr_prog(
            &config,
            self_tgid,
            runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
            runtime->tcp_redirect_map_fd,
            runtime->udp_redirect_map_fd,
            runtime->udp_token_map_fd,
            runtime->udp_flow_map_fd,
            runtime->udp_peer_map_fd,
            sockaddr_bypass_socket_cookie_map_fd,
            runtime->bypass_ipv4_cidr_map_fd,
            SB_EBPF_PROTO_TCP,
            true,
            listen_port,
            BPF_CGROUP_INET6_CONNECT,
            "sb_ebpf_c6v4m",
            log_error);
        if (enable_udp) {
            runtime->udp6_v4mapped_sendmsg_prog_fd = build_ipv4_mapped_ipv6_sock_addr_prog(
                &config,
                self_tgid,
                runtime->include_uid_map_fd, runtime->exclude_uid_map_fd,
                runtime->tcp_redirect_map_fd,
                runtime->udp_redirect_map_fd,
                runtime->udp_token_map_fd,
                runtime->udp_flow_map_fd,
                runtime->udp_peer_map_fd,
                sockaddr_bypass_socket_cookie_map_fd,
                runtime->bypass_ipv4_cidr_map_fd,
                SB_EBPF_PROTO_UDP,
                false,
                listen_port,
                BPF_CGROUP_UDP6_SENDMSG,
                "sb_ebpf_u6v4m",
                log_error);
            runtime->udp6_v4mapped_recvmsg_prog_fd = build_udp6_recvmsg_prog(
                &config,
                runtime->udp_redirect_map_fd,
                "sb_ebpf_ur6v4m");
        }
    }
    if (enable_udp && runtime->socket_release_supported) {
        runtime->socket_release_prog_fd = build_socket_release_prog(
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
        (enable_udp && runtime->socket_release_supported &&
         runtime->socket_release_prog_fd < 0)) {
        goto load_fail;
    }
    return 0;

load_fail:
    {
        int saved = errno;
        close_runtime_programs(runtime);
        errno = saved;
    }
    return -1;
}

int sb_ebpf_cgroup_load_programs(
    struct sb_ebpf_cgroup_runtime *runtime,
    uint16_t listen_port,
    uint32_t self_tgid,
    bool enable_ipv4,
    bool hijack_dns,
    const uint8_t redirect_ipv4[4],
    uint32_t redirect_ipv4_prefix_bits,
    bool enable_ipv6,
    const uint8_t redirect_ipv6[16],
    uint32_t redirect_ipv6_prefix_bits) {
    bool try_tgid = self_tgid != 0U;
    if (load_cgroup_program_set(
            runtime,
            listen_port,
            self_tgid,
            enable_ipv4,
            hijack_dns,
            redirect_ipv4,
            redirect_ipv4_prefix_bits,
            enable_ipv6,
            redirect_ipv6,
            redirect_ipv6_prefix_bits,
            !try_tgid) == 0) {
        runtime->self_bypass_tgid = try_tgid;
        return 0;
    }
    if (try_tgid && load_cgroup_program_set(
            runtime,
            listen_port,
            0U,
            enable_ipv4,
            hijack_dns,
            redirect_ipv4,
            redirect_ipv4_prefix_bits,
            enable_ipv6,
            redirect_ipv6,
            redirect_ipv6_prefix_bits,
            true) == 0) {
        runtime->self_bypass_tgid = false;
        return 0;
    }
    int saved = errno;
    (void)sb_ebpf_cgroup_close(runtime);
    errno = saved;
    return -1;
}
