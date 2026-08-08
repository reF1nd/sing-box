// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Experimental cgroup backend implemented as BPF C. The production
// testing-ref1nd branch retains the hand-written instruction emitter.

#include "abi.h"

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <stdbool.h>

#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline))
#define BPF_NOEXIST 1U
#define AF_INET_VALUE 2U
#define AF_INET6_VALUE 10U
#define TCP_VALUE 6U
#define UDP_VALUE 17U
#define REDIRECT_TOKEN_ATTEMPTS 4U

enum flow_cache_result {
    FLOW_CACHE_MISS,
    FLOW_CACHE_BYPASS,
    FLOW_CACHE_PROXY,
};

enum cgroup_protocol_mode {
    CGROUP_PROTOCOL_AUTO,
    CGROUP_PROTOCOL_TCP_ONLY,
    CGROUP_PROTOCOL_UDP_ONLY,
};

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

#define MAP(name, key, value, map_type) \
    struct bpf_map_def SEC("maps") name = { \
        .type = map_type, .key_size = sizeof(key), .value_size = sizeof(value), \
        .max_entries = 1U, \
    }

MAP(cgroup_control, __u32, struct sb_ebpf_cgroup_control, BPF_MAP_TYPE_ARRAY);
MAP(cgroup_tcp_redirect, struct sb_ebpf_listener_key, struct sb_ebpf_original_dst, BPF_MAP_TYPE_HASH);
MAP(cgroup_udp_redirect, struct sb_ebpf_listener_key, struct sb_ebpf_original_dst, BPF_MAP_TYPE_HASH);
MAP(cgroup_udp_token, __u64, struct sb_ebpf_listener_key, BPF_MAP_TYPE_HASH);
MAP(cgroup_udp_peer, struct sb_ebpf_udp_peer_key, struct sb_ebpf_udp_peer_value, BPF_MAP_TYPE_HASH);
MAP(cgroup_udp_flow, struct sb_ebpf_udp_flow_key, struct sb_ebpf_udp_flow_value, BPF_MAP_TYPE_LRU_HASH);
MAP(cgroup_socket_bypass, __u64, __u8, BPF_MAP_TYPE_LRU_HASH);
MAP(cgroup_uid_policy, struct sb_ebpf_uid_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE);
MAP(cgroup_bypass_ipv4, struct sb_ebpf_ipv4_cidr_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE);
MAP(cgroup_bypass_ipv6, struct sb_ebpf_ipv6_cidr_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE);
MAP(cgroup_ipv6_available, __u32, __u32, BPF_MAP_TYPE_ARRAY);

static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *map, const void *key, const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*get_socket_cookie)(void *ctx) = (void *)BPF_FUNC_get_socket_cookie;
static __u64 (*get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static __u64 (*ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

INLINE __u16 swap16(__u16 value) { return __builtin_bswap16(value); }
INLINE __u32 swap32(__u32 value) { return __builtin_bswap32(value); }

INLINE const struct sb_ebpf_cgroup_control *control(void) {
    __u32 key = 0U;
    return map_lookup(&cgroup_control, &key);
}

INLINE bool is_tgid_self(const struct sb_ebpf_cgroup_control *config) {
    if (config->self_tgid == 0U) return false;
    return ((__u32)(get_current_pid_tgid() >> 32)) == config->self_tgid;
}

INLINE bool is_cookie_bypassed(void *ctx) {
    __u64 cookie = get_socket_cookie(ctx);
    if (cookie == 0U) return false;
    return map_lookup(&cgroup_socket_bypass, &cookie) != 0;
}

INLINE bool uid_bypassed(const struct sb_ebpf_cgroup_control *config) {
    if ((config->flags & (SB_EBPF_CGROUP_FLAG_UID_POLICY |
        SB_EBPF_CGROUP_FLAG_EXCLUDE_ANDROID_DNS_TETHER)) == 0U) return false;
    __u32 uid = swap32((__u32)get_current_uid_gid());
    if ((config->flags & SB_EBPF_CGROUP_FLAG_EXCLUDE_ANDROID_DNS_TETHER) != 0U &&
        uid == SB_EBPF_ANDROID_DNS_TETHER_UID) return true;
    if ((config->flags & SB_EBPF_CGROUP_FLAG_UID_POLICY) == 0U) return false;
    struct sb_ebpf_uid_lpm_key key = {
        .prefixlen = 32U,
    };
    __builtin_memcpy(key.uid, &uid, sizeof(uid));
    bool matched = map_lookup(&cgroup_uid_policy, &key) != 0;
    return (config->flags & SB_EBPF_CGROUP_FLAG_UID_DEFAULT_BYPASS) != 0U
        ? !matched
        : matched;
}

INLINE bool protocol_selected(const struct sb_ebpf_cgroup_control *config, __u8 protocol) {
    if (protocol == TCP_VALUE) return (config->flags & SB_EBPF_CGROUP_FLAG_TCP) != 0U;
    if (protocol == UDP_VALUE) return (config->flags & SB_EBPF_CGROUP_FLAG_UDP) != 0U;
    return false;
}

INLINE bool service_port(__u8 protocol, __u16 port) {
    if (protocol != UDP_VALUE) return false;
    return port == 67U || port == 68U || port == 546U || port == 547U;
}

INLINE bool ipv4_destination_bypassed(__u32 address) {
    __u32 host = swap32(address);
    __u8 first = host >> 24;
    return host == 0U || first == 127U || first >= 224U;
}

INLINE bool ipv6_destination_bypassed(const __u32 address[4]) {
    if ((address[0] | address[1] | address[2] | address[3]) == 0U) return true;
    if (address[0] == 0U && address[1] == 0U && address[2] == 0U &&
        (swap32(address[3]) == 1U || (swap32(address[3]) >> 24) == 0xffU)) {
        return true;
    }
    return (swap32(address[0]) >> 24) == 0xffU;
}

INLINE bool ipv4_mapped(const __u32 address[4]) {
    return address[0] == 0U && address[1] == 0U && swap32(address[2]) == 0xffffU;
}

INLINE bool ipv6_available(const struct sb_ebpf_cgroup_control *config) {
    if ((config->flags & SB_EBPF_CGROUP_FLAG_AUTO_IPV6) == 0U) return true;
    __u32 key = 0U;
    __u32 *available = map_lookup(&cgroup_ipv6_available, &key);
    return available != 0 && *available != 0U;
}

INLINE bool bypass_ipv4_cidr(__u32 address) {
    struct sb_ebpf_ipv4_cidr_lpm_key key = {.prefixlen = 32U};
    __builtin_memcpy(key.addr, &address, sizeof(address));
    return map_lookup(&cgroup_bypass_ipv4, &key) != 0;
}

INLINE bool bypass_ipv6_cidr(const __u32 address[4]) {
    struct sb_ebpf_ipv6_cidr_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.addr, address, sizeof(key.addr));
    return map_lookup(&cgroup_bypass_ipv6, &key) != 0;
}

INLINE bool base_bypass(void *ctx, const struct sb_ebpf_cgroup_control *config, __u8 protocol, __u16 port, bool tgid_mode) {
    if (tgid_mode ? is_tgid_self(config) : is_cookie_bypassed(ctx)) return true;
    if (!protocol_selected(config, protocol)) return true;
    if (service_port(protocol, port)) return true;
    if ((config->flags & SB_EBPF_CGROUP_FLAG_HIJACK_DNS) == 0U && port == 53U) return true;
    if (uid_bypassed(config)) return true;
    return false;
}

INLINE void original_v4(
    struct sb_ebpf_original_dst *value,
    __u8 protocol,
    __u16 port,
    __u32 address,
    __u64 cookie,
    bool connected_udp) {
    __builtin_memset(value, 0, sizeof(*value));
    value->family = AF_INET_VALUE;
    value->protocol = protocol;
    value->port = port;
    __builtin_memcpy(value->addr, &address, sizeof(address));
    value->flags = connected_udp ? SB_EBPF_ORIGINAL_DST_FLAG_CONNECTED_UDP : 0U;
    value->socket_cookie = cookie;
}

INLINE void original_v6(
    struct sb_ebpf_original_dst *value,
    __u8 protocol,
    __u16 port,
    const __u32 address[4],
    __u64 cookie,
    bool connected_udp) {
    __builtin_memset(value, 0, sizeof(*value));
    value->family = AF_INET6_VALUE;
    value->protocol = protocol;
    value->port = port;
    __builtin_memcpy(value->addr, address, sizeof(value->addr));
    value->flags = connected_udp ? SB_EBPF_ORIGINAL_DST_FLAG_CONNECTED_UDP : 0U;
    value->socket_cookie = cookie;
}

INLINE bool equal_original(const struct sb_ebpf_original_dst *left, const struct sb_ebpf_original_dst *right) {
    const __u32 *l = (const __u32 *)left;
    const __u32 *r = (const __u32 *)right;
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < sizeof(*left) / sizeof(__u32); ++index) {
        if (l[index] != r[index]) return false;
    }
    return true;
}

INLINE __u32 mix32(__u32 value) {
    value ^= value >> 16;
    value *= 0x7feb352dU;
    value ^= value >> 15;
    value *= 0x846ca68bU;
    return value ^ (value >> 16);
}

INLINE bool token_v4(
    const struct sb_ebpf_cgroup_control *config,
    struct sb_ebpf_listener_key *key,
    struct sb_ebpf_original_dst *value,
    __u32 address,
    __u8 protocol,
    __u64 cookie) {
    __u32 seed = mix32(address ^ ((__u32)value->port << 16) ^ (__u32)cookie ^ (__u32)(cookie >> 32));
    key->family = AF_INET_VALUE;
    key->protocol = protocol;
    key->listener_port = config->listener_port;
#pragma clang loop unroll(full)
    for (__u32 attempt = 0U; attempt < REDIRECT_TOKEN_ATTEMPTS; ++attempt) {
        __u32 candidate = config->redirect_ipv4_prefix |
            (seed & config->redirect_ipv4_host_mask);
        __u32 network_candidate = swap32(candidate);
        __builtin_memset(key->token_addr, 0, sizeof(key->token_addr));
        __builtin_memcpy(key->token_addr, &network_candidate, sizeof(network_candidate));
        struct sb_ebpf_original_dst *existing = map_lookup(&cgroup_udp_redirect, key);
        if (protocol == TCP_VALUE) existing = map_lookup(&cgroup_tcp_redirect, key);
        if (existing != 0 && equal_original(existing, value)) return true;
        if (existing == 0 &&
            (protocol == TCP_VALUE
                ? map_update(&cgroup_tcp_redirect, key, value, BPF_NOEXIST)
                : map_update(&cgroup_udp_redirect, key, value, BPF_NOEXIST)) == 0) return true;
        seed += 0x9e3779b9U;
    }
    return false;
}

INLINE bool token_v6(
    const struct sb_ebpf_cgroup_control *config,
    struct sb_ebpf_listener_key *key,
    struct sb_ebpf_original_dst *value,
    const __u32 address[4],
    __u8 protocol,
    __u64 cookie) {
    __u32 seed0 = mix32(
        address[0] ^ address[2] ^ ((__u32)value->port << 16) ^ (__u32)cookie);
    __u32 seed1 = mix32(address[1] ^ address[3] ^ (__u32)(cookie >> 32) ^ 0x85ebca6bU);
    key->family = AF_INET6_VALUE;
    key->protocol = protocol;
    key->listener_port = config->listener_port;
#pragma clang loop unroll(full)
    for (__u32 attempt = 0U; attempt < REDIRECT_TOKEN_ATTEMPTS; ++attempt) {
        __builtin_memcpy(key->token_addr, config->redirect_ipv6_prefix, 8U);
        __builtin_memcpy(key->token_addr + 8U, &seed0, 4U);
        __builtin_memcpy(key->token_addr + 12U, &seed1, 4U);
        struct sb_ebpf_original_dst *existing = map_lookup(&cgroup_udp_redirect, key);
        if (protocol == TCP_VALUE) existing = map_lookup(&cgroup_tcp_redirect, key);
        if (existing != 0 && equal_original(existing, value)) return true;
        if (existing == 0 &&
            (protocol == TCP_VALUE
                ? map_update(&cgroup_tcp_redirect, key, value, BPF_NOEXIST)
                : map_update(&cgroup_udp_redirect, key, value, BPF_NOEXIST)) == 0) return true;
        seed0 += 0x9e3779b9U;
        seed1 += 0x7f4a7c15U;
    }
    return false;
}

INLINE bool rewrite_v4(struct bpf_sock_addr *ctx, const struct sb_ebpf_listener_key *key) {
    __u32 address;
    __builtin_memcpy(&address, key->token_addr, sizeof(address));
    ctx->user_ip4 = address;
    ctx->user_port = swap16(key->listener_port);
    return true;
}

INLINE bool rewrite_v6(struct bpf_sock_addr *ctx, const struct sb_ebpf_listener_key *key) {
    __u32 address[4];
    __builtin_memcpy(address, key->token_addr, sizeof(address));
    // Linux 4.19 verifiers require fixed-offset 32-bit accesses to user_ip6.
    *(volatile __u32 *)&ctx->user_ip6[0] = address[0];
    *(volatile __u32 *)&ctx->user_ip6[1] = address[1];
    *(volatile __u32 *)&ctx->user_ip6[2] = address[2];
    *(volatile __u32 *)&ctx->user_ip6[3] = address[3];
    ctx->user_port = swap16(key->listener_port);
    return true;
}

INLINE bool rewrite_v4_mapped(struct bpf_sock_addr *ctx, const struct sb_ebpf_listener_key *key) {
    __u32 address;
    __builtin_memcpy(&address, key->token_addr, sizeof(address));
    *(volatile __u32 *)&ctx->user_ip6[0] = 0U;
    *(volatile __u32 *)&ctx->user_ip6[1] = 0U;
    *(volatile __u32 *)&ctx->user_ip6[2] = 0xffff0000U;
    *(volatile __u32 *)&ctx->user_ip6[3] = address;
    ctx->user_port = swap16(key->listener_port);
    return true;
}

INLINE int flow_action(
    struct bpf_sock_addr *ctx,
    const struct sb_ebpf_cgroup_control *config,
    __u8 family,
    __u8 protocol,
    __u16 port,
    const __u8 address[16],
    __u64 cookie,
    bool mapped_context) {
    if ((config->flags & SB_EBPF_CGROUP_FLAG_UDP_FLOW) == 0U || cookie == 0U) {
        return FLOW_CACHE_MISS;
    }
    struct sb_ebpf_udp_flow_key flow_key = {
        .cookie = cookie,
        .family = family,
        .protocol = protocol,
        .port = port,
    };
    __builtin_memcpy(flow_key.addr, address, sizeof(flow_key.addr));
    struct sb_ebpf_udp_flow_value *flow = map_lookup(&cgroup_udp_flow, &flow_key);
    if (flow == 0) return FLOW_CACHE_MISS;
    __u32 now = (__u32)(ktime_get_ns() / 1000000000ULL);
    if (now - flow->last_seen_seconds > config->udp_timeout_seconds) {
        map_delete(&cgroup_udp_flow, &flow_key);
        return FLOW_CACHE_MISS;
    }
    flow->last_seen_seconds = now;
    if (flow->action == SB_EBPF_UDP_FLOW_ACTION_BYPASS) return FLOW_CACHE_BYPASS;
    if (flow->action == SB_EBPF_UDP_FLOW_ACTION_PROXY) {
        if (mapped_context) rewrite_v4_mapped(ctx, &flow->listener);
        else if (family == AF_INET_VALUE) rewrite_v4(ctx, &flow->listener);
        else rewrite_v6(ctx, &flow->listener);
        return FLOW_CACHE_PROXY;
    }
    return FLOW_CACHE_MISS;
}

INLINE void flow_store(
    const struct sb_ebpf_cgroup_control *config,
    __u8 family,
    __u8 protocol,
    __u16 port,
    const __u8 address[16],
    __u64 cookie,
    __u8 action,
    const struct sb_ebpf_listener_key *listener) {
    if ((config->flags & SB_EBPF_CGROUP_FLAG_UDP_FLOW) == 0U || cookie == 0U) return;
    struct sb_ebpf_udp_flow_key key = {.cookie = cookie, .family = family, .protocol = protocol, .port = port};
    struct sb_ebpf_udp_flow_value value = {.action = action,
        .last_seen_seconds = (__u32)(ktime_get_ns() / 1000000000ULL)};
    __builtin_memcpy(key.addr, address, sizeof(key.addr));
    if (listener != 0) __builtin_memcpy(&value.listener, listener, sizeof(value.listener));
    map_update(&cgroup_udp_flow, &key, &value, 0U);
}

INLINE bool restore_connected_token(
    struct bpf_sock_addr *ctx,
    __u64 cookie,
    bool ipv6_context,
    bool destination_missing) {
    if (!destination_missing || cookie == 0U) return false;
    struct sb_ebpf_listener_key *token = map_lookup(&cgroup_udp_token, &cookie);
    if (token == 0 || token->protocol != UDP_VALUE) return false;
    if (!ipv6_context) {
        if (token->family != AF_INET_VALUE) return false;
        return rewrite_v4(ctx, token);
    }
    if (token->family == AF_INET_VALUE) return rewrite_v4_mapped(ctx, token);
    if (token->family == AF_INET6_VALUE) return rewrite_v6(ctx, token);
    return false;
}

INLINE void reset_connected_udp(__u64 cookie) {
    if (cookie == 0U) return;
    struct sb_ebpf_listener_key *current = map_lookup(&cgroup_udp_token, &cookie);
    if (current != 0) {
        struct sb_ebpf_listener_key listener;
        __builtin_memcpy(&listener, current, sizeof(listener));
        map_delete(&cgroup_udp_redirect, &listener);
    }
    map_delete(&cgroup_udp_token, &cookie);
    map_delete(&cgroup_udp_peer, &cookie);
}

INLINE void store_udp_peer_v4(__u64 cookie, __u32 address, __u16 port) {
    if (cookie == 0U || address == 0U || port == 0U) return;
    struct sb_ebpf_udp_peer_value peer = {
        .family = AF_INET_VALUE,
        .protocol = UDP_VALUE,
        .port = port,
    };
    __builtin_memcpy(peer.addr, &address, sizeof(address));
    map_update(&cgroup_udp_peer, &cookie, &peer, 0U);
}

INLINE void store_udp_peer_v6(__u64 cookie, const __u32 address[4], __u16 port) {
    if (cookie == 0U || port == 0U ||
        (address[0] | address[1] | address[2] | address[3]) == 0U) return;
    struct sb_ebpf_udp_peer_value peer = {
        .family = AF_INET6_VALUE,
        .protocol = UDP_VALUE,
        .port = port,
    };
    __builtin_memcpy(peer.addr, address, sizeof(peer.addr));
    map_update(&cgroup_udp_peer, &cookie, &peer, 0U);
}

INLINE bool restore_udp_peer_v4(__u64 cookie, __u32 *address, __u16 *port) {
    if (cookie == 0U || (*address != 0U && *port != 0U)) return false;
    struct sb_ebpf_udp_peer_value *peer = map_lookup(&cgroup_udp_peer, &cookie);
    if (peer == 0 || peer->family != AF_INET_VALUE || peer->protocol != UDP_VALUE) return false;
    __builtin_memcpy(address, peer->addr, sizeof(*address));
    *port = peer->port;
    return true;
}

INLINE bool restore_udp_peer_v6(__u64 cookie, __u32 address[4], __u16 *port) {
    if (cookie == 0U ||
        ((address[0] | address[1] | address[2] | address[3]) != 0U && *port != 0U)) return false;
    struct sb_ebpf_udp_peer_value *peer = map_lookup(&cgroup_udp_peer, &cookie);
    if (peer == 0 || peer->family != AF_INET6_VALUE || peer->protocol != UDP_VALUE) return false;
    __builtin_memcpy(address, peer->addr, sizeof(peer->addr));
    *port = peer->port;
    return true;
}

INLINE bool restore_udp_peer_for_empty_v6(
    __u64 cookie,
    __u32 address[4],
    __u16 *port) {
    if (cookie == 0U ||
        (address[0] | address[1] | address[2] | address[3]) != 0U || *port != 0U) {
        return false;
    }
    struct sb_ebpf_udp_peer_value *peer = map_lookup(&cgroup_udp_peer, &cookie);
    if (peer == 0 || peer->protocol != UDP_VALUE) return false;
    if (peer->family == AF_INET_VALUE) {
        address[0] = 0U;
        address[1] = 0U;
        address[2] = 0xffff0000U;
        __builtin_memcpy(&address[3], peer->addr, sizeof(address[3]));
    } else if (peer->family == AF_INET6_VALUE) {
        __builtin_memcpy(address, peer->addr, sizeof(peer->addr));
    } else {
        return false;
    }
    *port = peer->port;
    return true;
}

INLINE int handle_v4(
    struct bpf_sock_addr *ctx,
    bool tgid_mode,
    bool connect_hook,
    enum cgroup_protocol_mode protocol_mode) {
    const struct sb_ebpf_cgroup_control *config = control();
    if (config == 0) return 1;
    __u8 protocol;
    if (protocol_mode == CGROUP_PROTOCOL_TCP_ONLY) {
        if (!connect_hook || ctx->protocol != TCP_VALUE) return 1;
        protocol = TCP_VALUE;
    } else if (protocol_mode == CGROUP_PROTOCOL_UDP_ONLY) {
        if (!connect_hook || ctx->protocol != UDP_VALUE) return 1;
        protocol = UDP_VALUE;
    } else {
        protocol = connect_hook ? ctx->protocol : UDP_VALUE;
    }
    __u16 port = swap16((__u16)ctx->user_port);
    if (base_bypass(ctx, config, protocol, port, tgid_mode)) return 1;
    __u64 cookie = get_socket_cookie(ctx);
    __u32 destination = ctx->user_ip4;
    if (!connect_hook && restore_connected_token(
            ctx, cookie, false, destination == 0U || port == 0U)) {
        return 1;
    }
    bool connected_udp = connect_hook && protocol == UDP_VALUE;
    if (connected_udp) {
        reset_connected_udp(cookie);
        store_udp_peer_v4(cookie, destination, port);
    } else if (!connect_hook) {
        (void)restore_udp_peer_v4(cookie, &destination, &port);
    }
    __u8 flow_address[16] = {0};
    __builtin_memcpy(flow_address, &destination, sizeof(destination));
    if (!connect_hook) {
        int cached = flow_action(
            ctx, config, AF_INET_VALUE, protocol, port, flow_address, cookie, false);
        if (cached != FLOW_CACHE_MISS) return 1;
    }
    if ((config->flags & SB_EBPF_CGROUP_FLAG_HIJACK_DNS) != 0U && port == 53U) {
        // DNS hijack intentionally bypasses destination and CIDR policy checks.
    } else {
        if (ipv4_destination_bypassed(destination)) return 1;
        if ((config->flags & SB_EBPF_CGROUP_FLAG_BYPASS_IPV4) != 0U &&
            bypass_ipv4_cidr(destination)) {
            if (!connect_hook) {
                flow_store(config, AF_INET_VALUE, protocol, port, flow_address, cookie,
                    SB_EBPF_UDP_FLOW_ACTION_BYPASS, 0);
            }
            return 1;
        }
    }
    struct sb_ebpf_listener_key listener = {0};
    struct sb_ebpf_original_dst original;
    original_v4(&original, protocol, port, destination, cookie, connected_udp);
    if (!token_v4(config, &listener, &original, destination, protocol, cookie)) return 0;
    if (connected_udp) {
        if (cookie == 0U || map_update(&cgroup_udp_token, &cookie, &listener, 0U) != 0) {
            map_delete(&cgroup_udp_redirect, &listener);
            return 0;
        }
    }
    if (!connect_hook && protocol == UDP_VALUE) {
        flow_store(config, AF_INET_VALUE, protocol, port, flow_address,
            cookie, SB_EBPF_UDP_FLOW_ACTION_PROXY, &listener);
    }
    return rewrite_v4(ctx, &listener) ? 1 : 0;
}

INLINE int handle_v6(
    struct bpf_sock_addr *ctx,
    bool tgid_mode,
    bool connect_hook,
    bool enable_native_ipv6,
    enum cgroup_protocol_mode protocol_mode) {
    const struct sb_ebpf_cgroup_control *config = control();
    if (config == 0) return 1;
    __u32 address[4];
    __builtin_memcpy(address, ctx->user_ip6, sizeof(address));
    __u8 protocol;
    if (protocol_mode == CGROUP_PROTOCOL_TCP_ONLY) {
        if (!connect_hook || ctx->protocol != TCP_VALUE) return 1;
        protocol = TCP_VALUE;
    } else if (protocol_mode == CGROUP_PROTOCOL_UDP_ONLY) {
        if (!connect_hook || ctx->protocol != UDP_VALUE) return 1;
        protocol = UDP_VALUE;
    } else {
        protocol = connect_hook ? ctx->protocol : UDP_VALUE;
    }
    __u16 port = swap16((__u16)ctx->user_port);
    if (base_bypass(ctx, config, protocol, port, tgid_mode)) return 1;
    __u64 cookie = get_socket_cookie(ctx);
    bool missing_destination =
        (address[0] | address[1] | address[2] | address[3]) == 0U || port == 0U;
    if (!connect_hook && restore_connected_token(ctx, cookie, true, missing_destination)) return 1;
    if (!connect_hook) (void)restore_udp_peer_for_empty_v6(cookie, address, &port);
    bool connected_udp = connect_hook && protocol == UDP_VALUE;
    bool mapped = ipv4_mapped(address);
    if (mapped) {
        if ((config->flags & SB_EBPF_CGROUP_FLAG_IPV4) == 0U) return 1;
        __u32 destination;
        __builtin_memcpy(&destination, ((__u8 *)address) + 12U, sizeof(destination));
        if (connected_udp) {
            reset_connected_udp(cookie);
            store_udp_peer_v4(cookie, destination, port);
        } else if (!connect_hook) {
            (void)restore_udp_peer_v4(cookie, &destination, &port);
        }
        __u8 flow_address[16] = {0};
        __builtin_memcpy(flow_address, &destination, sizeof(destination));
        if (!connect_hook) {
            int cached = flow_action(
                ctx, config, AF_INET_VALUE, protocol, port, flow_address, cookie, true);
            if (cached != FLOW_CACHE_MISS) return 1;
        }
        if ((config->flags & SB_EBPF_CGROUP_FLAG_HIJACK_DNS) == 0U || port != 53U) {
            if (ipv4_destination_bypassed(destination)) return 1;
            if ((config->flags & SB_EBPF_CGROUP_FLAG_BYPASS_IPV4) != 0U &&
                bypass_ipv4_cidr(destination)) {
                if (!connect_hook) {
                    flow_store(config, AF_INET_VALUE, protocol, port, flow_address, cookie,
                        SB_EBPF_UDP_FLOW_ACTION_BYPASS, 0);
                }
                return 1;
            }
        }
        struct sb_ebpf_listener_key listener = {0};
        struct sb_ebpf_original_dst original;
        original_v4(&original, protocol, port, destination, cookie, connected_udp);
        if (!token_v4(config, &listener, &original, destination, protocol, cookie)) return 0;
        if (connected_udp &&
            (cookie == 0U || map_update(&cgroup_udp_token, &cookie, &listener, 0U) != 0)) {
            map_delete(&cgroup_udp_redirect, &listener);
            return 0;
        }
        if (!connect_hook && protocol == UDP_VALUE) {
            flow_store(config, AF_INET_VALUE, protocol, port, flow_address, cookie,
                SB_EBPF_UDP_FLOW_ACTION_PROXY, &listener);
        }
        return rewrite_v4_mapped(ctx, &listener) ? 1 : 0;
    }
    if (!enable_native_ipv6) return 1;
    if ((config->flags & SB_EBPF_CGROUP_FLAG_IPV6) == 0U || !ipv6_available(config)) return 1;
    if (connected_udp) {
        reset_connected_udp(cookie);
        store_udp_peer_v6(cookie, address, port);
    } else if (!connect_hook) {
        (void)restore_udp_peer_v6(cookie, address, &port);
    }
    __u8 flow_address[16];
    __builtin_memcpy(flow_address, address, sizeof(flow_address));
    if (!connect_hook) {
        int cached = flow_action(
            ctx, config, AF_INET6_VALUE, protocol, port, flow_address, cookie, false);
        if (cached != FLOW_CACHE_MISS) return 1;
    }
    if ((config->flags & SB_EBPF_CGROUP_FLAG_HIJACK_DNS) == 0U || port != 53U) {
        if (ipv6_destination_bypassed(address)) return 1;
        if ((config->flags & SB_EBPF_CGROUP_FLAG_BYPASS_IPV6) != 0U &&
            bypass_ipv6_cidr(address)) {
            if (!connect_hook) {
                flow_store(config, AF_INET6_VALUE, protocol, port, flow_address, cookie,
                    SB_EBPF_UDP_FLOW_ACTION_BYPASS, 0);
            }
            return 1;
        }
    }
    struct sb_ebpf_listener_key listener = {0};
    struct sb_ebpf_original_dst original;
    original_v6(&original, protocol, port, address, cookie, connected_udp);
    if (!token_v6(config, &listener, &original, address, protocol, cookie)) return 0;
    if (connected_udp &&
        (cookie == 0U || map_update(&cgroup_udp_token, &cookie, &listener, 0U) != 0)) {
        map_delete(&cgroup_udp_redirect, &listener);
        return 0;
    }
    if (!connect_hook && protocol == UDP_VALUE) {
        flow_store(config, AF_INET6_VALUE, protocol, port, flow_address, cookie,
            SB_EBPF_UDP_FLOW_ACTION_PROXY, &listener);
    }
    return rewrite_v6(ctx, &listener) ? 1 : 0;
}

SEC("cgroup/connect4_tgid") int sb_ebpf_conn4_tgid(struct bpf_sock_addr *ctx) { return handle_v4(ctx, true, true, CGROUP_PROTOCOL_AUTO); }
SEC("cgroup/connect4_cookie") int sb_ebpf_conn4_cookie(struct bpf_sock_addr *ctx) { return handle_v4(ctx, false, true, CGROUP_PROTOCOL_AUTO); }
SEC("cgroup/connect4_tgid_tcp") int sb_ebpf_conn4_tgid_tcp(struct bpf_sock_addr *ctx) { return handle_v4(ctx, true, true, CGROUP_PROTOCOL_TCP_ONLY); }
SEC("cgroup/connect4_cookie_tcp") int sb_ebpf_conn4_cookie_tcp(struct bpf_sock_addr *ctx) { return handle_v4(ctx, false, true, CGROUP_PROTOCOL_TCP_ONLY); }
SEC("cgroup/connect4_tgid_udp") int sb_ebpf_conn4_tgid_udp(struct bpf_sock_addr *ctx) { return handle_v4(ctx, true, true, CGROUP_PROTOCOL_UDP_ONLY); }
SEC("cgroup/connect4_cookie_udp") int sb_ebpf_conn4_cookie_udp(struct bpf_sock_addr *ctx) { return handle_v4(ctx, false, true, CGROUP_PROTOCOL_UDP_ONLY); }
SEC("cgroup/sendmsg4_tgid") int sb_ebpf_udp4_tgid(struct bpf_sock_addr *ctx) { return handle_v4(ctx, true, false, CGROUP_PROTOCOL_AUTO); }
SEC("cgroup/sendmsg4_cookie") int sb_ebpf_udp4_cookie(struct bpf_sock_addr *ctx) { return handle_v4(ctx, false, false, CGROUP_PROTOCOL_AUTO); }
SEC("cgroup/connect6_tgid") int sb_ebpf_conn6_tgid(struct bpf_sock_addr *ctx) { return handle_v6(ctx, true, true, true, CGROUP_PROTOCOL_AUTO); }
SEC("cgroup/connect6_cookie") int sb_ebpf_conn6_cookie(struct bpf_sock_addr *ctx) { return handle_v6(ctx, false, true, true, CGROUP_PROTOCOL_AUTO); }
SEC("cgroup/connect6_tgid_tcp") int sb_ebpf_conn6_tgid_tcp(struct bpf_sock_addr *ctx) { return handle_v6(ctx, true, true, true, CGROUP_PROTOCOL_TCP_ONLY); }
SEC("cgroup/connect6_cookie_tcp") int sb_ebpf_conn6_cookie_tcp(struct bpf_sock_addr *ctx) { return handle_v6(ctx, false, true, true, CGROUP_PROTOCOL_TCP_ONLY); }
SEC("cgroup/connect6_tgid_udp") int sb_ebpf_conn6_tgid_udp(struct bpf_sock_addr *ctx) { return handle_v6(ctx, true, true, true, CGROUP_PROTOCOL_UDP_ONLY); }
SEC("cgroup/connect6_cookie_udp") int sb_ebpf_conn6_cookie_udp(struct bpf_sock_addr *ctx) { return handle_v6(ctx, false, true, true, CGROUP_PROTOCOL_UDP_ONLY); }
SEC("cgroup/connect6_mapped_tgid") int sb_ebpf_conn6_mapped_tgid(struct bpf_sock_addr *ctx) { return handle_v6(ctx, true, true, false, CGROUP_PROTOCOL_AUTO); }
SEC("cgroup/connect6_mapped_cookie") int sb_ebpf_conn6_mapped_cookie(struct bpf_sock_addr *ctx) { return handle_v6(ctx, false, true, false, CGROUP_PROTOCOL_AUTO); }
SEC("cgroup/connect6_mapped_tgid_tcp") int sb_ebpf_conn6_mapped_tgid_tcp(struct bpf_sock_addr *ctx) { return handle_v6(ctx, true, true, false, CGROUP_PROTOCOL_TCP_ONLY); }
SEC("cgroup/connect6_mapped_cookie_tcp") int sb_ebpf_conn6_mapped_cookie_tcp(struct bpf_sock_addr *ctx) { return handle_v6(ctx, false, true, false, CGROUP_PROTOCOL_TCP_ONLY); }
SEC("cgroup/connect6_mapped_tgid_udp") int sb_ebpf_conn6_mapped_tgid_udp(struct bpf_sock_addr *ctx) { return handle_v6(ctx, true, true, false, CGROUP_PROTOCOL_UDP_ONLY); }
SEC("cgroup/connect6_mapped_cookie_udp") int sb_ebpf_conn6_mapped_cookie_udp(struct bpf_sock_addr *ctx) { return handle_v6(ctx, false, true, false, CGROUP_PROTOCOL_UDP_ONLY); }
SEC("cgroup/sendmsg6_tgid") int sb_ebpf_udp6_tgid(struct bpf_sock_addr *ctx) { return handle_v6(ctx, true, false, true, CGROUP_PROTOCOL_AUTO); }
SEC("cgroup/sendmsg6_cookie") int sb_ebpf_udp6_cookie(struct bpf_sock_addr *ctx) { return handle_v6(ctx, false, false, true, CGROUP_PROTOCOL_AUTO); }
SEC("cgroup/sendmsg6_mapped_tgid") int sb_ebpf_udp6_mapped_tgid(struct bpf_sock_addr *ctx) { return handle_v6(ctx, true, false, false, CGROUP_PROTOCOL_AUTO); }
SEC("cgroup/sendmsg6_mapped_cookie") int sb_ebpf_udp6_mapped_cookie(struct bpf_sock_addr *ctx) { return handle_v6(ctx, false, false, false, CGROUP_PROTOCOL_AUTO); }

INLINE int recv_v4(struct bpf_sock_addr *ctx) {
    const struct sb_ebpf_cgroup_control *config = control();
    if (config == 0) return 1;
    __u32 destination = ctx->user_ip4;
    if ((config->flags & SB_EBPF_CGROUP_FLAG_IPV4) == 0U) return 1;
    if ((swap32(destination) & ~config->redirect_ipv4_host_mask) != config->redirect_ipv4_prefix) return 1;
    struct sb_ebpf_listener_key key = {.family = AF_INET_VALUE, .protocol = UDP_VALUE,
        .listener_port = swap16((__u16)ctx->user_port)};
    __builtin_memcpy(key.token_addr, &destination, sizeof(destination));
    struct sb_ebpf_original_dst *original = map_lookup(&cgroup_udp_redirect, &key);
    if (original == 0 || original->family != AF_INET_VALUE) return 1;
    __u32 address;
    __builtin_memcpy(&address, original->addr, sizeof(address));
    ctx->user_ip4 = address;
    ctx->user_port = swap16(original->port);
    return 1;
}

INLINE int recv_v6(struct bpf_sock_addr *ctx, bool enable_native_ipv6) {
    const struct sb_ebpf_cgroup_control *config = control();
    if (config == 0) return 1;
    __u32 address[4];
    __builtin_memcpy(address, ctx->user_ip6, sizeof(address));
    if (ipv4_mapped(address)) {
        if ((config->flags & SB_EBPF_CGROUP_FLAG_IPV4) == 0U) return 1;
        __u32 v4;
        __builtin_memcpy(&v4, ((__u8 *)address) + 12U, sizeof(v4));
        if ((swap32(v4) & ~config->redirect_ipv4_host_mask) != config->redirect_ipv4_prefix) return 1;
        struct sb_ebpf_listener_key key = {.family = AF_INET_VALUE, .protocol = UDP_VALUE,
            .listener_port = swap16((__u16)ctx->user_port)};
        __builtin_memcpy(key.token_addr, &v4, sizeof(v4));
        struct sb_ebpf_original_dst *original = map_lookup(&cgroup_udp_redirect, &key);
        if (original == 0 || original->family != AF_INET_VALUE) return 1;
        __u32 original_address;
        __builtin_memcpy(&original_address, original->addr, sizeof(original_address));
        *(volatile __u32 *)&ctx->user_ip6[0] = 0U;
        *(volatile __u32 *)&ctx->user_ip6[1] = 0U;
        *(volatile __u32 *)&ctx->user_ip6[2] = 0xffff0000U;
        *(volatile __u32 *)&ctx->user_ip6[3] = original_address;
        ctx->user_port = swap16(original->port);
        return 1;
    }
    if (!enable_native_ipv6) return 1;
    if ((config->flags & SB_EBPF_CGROUP_FLAG_IPV6) == 0U) return 1;
    __u32 redirect_prefix[2];
    __builtin_memcpy(redirect_prefix, config->redirect_ipv6_prefix, sizeof(redirect_prefix));
    if (address[0] != redirect_prefix[0] || address[1] != redirect_prefix[1]) return 1;
    struct sb_ebpf_listener_key key = {.family = AF_INET6_VALUE, .protocol = UDP_VALUE,
        .listener_port = swap16((__u16)ctx->user_port)};
    __builtin_memcpy(key.token_addr, address, sizeof(key.token_addr));
    struct sb_ebpf_original_dst *original = map_lookup(&cgroup_udp_redirect, &key);
    if (original == 0 || original->family != AF_INET6_VALUE) return 1;
    __u32 original_address[4];
    __builtin_memcpy(original_address, original->addr, sizeof(original_address));
    *(volatile __u32 *)&ctx->user_ip6[0] = original_address[0];
    *(volatile __u32 *)&ctx->user_ip6[1] = original_address[1];
    *(volatile __u32 *)&ctx->user_ip6[2] = original_address[2];
    *(volatile __u32 *)&ctx->user_ip6[3] = original_address[3];
    ctx->user_port = swap16(original->port);
    return 1;
}

SEC("cgroup/recvmsg4") int sb_ebpf_urcv4_c(struct bpf_sock_addr *ctx) { return recv_v4(ctx); }
SEC("cgroup/recvmsg6") int sb_ebpf_urcv6_c(struct bpf_sock_addr *ctx) { return recv_v6(ctx, true); }
SEC("cgroup/recvmsg6_mapped") int sb_ebpf_urcv6_mapped_c(struct bpf_sock_addr *ctx) { return recv_v6(ctx, false); }

INLINE int release_socket(struct bpf_sock *ctx, bool delete_bypass) {
    __u64 cookie = get_socket_cookie(ctx);
    if (cookie == 0U) return 1;
    struct sb_ebpf_listener_key *listener = map_lookup(&cgroup_udp_token, &cookie);
    if (listener != 0) {
        map_delete(&cgroup_udp_redirect, listener);
        map_delete(&cgroup_udp_token, &cookie);
    }
    map_delete(&cgroup_udp_peer, &(__u64){cookie});
    if (delete_bypass) map_delete(&cgroup_socket_bypass, &cookie);
    return 1;
}

SEC("cgroup/release_tgid") int sb_ebpf_rel_tgid(struct bpf_sock *ctx) { return release_socket(ctx, false); }
SEC("cgroup/release_cookie") int sb_ebpf_rel_cookie(struct bpf_sock *ctx) { return release_socket(ctx, true); }

char _license[] SEC("license") = "GPL";
