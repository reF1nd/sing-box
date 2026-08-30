// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_SHARED_NETWORK_FLOW_H
#define SING_BOX_EBPF_SHARED_NETWORK_FLOW_H

NOINLINE __u32 hash_original(const struct sb_shared_original_key *key, __u32 salt) {
    const __u8 *bytes = (const __u8 *)key;
    __u32 hash = 2166136261U ^ salt;
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < sizeof(*key); ++index) {
        hash ^= bytes[index];
        hash *= 16777619U;
    }
    hash ^= hash >> 16U;
    hash *= 0x7feb352dU;
    hash ^= hash >> 15U;
    hash *= 0x846ca68bU;
    hash ^= hash >> 16U;
    return hash;
}

INLINE void fill_listener(struct sb_shared_scratch *scratch, const struct sb_shared_control *control) {
    __builtin_memset(&scratch->listener_key, 0, sizeof(scratch->listener_key));
    scratch->listener_key.family = scratch->original.family;
    scratch->listener_key.protocol = scratch->original.protocol;
    scratch->listener_key.listener_port = control->listener_port;
    scratch->listener_key.client_port = scratch->original.client_port;
    copy_address(
        scratch->listener_key.token_addr,
        scratch->token.token_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    copy_address(
        scratch->listener_key.client_addr,
        scratch->original.client_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    __builtin_memset(&scratch->original_value, 0, sizeof(scratch->original_value));
    scratch->original_value.family = scratch->original.family;
    scratch->original_value.protocol = scratch->original.protocol;
    scratch->original_value.port = scratch->original.original_port;
    scratch->original_value.ifindex = scratch->original.ifindex;
    scratch->original_value.generation = scratch->token.generation;
    __builtin_memcpy(scratch->original_value.source_mac, scratch->source_mac.address, 6U);
    copy_address(
        scratch->original_value.addr,
        scratch->original.original_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
}

NOINLINE bool publish_token(
    struct sb_shared_scratch *scratch,
    const struct sb_shared_control *control,
    __u64 listener_flags) {
    fill_listener(scratch, control);
    return map_update(
        &shared_flow_by_token,
        &scratch->listener_key,
        &scratch->original_value,
        listener_flags) == 0;
}

INLINE void delete_token_generation(struct sb_shared_scratch *scratch) {
    struct sb_shared_original_value *reverse = map_lookup(
        &shared_flow_by_token,
        &scratch->listener_key);
    if (reverse != 0 && reverse->generation == scratch->token.generation) {
        map_delete(&shared_flow_by_token, &scratch->listener_key);
    }
}

#define SB_SHARED_TOKEN_RETRY 0
#define SB_SHARED_TOKEN_RESERVED 1

// Keep each attempt in its own BPF subprogram: LLVM 21 otherwise carries loop
// state in caller-clobbered registers across the hash and map subprogram calls.
NOINLINE int reserve_token_attempt(
    struct sb_shared_scratch *scratch,
    const struct sb_shared_control *control,
    __u32 attempt) {
    __builtin_memset(&scratch->token, 0, sizeof(scratch->token));
    __u64 now = ktime_get_ns();
    __u32 generation_salt = (__u32)now ^ (__u32)(now >> 32U);
    __u32 hash = hash_original(
        &scratch->original,
        generation_salt ^ (0x9e3779b9U * (attempt + 1U)));
    if (scratch->original.family == AF_INET_VALUE) {
        __u32 prefix = ((__u32)control->token_ipv4_prefix[0] << 24U) |
            ((__u32)control->token_ipv4_prefix[1] << 16U) |
            ((__u32)control->token_ipv4_prefix[2] << 8U) |
            (__u32)control->token_ipv4_prefix[3];
        __u32 host_bits = 32U - (__u32)control->token_ipv4_prefix_bits;
        __u32 host_mask = 0xffffffffU >> (32U - host_bits);
        __u32 candidate = (prefix & ~host_mask) | (hash & host_mask);
        if ((candidate & host_mask) == 0U || (candidate & host_mask) == host_mask) {
            return SB_SHARED_TOKEN_RETRY;
        }
        scratch->token.token_addr[0] = (__u8)(candidate >> 24U);
        scratch->token.token_addr[1] = (__u8)(candidate >> 16U);
        scratch->token.token_addr[2] = (__u8)(candidate >> 8U);
        scratch->token.token_addr[3] = (__u8)candidate;
    } else {
        copy_address(scratch->token.token_addr, control->token_ipv6_prefix, 8U);
        __u32 second = hash_original(
            &scratch->original,
            generation_salt ^ 0x85ebca6bU ^ attempt);
        scratch->token.token_addr[8] = (__u8)(hash >> 24U);
        scratch->token.token_addr[9] = (__u8)(hash >> 16U);
        scratch->token.token_addr[10] = (__u8)(hash >> 8U);
        scratch->token.token_addr[11] = (__u8)hash;
        scratch->token.token_addr[12] = (__u8)(second >> 24U);
        scratch->token.token_addr[13] = (__u8)(second >> 16U);
        scratch->token.token_addr[14] = (__u8)(second >> 8U);
        scratch->token.token_addr[15] = (__u8)second;
    }
    scratch->token.generation = now ^ ((__u64)hash << 32U);
    scratch->token.last_seen_ns = now;
    if (!publish_token(scratch, control, BPF_NOEXIST)) {
        return SB_SHARED_TOKEN_RETRY;
    }
    if (map_update(
            &shared_flow_by_original,
            &scratch->original,
            &scratch->token,
            BPF_NOEXIST) == 0) {
        return SB_SHARED_TOKEN_RESERVED;
    }
    delete_token_generation(scratch);
    struct sb_shared_token_value *existing = map_lookup(
        &shared_flow_by_original,
        &scratch->original);
    if (existing != 0) {
        __builtin_memcpy(&scratch->token, existing, sizeof(scratch->token));
        return SB_SHARED_TOKEN_RESERVED;
    }
    return SB_SHARED_TOKEN_RETRY;
}

NOINLINE bool reserve_token(
    struct sb_shared_scratch *scratch,
    const struct sb_shared_control *control) {
    int result = SB_SHARED_TOKEN_RETRY;
#pragma clang loop unroll(full)
    for (__u32 attempt = 0U; attempt < SB_SHARED_TOKEN_ATTEMPTS; ++attempt) {
        if (result == SB_SHARED_TOKEN_RETRY) {
            result = reserve_token_attempt(scratch, control, attempt);
        }
    }
    if (result != SB_SHARED_TOKEN_RESERVED) record_token_reservation_failure();
    return result == SB_SHARED_TOKEN_RESERVED;
}

INLINE bool load_cached_token(struct sb_shared_scratch *scratch) {
    struct sb_shared_token_value *existing = map_lookup(
        &shared_flow_by_original,
        &scratch->original);
    if (existing == 0) return false;
    __builtin_memcpy(&scratch->token, existing, sizeof(scratch->token));
    if (scratch->original.protocol != IPPROTO_TCP_VALUE) {
        refresh_activity_timestamp(&existing->last_seen_ns, ktime_get_ns());
    }
    return true;
}

INLINE bool initial_tcp_syn(
    __u8 protocol,
    const struct transport_ports *ports,
    const void *data_end,
    __u32 *sequence) {
    if (protocol != IPPROTO_TCP_VALUE) return false;
    const struct tcp_header_min *tcp = (const void *)ports;
    if ((const void *)(tcp + 1) > data_end) return false;
    __u16 flags = swap16(tcp->flags);
    if ((flags & TCP_FLAG_SYN) == 0U || (flags & TCP_FLAG_ACK) != 0U) return false;
    *sequence = tcp->sequence;
    return true;
}

NOINLINE bool load_cached_bypass(
    struct sb_shared_scratch *scratch,
    const struct sb_shared_control *control,
    __u8 protocol,
    bool initial_syn,
    __u32 tcp_sequence) {
    if ((control->flags & SB_SHARED_FLAG_BYPASS_FLOW_CACHE) == 0U) return false;
    struct sb_shared_bypass_flow_value *cached = map_lookup(
        &shared_bypass_flow,
        &scratch->original);
    if (cached == 0) return false;
    if (protocol == IPPROTO_TCP_VALUE) {
        if (!initial_syn || cached->tcp_sequence == tcp_sequence) return true;
        map_delete(&shared_bypass_flow, &scratch->original);
        return false;
    }
    __u64 now = ktime_get_ns();
    __u64 timeout = (__u64)control->udp_timeout_seconds * 1000000000ULL;
    if (now - cached->last_seen_ns > timeout) {
        map_delete(&shared_bypass_flow, &scratch->original);
        return false;
    }
    refresh_activity_timestamp(&cached->last_seen_ns, now);
    return true;
}

NOINLINE void cache_bypass(
    struct sb_shared_scratch *scratch,
    __u8 protocol,
    __u32 tcp_sequence) {
    __builtin_memset(&scratch->bypass_flow, 0, sizeof(scratch->bypass_flow));
    scratch->bypass_flow.last_seen_ns = ktime_get_ns();
    if (protocol == IPPROTO_TCP_VALUE) scratch->bypass_flow.tcp_sequence = tcp_sequence;
    map_update(
        &shared_bypass_flow,
        &scratch->original,
        &scratch->bypass_flow,
        BPF_ANY);
}

#endif
