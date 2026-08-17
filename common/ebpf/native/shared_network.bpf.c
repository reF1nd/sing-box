// Copyright 2026, Asterisk4Magisk contributors
// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bpf_compat.h"
#include "shared_network.h"
#include "shared_network_packet.h"
#include "private_address.h"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#define SB_SHARED_POLICY_BYPASS 0U
#define SB_SHARED_POLICY_PROXY 1U
#define SB_SHARED_POLICY_CACHE_BYPASS 2U

#define SB_SHARED_FRAGMENT_NONE 0U
#define SB_SHARED_FRAGMENT_FIRST 1U
#define SB_SHARED_FRAGMENT_LATER 2U

// TCX only continues with later TCX programs and the legacy clsact chain for
// TC_ACT_UNSPEC. TC_ACT_PIPE stops the TCX program array before being mapped
// to "next", which can skip tethering programs attached after sing-box.
#define SB_SHARED_ACT_CONTINUE TC_ACT_UNSPEC

#ifndef BPF_F_MARK_MANGLED_0
#define BPF_F_MARK_MANGLED_0 (1ULL << 5)
#endif

#define EXTERNAL_MAP(name, key_type, value_type, entries) \
    struct bpf_map_def SEC("maps") name = { \
        .type = BPF_MAP_TYPE_HASH, \
        .key_size = sizeof(key_type), \
        .value_size = sizeof(value_type), \
        .max_entries = entries, \
    }

EXTERNAL_MAP(shared_control, __u32, struct sb_shared_control, 1U);
EXTERNAL_MAP(shared_stats, __u32, __u64, SB_SHARED_STAT_COUNT);
EXTERNAL_MAP(shared_original_to_token, struct sb_shared_original_key, struct sb_shared_token_value, SB_SHARED_NETWORK_OBJECT_MAP_ENTRIES);
struct bpf_map_def SEC("maps") shared_bypass_flow = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct sb_shared_original_key),
    .value_size = sizeof(struct sb_shared_bypass_flow_value),
    .max_entries = SB_SHARED_NETWORK_OBJECT_MAP_ENTRIES,
};
EXTERNAL_MAP(shared_reply, struct sb_shared_reply_key, struct sb_shared_reply_value, SB_SHARED_NETWORK_OBJECT_MAP_ENTRIES);
EXTERNAL_MAP(shared_listener, struct sb_shared_listener_key, struct sb_shared_original_value, SB_SHARED_NETWORK_OBJECT_MAP_ENTRIES);
struct bpf_map_def SEC("maps") shared_fragment = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct sb_shared_fragment_key),
    .value_size = sizeof(struct sb_shared_fragment_value),
    .max_entries = SB_SHARED_NETWORK_OBJECT_MAP_ENTRIES,
};
EXTERNAL_MAP(shared_host_ipv4, struct sb_lpm4_key, __u8, 256U);
EXTERNAL_MAP(shared_host_ipv6, struct sb_lpm6_key, __u8, 256U);
EXTERNAL_MAP(shared_include_source_ipv4, struct sb_lpm4_key, __u8, SB_SHARED_SOURCE_CIDR_MAP_ENTRIES);
EXTERNAL_MAP(shared_include_source_ipv6, struct sb_lpm6_key, __u8, SB_SHARED_SOURCE_CIDR_MAP_ENTRIES);
EXTERNAL_MAP(shared_exclude_source_ipv4, struct sb_lpm4_key, __u8, SB_SHARED_SOURCE_CIDR_MAP_ENTRIES);
EXTERNAL_MAP(shared_exclude_source_ipv6, struct sb_lpm6_key, __u8, SB_SHARED_SOURCE_CIDR_MAP_ENTRIES);
EXTERNAL_MAP(shared_include_source_mac, struct sb_shared_mac_key, __u8, SB_SHARED_SOURCE_MAC_MAP_ENTRIES);
EXTERNAL_MAP(shared_exclude_source_mac, struct sb_shared_mac_key, __u8, SB_SHARED_SOURCE_MAC_MAP_ENTRIES);
EXTERNAL_MAP(shared_bypass_ipv4, struct sb_lpm4_key, __u8, 65536U);
EXTERNAL_MAP(shared_bypass_ipv6, struct sb_lpm6_key, __u8, 65536U);
struct bpf_map_def SEC("maps") shared_scratch = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct sb_shared_scratch),
    .max_entries = 1U,
};

static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *map, const void *key, const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __s64 (*csum_diff)(const __be32 *from, __u32 from_size, const __be32 *to, __u32 to_size, __wsum seed) =
    (void *)BPF_FUNC_csum_diff;
static long (*skb_pull_data)(struct __sk_buff *skb, __u32 length) = (void *)BPF_FUNC_skb_pull_data;
static long (*skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 length, __u64 flags) =
    (void *)BPF_FUNC_skb_store_bytes;
static long (*l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l3_csum_replace;
static long (*l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l4_csum_replace;
INLINE void record_token_reservation_failure(void) {
    __u32 key = SB_SHARED_STAT_TOKEN_RESERVATION_FAILURE;
    __u64 *counter = map_lookup(&shared_stats, &key);
    if (counter != 0) __sync_fetch_and_add(counter, 1U);
}
INLINE void refresh_activity_timestamp(__u64 *last_seen_ns, __u64 now) {
    __u64 previous = *last_seen_ns;
    if (now >= previous &&
        now - previous >= SB_SHARED_ACTIVITY_UPDATE_INTERVAL_NS) {
        *last_seen_ns = now;
    }
}

INLINE __u16 swap16(__u16 value) {
    return __builtin_bswap16(value);
}

INLINE __u32 swap32(__u32 value) {
    return __builtin_bswap32(value);
}

INLINE void copy_address(__u8 destination[16], const __u8 source[16], __u32 size) {
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < 16U; ++index) {
        if (index < size) destination[index] = source[index];
    }
}

INLINE bool equal_address(const __u8 left[16], const __u8 right[16], __u32 size) {
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < 16U; ++index) {
        if (index < size && left[index] != right[index]) return false;
    }
    return true;
}

INLINE void prepare_fragment_key(
    struct sb_shared_scratch *scratch,
    __u32 ifindex,
    __u8 family,
    __u8 protocol,
    __u8 direction,
    __u32 identification,
    const __u8 source[16],
    const __u8 destination[16],
    __u32 address_size) {
    __builtin_memset(&scratch->fragment_key, 0, sizeof(scratch->fragment_key));
    scratch->fragment_key.ifindex = ifindex;
    scratch->fragment_key.identification = identification;
    scratch->fragment_key.family = family;
    scratch->fragment_key.protocol = protocol;
    scratch->fragment_key.direction = direction;
    copy_address(scratch->fragment_key.source_addr, source, address_size);
    copy_address(scratch->fragment_key.destination_addr, destination, address_size);
}

INLINE bool load_fragment(struct sb_shared_scratch *scratch) {
    struct sb_shared_fragment_value *value = map_lookup(
        &shared_fragment,
        &scratch->fragment_key);
    if (value == 0) return false;
    __u64 now = ktime_get_ns();
    if (now - value->last_seen_ns > SB_SHARED_FRAGMENT_TIMEOUT_NS) {
        map_delete(&shared_fragment, &scratch->fragment_key);
        return false;
    }
    value->last_seen_ns = now;
    __builtin_memcpy(&scratch->fragment_value, value, sizeof(scratch->fragment_value));
    return true;
}

INLINE bool store_fragment(
    struct sb_shared_scratch *scratch,
    const __u8 translated[16],
    __u32 address_size,
    __u8 action) {
    __builtin_memset(&scratch->fragment_value, 0, sizeof(scratch->fragment_value));
    scratch->fragment_value.last_seen_ns = ktime_get_ns();
    scratch->fragment_value.action = action;
    copy_address(scratch->fragment_value.translated_addr, translated, address_size);
    return map_update(
        &shared_fragment,
        &scratch->fragment_key,
        &scratch->fragment_value,
        BPF_ANY) == 0;
}
INLINE bool store_ipv4_fragment_bypass(
    struct sb_shared_scratch *scratch,
    struct __sk_buff *skb,
    const struct ipv4_header *ip) {
    prepare_fragment_key(
        scratch,
        skb->ifindex,
        AF_INET_VALUE,
        ip->protocol,
        SB_SHARED_FRAGMENT_DIRECTION_INGRESS,
        (__u32)ip->id,
        (const __u8 *)&ip->source,
        (const __u8 *)&ip->destination,
        4U);
    return store_fragment(
        scratch,
        (const __u8 *)&ip->destination,
        4U,
        SB_SHARED_POLICY_BYPASS);
}

INLINE bool store_ipv6_fragment_bypass(
    struct sb_shared_scratch *scratch,
    struct __sk_buff *skb,
    const struct ipv6_header *ip,
    __u8 protocol,
    __u32 fragment_id) {
    prepare_fragment_key(
        scratch,
        skb->ifindex,
        AF_INET6_VALUE,
        protocol,
        SB_SHARED_FRAGMENT_DIRECTION_INGRESS,
        fragment_id,
        ip->source,
        ip->destination,
        16U);
    return store_fragment(
        scratch,
        ip->destination,
        16U,
        SB_SHARED_POLICY_BYPASS);
}

#include "shared_network_policy.h"

#include "shared_network_flow.h"

#include "shared_network_rewrite.h"

NOINLINE int ingress_ipv4(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control,
    __u32 source_mac_first,
    __u16 source_mac_last) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv4_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U) return SB_SHARED_ACT_CONTINUE;
    if (!selected_protocol(ip->protocol, control)) return SB_SHARED_ACT_CONTINUE;
    __u16 fragment = swap16(ip->fragment_offset);
    __u16 fragment_offset = fragment & IPV4_FRAGMENT_OFFSET_MASK;
    bool more_fragments = (fragment & IPV4_FRAGMENT_MORE) != 0U;
    __u32 header_length = (__u32)ip->ihl * 4U;
    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    if (fragment_offset != 0U) {
        prepare_fragment_key(
            scratch,
            skb->ifindex,
            AF_INET_VALUE,
            ip->protocol,
            SB_SHARED_FRAGMENT_DIRECTION_INGRESS,
            (__u32)ip->id,
            (const __u8 *)&ip->source,
            (const __u8 *)&ip->destination,
            4U);
        if (!load_fragment(scratch)) return TC_ACT_SHOT;
        if (scratch->fragment_value.action == SB_SHARED_POLICY_BYPASS) {
            return SB_SHARED_ACT_CONTINUE;
        }
        if (scratch->fragment_value.action != SB_SHARED_POLICY_PROXY) {
            return TC_ACT_SHOT;
        }
        __be32 token_address;
        __builtin_memcpy(
            &token_address,
            scratch->fragment_value.translated_addr,
            sizeof(token_address));
        return rewrite_ipv4_fragment(
            skb,
            l3_offset,
            false,
            ip->destination,
            token_address);
    }
    struct transport_ports *ports = (void *)ip + header_length;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    __u16 source_port = swap16(ports->source);
    __u16 destination_port = swap16(ports->destination);
    __builtin_memset(&scratch->original, 0, sizeof(scratch->original));
    scratch->original.ifindex = skb->ifindex;
    scratch->original.family = AF_INET_VALUE;
    scratch->original.protocol = ip->protocol;
    scratch->original.client_port = source_port;
    scratch->original.original_port = destination_port;
    __builtin_memcpy(scratch->source_mac.address, &source_mac_first, 4U);
    __builtin_memcpy(scratch->source_mac.address + 4U, &source_mac_last, 2U);
    __builtin_memcpy(scratch->original.client_addr, &ip->source, 4U);
    __builtin_memcpy(scratch->original.original_addr, &ip->destination, 4U);
    bool cached = load_cached_token(scratch);
    if (!cached) {
        __u32 tcp_sequence = 0U;
        bool initial_syn = initial_tcp_syn(ip->protocol, ports, data_end, &tcp_sequence);
        if (load_cached_bypass(scratch, control, ip->protocol, initial_syn, tcp_sequence)) {
            if (more_fragments && !store_ipv4_fragment_bypass(scratch, skb, ip)) {
                return TC_ACT_SHOT;
            }
            return SB_SHARED_ACT_CONTINUE;
        }
        if (!ipv4_client_selected(
                scratch->source_mac.address,
                (const __u8 *)&ip->source,
                control)) {
            cache_bypass(scratch, ip->protocol, tcp_sequence);
            if (more_fragments && !store_ipv4_fragment_bypass(scratch, skb, ip)) {
                return TC_ACT_SHOT;
            }
            return SB_SHARED_ACT_CONTINUE;
        }
        __u8 policy = ipv4_policy(
            (const __u8 *)&ip->destination,
            ip->protocol,
            source_port,
            destination_port,
            control);
        if (policy != SB_SHARED_POLICY_PROXY) {
            if (policy == SB_SHARED_POLICY_CACHE_BYPASS) {
                cache_bypass(scratch, ip->protocol, tcp_sequence);
            }
            if (more_fragments && !store_ipv4_fragment_bypass(scratch, skb, ip)) {
                return TC_ACT_SHOT;
            }
            return SB_SHARED_ACT_CONTINUE;
        }
    }

    if (skb_pull_data(skb, 0U) != 0) return TC_ACT_SHOT;
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U) {
        return TC_ACT_SHOT;
    }
    fragment = swap16(ip->fragment_offset);
    fragment_offset = fragment & IPV4_FRAGMENT_OFFSET_MASK;
    more_fragments = (fragment & IPV4_FRAGMENT_MORE) != 0U;
    if (!selected_protocol(ip->protocol, control) || fragment_offset != 0U) {
        return TC_ACT_SHOT;
    }
    header_length = (__u32)ip->ihl * 4U;
    ports = (void *)ip + header_length;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    source_port = swap16(ports->source);
    destination_port = swap16(ports->destination);

    if (!cached) {
        if (!reserve_token(scratch, control)) return TC_ACT_SHOT;
    }
    __be32 token_address;
    __builtin_memcpy(&token_address, scratch->token.token_addr, 4U);
    if (more_fragments) {
        prepare_fragment_key(
            scratch,
            skb->ifindex,
            AF_INET_VALUE,
            ip->protocol,
            SB_SHARED_FRAGMENT_DIRECTION_INGRESS,
            (__u32)ip->id,
            (const __u8 *)&ip->source,
            (const __u8 *)&ip->destination,
            4U);
        if (!store_fragment(scratch, (const __u8 *)&token_address, 4U, SB_SHARED_POLICY_PROXY)) {
            return TC_ACT_SHOT;
        }
    }
    return rewrite_ipv4(
        skb,
        l3_offset,
        l3_offset + header_length,
        false,
        ip->destination,
        token_address,
        ports->destination,
        swap16(control->listener_port),
        ip->protocol);
}

NOINLINE int egress_ipv4(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv4_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U) return SB_SHARED_ACT_CONTINUE;
    if (!ipv4_token_address(ip->source, control)) return SB_SHARED_ACT_CONTINUE;
    if (!selected_protocol(ip->protocol, control)) return TC_ACT_SHOT;
    __u16 fragment = swap16(ip->fragment_offset);
    __u16 fragment_offset = fragment & IPV4_FRAGMENT_OFFSET_MASK;
    bool more_fragments = (fragment & IPV4_FRAGMENT_MORE) != 0U;
    __u32 header_length = (__u32)ip->ihl * 4U;
    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    if (fragment_offset != 0U) {
        prepare_fragment_key(
            scratch,
            skb->ifindex,
            AF_INET_VALUE,
            ip->protocol,
            SB_SHARED_FRAGMENT_DIRECTION_EGRESS,
            (__u32)ip->id,
            (const __u8 *)&ip->source,
            (const __u8 *)&ip->destination,
            4U);
        if (!load_fragment(scratch)) return TC_ACT_SHOT;
        if (scratch->fragment_value.action != SB_SHARED_POLICY_PROXY) {
            return TC_ACT_SHOT;
        }
        __be32 original_address;
        __builtin_memcpy(
            &original_address,
            scratch->fragment_value.translated_addr,
            sizeof(original_address));
        return rewrite_ipv4_fragment(
            skb,
            l3_offset,
            true,
            ip->source,
            original_address);
    }
    struct transport_ports *ports = (void *)ip + header_length;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    if (swap16(ports->source) != control->listener_port) return SB_SHARED_ACT_CONTINUE;

    if (skb_pull_data(skb, 0U) != 0) return TC_ACT_SHOT;
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U ||
        !ipv4_token_address(ip->source, control)) {
        return TC_ACT_SHOT;
    }
    fragment = swap16(ip->fragment_offset);
    fragment_offset = fragment & IPV4_FRAGMENT_OFFSET_MASK;
    more_fragments = (fragment & IPV4_FRAGMENT_MORE) != 0U;
    if (!selected_protocol(ip->protocol, control) || fragment_offset != 0U) {
        return TC_ACT_SHOT;
    }
    header_length = (__u32)ip->ihl * 4U;
    ports = (void *)ip + header_length;
    if ((void *)(ports + 1) > data_end ||
        swap16(ports->source) != control->listener_port) {
        return TC_ACT_SHOT;
    }

    __builtin_memset(&scratch->reply_key, 0, sizeof(scratch->reply_key));
    scratch->reply_key.ifindex = skb->ifindex;
    scratch->reply_key.family = AF_INET_VALUE;
    scratch->reply_key.protocol = ip->protocol;
    scratch->reply_key.client_port = swap16(ports->destination);
    scratch->reply_key.listener_port = control->listener_port;
    __builtin_memcpy(scratch->reply_key.client_addr, &ip->destination, 4U);
    __builtin_memcpy(scratch->reply_key.token_addr, &ip->source, 4U);
    struct sb_shared_reply_value *original = map_lookup(
        &shared_reply,
        &scratch->reply_key);
    if (original == 0) return TC_ACT_SHOT;
    __be32 original_address;
    __builtin_memcpy(&original_address, original->original_addr, 4U);
    if (more_fragments) {
        prepare_fragment_key(
            scratch,
            skb->ifindex,
            AF_INET_VALUE,
            ip->protocol,
            SB_SHARED_FRAGMENT_DIRECTION_EGRESS,
            (__u32)ip->id,
            (const __u8 *)&ip->source,
            (const __u8 *)&ip->destination,
            4U);
        if (!store_fragment(scratch, (const __u8 *)&original_address, 4U, SB_SHARED_POLICY_PROXY)) {
            return TC_ACT_SHOT;
        }
    }
    return rewrite_ipv4(
        skb,
        l3_offset,
        l3_offset + header_length,
        true,
        ip->source,
        original_address,
        ports->source,
        swap16(original->original_port),
        ip->protocol);
}

NOINLINE __u64 ipv6_transport_offset(
    void *data,
    void *data_end,
    __u32 l3_offset,
    __u8 *protocol_out) {
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end) return IPV6_TRANSPORT_DROP;
    __u8 protocol = ip->next_header;
    __u32 offset = l3_offset + sizeof(*ip);
    __u64 result = 0U;
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 4U; ++depth) {
        if (result != 0U) continue;
        if (protocol == IPPROTO_TCP_VALUE || protocol == IPPROTO_UDP_VALUE) {
            *protocol_out = protocol;
            result = offset;
        } else if (protocol == 44U) {
            struct ipv6_fragment_header *fragment = data + offset;
            if ((void *)(fragment + 1) > data_end) {
                result = IPV6_TRANSPORT_DROP;
                continue;
            }
            protocol = fragment->next_header;
            if (protocol != IPPROTO_TCP_VALUE && protocol != IPPROTO_UDP_VALUE) {
                if (protocol == 0U || protocol == 43U || protocol == 60U ||
                    protocol == 51U || protocol == 44U) {
                    result = IPV6_TRANSPORT_DROP;
                } else {
                    result = IPV6_TRANSPORT_BYPASS;
                }
                continue;
            }
            __u16 fragment_offset = swap16(fragment->fragment_offset);
            offset += sizeof(*fragment);
            if ((fragment_offset & (IPV6_FRAGMENT_OFFSET_MASK | IPV6_FRAGMENT_MORE)) == 0U) {
                *protocol_out = protocol;
                result = offset;
                continue;
            }
            *protocol_out = protocol;
            __u64 fragment_state = (fragment_offset & IPV6_FRAGMENT_OFFSET_MASK) == 0U
                ? SB_SHARED_FRAGMENT_FIRST
                : SB_SHARED_FRAGMENT_LATER;
            result = ((__u64)fragment->identification << 32U) |
                (fragment_state << IPV6_FRAGMENT_STATE_SHIFT) |
                (__u64)offset;
        } else if (protocol != 0U && protocol != 43U && protocol != 60U && protocol != 51U) {
            result = IPV6_TRANSPORT_BYPASS;
        } else {
            struct ipv6_extension_header *extension = data + offset;
            if ((void *)(extension + 1) > data_end) {
                result = IPV6_TRANSPORT_DROP;
                continue;
            }
            __u8 current = protocol;
            protocol = extension->next_header;
            offset += current == 51U
                ? ((__u32)extension->length + 2U) * 4U
                : ((__u32)extension->length + 1U) * 8U;
            if (data + offset > data_end) result = IPV6_TRANSPORT_DROP;
        }
    }
    return result == 0U ? IPV6_TRANSPORT_DROP : result;
}

NOINLINE int ingress_ipv6(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control,
    __u32 source_mac_first,
    __u16 source_mac_last) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || (swap32(ip->version_flow) >> 28U) != 6U) return SB_SHARED_ACT_CONTINUE;
    __u8 protocol = 0U;
    __u64 transport_result = ipv6_transport_offset(
        data,
        data_end,
        l3_offset,
        &protocol);
    __u32 transport = (__u32)transport_result;
    __u32 fragment_id = (__u32)(transport_result >> 32U);
    __u8 fragment_state = (__u8)(
        (transport >> IPV6_FRAGMENT_STATE_SHIFT) & 0x3U);
    if (transport == IPV6_TRANSPORT_DROP) return TC_ACT_SHOT;
    if (transport == IPV6_TRANSPORT_BYPASS) return SB_SHARED_ACT_CONTINUE;
    if ((transport & IPV6_TRANSPORT_MASK) < IPV6_TRANSPORT_MIN_OFFSET ||
        (transport & IPV6_TRANSPORT_MASK) > IPV6_TRANSPORT_MAX_OFFSET) {
        return TC_ACT_SHOT;
    }
    transport &= IPV6_TRANSPORT_MASK;
    if (!selected_protocol(protocol, control)) return SB_SHARED_ACT_CONTINUE;
    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    if (fragment_state == SB_SHARED_FRAGMENT_LATER) {
        prepare_fragment_key(
            scratch,
            skb->ifindex,
            AF_INET6_VALUE,
            protocol,
            SB_SHARED_FRAGMENT_DIRECTION_INGRESS,
            fragment_id,
            ip->source,
            ip->destination,
            16U);
        if (!load_fragment(scratch)) return TC_ACT_SHOT;
        if (scratch->fragment_value.action == SB_SHARED_POLICY_BYPASS) {
            return SB_SHARED_ACT_CONTINUE;
        }
        if (scratch->fragment_value.action != SB_SHARED_POLICY_PROXY) {
            return TC_ACT_SHOT;
        }
        return rewrite_ipv6_fragment(
            skb,
            l3_offset,
            false,
            scratch->fragment_value.translated_addr);
    }
    struct transport_ports *ports = data + transport;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    __be16 source_port_raw = ports->source;
    __be16 destination_port_raw = ports->destination;
    __u16 source_port = swap16(source_port_raw);
    __u16 destination_port = swap16(destination_port_raw);
    __builtin_memset(&scratch->original, 0, sizeof(scratch->original));
    scratch->original.ifindex = skb->ifindex;
    scratch->original.family = AF_INET6_VALUE;
    scratch->original.protocol = protocol;
    scratch->original.client_port = source_port;
    scratch->original.original_port = destination_port;
    __builtin_memcpy(scratch->source_mac.address, &source_mac_first, 4U);
    __builtin_memcpy(scratch->source_mac.address + 4U, &source_mac_last, 2U);
    copy_address(scratch->original.client_addr, ip->source, 16U);
    copy_address(scratch->original.original_addr, ip->destination, 16U);
    bool cached = load_cached_token(scratch);
    if (!cached) {
        __u32 tcp_sequence = 0U;
        bool initial_syn = initial_tcp_syn(protocol, ports, data_end, &tcp_sequence);
        if (load_cached_bypass(scratch, control, protocol, initial_syn, tcp_sequence)) {
            if (fragment_state == SB_SHARED_FRAGMENT_FIRST &&
                !store_ipv6_fragment_bypass(scratch, skb, ip, protocol, fragment_id)) {
                return TC_ACT_SHOT;
            }
            return SB_SHARED_ACT_CONTINUE;
        }
        if (!ipv6_client_selected(scratch->source_mac.address, ip->source, control)) {
            cache_bypass(scratch, protocol, tcp_sequence);
            if (fragment_state == SB_SHARED_FRAGMENT_FIRST &&
                !store_ipv6_fragment_bypass(scratch, skb, ip, protocol, fragment_id)) {
                return TC_ACT_SHOT;
            }
            return SB_SHARED_ACT_CONTINUE;
        }
        __u8 policy = ipv6_policy(
            ip->destination,
            protocol,
            source_port,
            destination_port,
            control);
        if (policy != SB_SHARED_POLICY_PROXY) {
            if (policy == SB_SHARED_POLICY_CACHE_BYPASS) {
                cache_bypass(scratch, protocol, tcp_sequence);
            }
            if (fragment_state == SB_SHARED_FRAGMENT_FIRST &&
                !store_ipv6_fragment_bypass(scratch, skb, ip, protocol, fragment_id)) {
                return TC_ACT_SHOT;
            }
            return SB_SHARED_ACT_CONTINUE;
        }
    }

    if (skb_pull_data(skb, 0U) != 0) return TC_ACT_SHOT;
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || (swap32(ip->version_flow) >> 28U) != 6U) {
        return TC_ACT_SHOT;
    }
    protocol = 0U;
    transport_result = ipv6_transport_offset(
        data,
        data_end,
        l3_offset,
        &protocol);
    transport = (__u32)transport_result;
    fragment_id = (__u32)(transport_result >> 32U);
    fragment_state = (__u8)(
        (transport >> IPV6_FRAGMENT_STATE_SHIFT) & 0x3U);
    if ((transport & IPV6_TRANSPORT_MASK) < IPV6_TRANSPORT_MIN_OFFSET ||
        (transport & IPV6_TRANSPORT_MASK) > IPV6_TRANSPORT_MAX_OFFSET ||
        fragment_state == SB_SHARED_FRAGMENT_LATER) {
        return TC_ACT_SHOT;
    }
    transport &= IPV6_TRANSPORT_MASK;
    ports = data + transport;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    source_port_raw = ports->source;
    destination_port_raw = ports->destination;
    if (!selected_protocol(protocol, control)) return TC_ACT_SHOT;
    source_port = swap16(source_port_raw);
    destination_port = swap16(destination_port_raw);

    if (!cached) {
        if (!reserve_token(scratch, control)) return TC_ACT_SHOT;
    }
    if (fragment_state == SB_SHARED_FRAGMENT_FIRST) {
        prepare_fragment_key(
            scratch,
            skb->ifindex,
            AF_INET6_VALUE,
            protocol,
            SB_SHARED_FRAGMENT_DIRECTION_INGRESS,
            fragment_id,
            ip->source,
            ip->destination,
            16U);
        if (!store_fragment(scratch, scratch->token.token_addr, 16U, SB_SHARED_POLICY_PROXY)) {
            return TC_ACT_SHOT;
        }
    }
    return rewrite_ipv6(
        skb,
        l3_offset,
        transport,
        false,
        scratch->original.original_addr,
        scratch->token.token_addr,
        destination_port_raw,
        swap16(control->listener_port),
        protocol);
}

NOINLINE int egress_ipv6(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || (swap32(ip->version_flow) >> 28U) != 6U) return SB_SHARED_ACT_CONTINUE;
    if (!ipv6_token_address(ip->source, control)) return SB_SHARED_ACT_CONTINUE;
    __u8 protocol = 0U;
    __u64 transport_result = ipv6_transport_offset(
        data,
        data_end,
        l3_offset,
        &protocol);
    __u32 transport = (__u32)transport_result;
    __u32 fragment_id = (__u32)(transport_result >> 32U);
    __u8 fragment_state = (__u8)(
        (transport >> IPV6_FRAGMENT_STATE_SHIFT) & 0x3U);
    if ((transport & IPV6_TRANSPORT_MASK) < IPV6_TRANSPORT_MIN_OFFSET ||
        (transport & IPV6_TRANSPORT_MASK) > IPV6_TRANSPORT_MAX_OFFSET) {
        return TC_ACT_SHOT;
    }
    transport &= IPV6_TRANSPORT_MASK;
    if (!selected_protocol(protocol, control)) return TC_ACT_SHOT;
    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    if (fragment_state == SB_SHARED_FRAGMENT_LATER) {
        prepare_fragment_key(
            scratch,
            skb->ifindex,
            AF_INET6_VALUE,
            protocol,
            SB_SHARED_FRAGMENT_DIRECTION_EGRESS,
            fragment_id,
            ip->source,
            ip->destination,
            16U);
        if (!load_fragment(scratch)) return TC_ACT_SHOT;
        if (scratch->fragment_value.action != SB_SHARED_POLICY_PROXY) {
            return TC_ACT_SHOT;
        }
        return rewrite_ipv6_fragment(
            skb,
            l3_offset,
            true,
            scratch->fragment_value.translated_addr);
    }
    struct transport_ports *ports = data + transport;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    __be16 source_port_raw = ports->source;
    if (swap16(source_port_raw) != control->listener_port) return SB_SHARED_ACT_CONTINUE;

    if (skb_pull_data(skb, 0U) != 0) return TC_ACT_SHOT;
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end ||
        (swap32(ip->version_flow) >> 28U) != 6U ||
        !ipv6_token_address(ip->source, control)) {
        return TC_ACT_SHOT;
    }
    protocol = 0U;
    transport_result = ipv6_transport_offset(
        data,
        data_end,
        l3_offset,
        &protocol);
    transport = (__u32)transport_result;
    fragment_id = (__u32)(transport_result >> 32U);
    fragment_state = (__u8)(
        (transport >> IPV6_FRAGMENT_STATE_SHIFT) & 0x3U);
    if ((transport & IPV6_TRANSPORT_MASK) < IPV6_TRANSPORT_MIN_OFFSET ||
        (transport & IPV6_TRANSPORT_MASK) > IPV6_TRANSPORT_MAX_OFFSET ||
        fragment_state == SB_SHARED_FRAGMENT_LATER) {
        return TC_ACT_SHOT;
    }
    transport &= IPV6_TRANSPORT_MASK;
    ports = data + transport;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    source_port_raw = ports->source;
    __be16 destination_port_raw = ports->destination;
    if (!selected_protocol(protocol, control) ||
        swap16(source_port_raw) != control->listener_port) {
        return TC_ACT_SHOT;
    }

    __builtin_memset(&scratch->reply_key, 0, sizeof(scratch->reply_key));
    scratch->reply_key.ifindex = skb->ifindex;
    scratch->reply_key.family = AF_INET6_VALUE;
    scratch->reply_key.protocol = protocol;
    scratch->reply_key.client_port = swap16(destination_port_raw);
    scratch->reply_key.listener_port = control->listener_port;
    copy_address(scratch->reply_key.client_addr, ip->destination, 16U);
    copy_address(scratch->reply_key.token_addr, ip->source, 16U);
    struct sb_shared_reply_value *original = map_lookup(
        &shared_reply,
        &scratch->reply_key);
    if (original == 0) return TC_ACT_SHOT;
    __builtin_memcpy(&scratch->reply_value, original, sizeof(scratch->reply_value));
    if (fragment_state == SB_SHARED_FRAGMENT_FIRST) {
        prepare_fragment_key(
            scratch,
            skb->ifindex,
            AF_INET6_VALUE,
            protocol,
            SB_SHARED_FRAGMENT_DIRECTION_EGRESS,
            fragment_id,
            ip->source,
            ip->destination,
            16U);
        if (!store_fragment(scratch, scratch->reply_value.original_addr, 16U, SB_SHARED_POLICY_PROXY)) {
            return TC_ACT_SHOT;
        }
    }
    return rewrite_ipv6(
        skb,
        l3_offset,
        transport,
        true,
        scratch->reply_key.token_addr,
        scratch->reply_value.original_addr,
        source_port_raw,
        swap16(scratch->reply_value.original_port),
        protocol);
}

NOINLINE int classify_ingress(struct __sk_buff *skb) {
    __u32 zero = 0U;
    struct sb_shared_control *control = map_lookup(&shared_control, &zero);
    if (control == 0 || control->enabled == 0U) return SB_SHARED_ACT_CONTINUE;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return SB_SHARED_ACT_CONTINUE;
    __u16 protocol = swap16(ethernet->protocol);
    __u32 l3_offset = sizeof(*ethernet);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 2U; ++depth) {
        if (protocol != ETH_P_8021Q_VALUE && protocol != ETH_P_8021AD_VALUE) break;
        struct vlan_header *vlan = data + l3_offset;
        if ((void *)(vlan + 1) > data_end) return SB_SHARED_ACT_CONTINUE;
        protocol = swap16(vlan->protocol);
        l3_offset += sizeof(*vlan);
    }
    __u32 source_mac_first;
    __u16 source_mac_last;
    __builtin_memcpy(&source_mac_first, ethernet->source, 4U);
    __builtin_memcpy(&source_mac_last, ethernet->source + 4U, 2U);
    if (protocol == ETH_P_IP_VALUE && (control->flags & SB_SHARED_FLAG_IPV4) != 0U) {
        return ingress_ipv4(skb, l3_offset, control, source_mac_first, source_mac_last);
    }
    if (protocol == ETH_P_IPV6_VALUE && (control->flags & SB_SHARED_FLAG_IPV6) != 0U) {
        return ingress_ipv6(skb, l3_offset, control, source_mac_first, source_mac_last);
    }
    return SB_SHARED_ACT_CONTINUE;
}

NOINLINE int classify_egress(struct __sk_buff *skb) {
    __u32 zero = 0U;
    struct sb_shared_control *control = map_lookup(&shared_control, &zero);
    if (control == 0 || control->enabled == 0U) return SB_SHARED_ACT_CONTINUE;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return SB_SHARED_ACT_CONTINUE;
    __u16 protocol = swap16(ethernet->protocol);
    __u32 l3_offset = sizeof(*ethernet);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 2U; ++depth) {
        if (protocol != ETH_P_8021Q_VALUE && protocol != ETH_P_8021AD_VALUE) break;
        struct vlan_header *vlan = data + l3_offset;
        if ((void *)(vlan + 1) > data_end) return SB_SHARED_ACT_CONTINUE;
        protocol = swap16(vlan->protocol);
        l3_offset += sizeof(*vlan);
    }
    if (protocol == ETH_P_IP_VALUE && (control->flags & SB_SHARED_FLAG_IPV4) != 0U) {
        return egress_ipv4(skb, l3_offset, control);
    }
    if (protocol == ETH_P_IPV6_VALUE && (control->flags & SB_SHARED_FLAG_IPV6) != 0U) {
        return egress_ipv6(skb, l3_offset, control);
    }
    return SB_SHARED_ACT_CONTINUE;
}

SEC("classifier/ingress")
int singbox_shared_ingress(struct __sk_buff *skb) {
    return classify_ingress(skb);
}

SEC("classifier/egress")
int singbox_shared_egress(struct __sk_buff *skb) {
    return classify_egress(skb);
}

char _license[] SEC("license") = "GPL";
