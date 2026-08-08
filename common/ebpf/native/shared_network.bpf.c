// Copyright 2026, Asterisk4Magisk contributors
// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "shared_network.h"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline))
#define NOINLINE static __attribute__((noinline))

#define ETH_P_IP_VALUE 0x0800U
#define ETH_P_IPV6_VALUE 0x86ddU
#define ETH_P_8021Q_VALUE 0x8100U
#define ETH_P_8021AD_VALUE 0x88a8U
#define IPPROTO_TCP_VALUE 6U
#define IPPROTO_UDP_VALUE 17U
#define AF_INET_VALUE 2U
#define AF_INET6_VALUE 10U
#define IPV4_FRAGMENT_OFFSET_MASK 0x1fffU
#define IPV4_FRAGMENT_MORE 0x2000U
#define IPV6_FRAGMENT_OFFSET_MASK 0xfff8U
#define IPV6_FRAGMENT_MORE 0x0001U
#define TCP_FLAG_SYN 0x0002U
#define TCP_FLAG_ACK 0x0010U

/* Bound old-verifier offsets for Ethernet, two VLAN tags, IPv6, and three extension headers. */
#define IPV6_TRANSPORT_MIN_OFFSET 54U
#define IPV6_TRANSPORT_MAX_OFFSET 6206U
#define IPV6_TRANSPORT_MASK 0x1fffU
#define IPV6_FRAGMENT_STATE_SHIFT 13U
#define IPV6_TRANSPORT_BYPASS 0xffffffffU
#define IPV6_TRANSPORT_DROP 0xfffffffeU

#define SB_SHARED_POLICY_BYPASS 0U
#define SB_SHARED_POLICY_PROXY 1U
#define SB_SHARED_POLICY_CACHE_BYPASS 2U

#define SB_SHARED_FRAGMENT_NONE 0U
#define SB_SHARED_FRAGMENT_FIRST 1U
#define SB_SHARED_FRAGMENT_LATER 2U

#ifndef BPF_F_MARK_MANGLED_0
#define BPF_F_MARK_MANGLED_0 (1ULL << 5)
#endif

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct sb_lpm4_key {
    __u32 prefixlen;
    __u8 addr[4];
};

struct sb_lpm6_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct ethernet_header {
    __u8 destination[6];
    __u8 source[6];
    __be16 protocol;
};

struct vlan_header {
    __be16 tci;
    __be16 protocol;
};

struct ipv4_header {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl : 4;
    __u8 version : 4;
#else
    __u8 version : 4;
    __u8 ihl : 4;
#endif
    __u8 tos;
    __be16 total_length;
    __be16 id;
    __be16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __sum16 checksum;
    __be32 source;
    __be32 destination;
};

struct ipv6_header {
    __be32 version_flow;
    __be16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 source[16];
    __u8 destination[16];
};

struct ipv6_extension_header {
    __u8 next_header;
    __u8 length;
};

struct ipv6_fragment_header {
    __u8 next_header;
    __u8 reserved;
    __be16 fragment_offset;
    __be32 identification;
};

struct transport_ports {
    __be16 source;
    __be16 destination;
};

struct tcp_header_min {
    __be16 source;
    __be16 destination;
    __be32 sequence;
    __be32 acknowledgement;
    __be16 flags;
    __be16 window;
    __sum16 checksum;
    __be16 urgent_pointer;
};

struct udp_header_min {
    __be16 source;
    __be16 destination;
    __be16 length;
    __sum16 checksum;
};

#define EXTERNAL_MAP(name, key_type, value_type, entries) \
    struct bpf_map_def SEC("maps") name = { \
        .type = BPF_MAP_TYPE_HASH, \
        .key_size = sizeof(key_type), \
        .value_size = sizeof(value_type), \
        .max_entries = entries, \
    }

EXTERNAL_MAP(shared_control, __u32, struct sb_shared_control, 1U);
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



INLINE bool selected_protocol(__u8 protocol, const struct sb_shared_control *control) {
    if (protocol == IPPROTO_TCP_VALUE) return (control->flags & SB_SHARED_FLAG_TCP) != 0U;
    if (protocol == IPPROTO_UDP_VALUE) return (control->flags & SB_SHARED_FLAG_UDP) != 0U;
    return false;
}

INLINE bool dhcp_packet(__u8 protocol, __u16 source_port, __u16 destination_port) {
    if (protocol != IPPROTO_UDP_VALUE) return false;
    return source_port == 67U || source_port == 68U ||
        source_port == 546U || source_port == 547U ||
        destination_port == 67U || destination_port == 68U ||
        destination_port == 546U || destination_port == 547U;
}

#define SB_SHARED_SOURCE_IP_POLICY_FLAGS \
    (SB_SHARED_FLAG_INCLUDE_SOURCE | SB_SHARED_FLAG_EXCLUDE_SOURCE)
#define SB_SHARED_SOURCE_MAC_POLICY_FLAGS \
    (SB_SHARED_FLAG_INCLUDE_SOURCE_MAC | SB_SHARED_FLAG_EXCLUDE_SOURCE_MAC)
#define SB_SHARED_SOURCE_POLICY_FLAGS \
    (SB_SHARED_SOURCE_IP_POLICY_FLAGS | SB_SHARED_SOURCE_MAC_POLICY_FLAGS)

INLINE bool ipv4_source_selected(const __u8 source[4], __u32 flags) {
    if ((flags & (SB_SHARED_FLAG_INCLUDE_SOURCE | SB_SHARED_FLAG_EXCLUDE_SOURCE)) == 0U) return true;
    struct sb_lpm4_key key = {.prefixlen = 32U};
    __builtin_memcpy(key.addr, source, 4U);
    if ((flags & SB_SHARED_FLAG_EXCLUDE_SOURCE) != 0U &&
        map_lookup(&shared_exclude_source_ipv4, &key) != 0) return false;
    return (flags & SB_SHARED_FLAG_INCLUDE_SOURCE) == 0U ||
        map_lookup(&shared_include_source_ipv4, &key) != 0;
}

INLINE bool ipv6_source_selected(const __u8 source[16], __u32 flags) {
    if ((flags & (SB_SHARED_FLAG_INCLUDE_SOURCE | SB_SHARED_FLAG_EXCLUDE_SOURCE)) == 0U) return true;
    struct sb_lpm6_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.addr, source, 16U);
    if ((flags & SB_SHARED_FLAG_EXCLUDE_SOURCE) != 0U &&
        map_lookup(&shared_exclude_source_ipv6, &key) != 0) return false;
    return (flags & SB_SHARED_FLAG_INCLUDE_SOURCE) == 0U ||
        map_lookup(&shared_include_source_ipv6, &key) != 0;
}

INLINE bool source_mac_selected(const __u8 source[6], __u32 flags) {
    if ((flags & (SB_SHARED_FLAG_INCLUDE_SOURCE_MAC | SB_SHARED_FLAG_EXCLUDE_SOURCE_MAC)) == 0U) return true;
    struct sb_shared_mac_key key = {};
    __builtin_memcpy(key.address, source, 6U);
    if ((flags & SB_SHARED_FLAG_EXCLUDE_SOURCE_MAC) != 0U &&
        map_lookup(&shared_exclude_source_mac, &key) != 0) return false;
    return (flags & SB_SHARED_FLAG_INCLUDE_SOURCE_MAC) == 0U ||
        map_lookup(&shared_include_source_mac, &key) != 0;
}

INLINE bool ipv4_client_selected(
    const __u8 source_mac[6],
    const __u8 source[4],
    const struct sb_shared_control *control) {
    __u32 flags = control->flags;
    if ((flags & SB_SHARED_SOURCE_POLICY_FLAGS) == 0U) return true;
    return source_mac_selected(source_mac, flags) && ipv4_source_selected(source, flags);
}

INLINE bool ipv6_client_selected(
    const __u8 source_mac[6],
    const __u8 source[16],
    const struct sb_shared_control *control) {
    __u32 flags = control->flags;
    if ((flags & SB_SHARED_SOURCE_POLICY_FLAGS) == 0U) return true;
    return source_mac_selected(source_mac, flags) && ipv6_source_selected(source, flags);
}

INLINE bool ipv4_builtin_bypass(const __u8 address[4]) {
    if (address[0] == 0U || address[0] == 10U || address[0] == 127U || address[0] >= 224U) return true;
    if (address[0] == 100U && (address[1] & 0xc0U) == 0x40U) return true;
    if (address[0] == 169U && address[1] == 254U) return true;
    if (address[0] == 172U && (address[1] & 0xf0U) == 0x10U) return true;
    if (address[0] == 192U && address[1] == 168U) return true;
    return false;
}

INLINE bool ipv6_builtin_bypass(const __u8 address[16]) {
    if (address[0] == 0xffU || (address[0] & 0xfeU) == 0xfcU) return true;
    return address[0] == 0xfeU && (address[1] & 0xc0U) == 0x80U;
}

NOINLINE __u8 ipv4_policy(
    const __u8 destination[4],
    __u8 protocol,
    __u16 source_port,
    __u16 destination_port,
    const struct sb_shared_control *control) {
    if (dhcp_packet(protocol, source_port, destination_port)) return SB_SHARED_POLICY_BYPASS;
    if (destination_port == 53U) return (control->flags & SB_SHARED_FLAG_DNS_HIJACK) != 0U
        ? SB_SHARED_POLICY_PROXY
        : SB_SHARED_POLICY_BYPASS;
    if ((control->flags & SB_SHARED_FLAG_BYPASS_PRIVATE_ADDRESS) != 0U &&
        ipv4_builtin_bypass(destination)) return SB_SHARED_POLICY_BYPASS;
    __u32 map_policy_flags = control->flags &
        (SB_SHARED_FLAG_HOST_IPV4 | SB_SHARED_FLAG_BYPASS_IPV4);
    if (map_policy_flags == 0U) return SB_SHARED_POLICY_PROXY;
    struct sb_lpm4_key key = {.prefixlen = 32U};
    __builtin_memcpy(key.addr, destination, 4U);
    if ((map_policy_flags & SB_SHARED_FLAG_HOST_IPV4) != 0U &&
        map_lookup(&shared_host_ipv4, &key) != 0) return SB_SHARED_POLICY_BYPASS;
    if ((map_policy_flags & SB_SHARED_FLAG_BYPASS_IPV4) == 0U) return SB_SHARED_POLICY_PROXY;
    return map_lookup(&shared_bypass_ipv4, &key) == 0
        ? SB_SHARED_POLICY_PROXY
        : SB_SHARED_POLICY_CACHE_BYPASS;
}

NOINLINE __u8 ipv6_policy(
    const __u8 destination[16],
    __u8 protocol,
    __u16 source_port,
    __u16 destination_port,
    const struct sb_shared_control *control) {
    if (dhcp_packet(protocol, source_port, destination_port)) return SB_SHARED_POLICY_BYPASS;
    if (destination_port == 53U) return (control->flags & SB_SHARED_FLAG_DNS_HIJACK) != 0U
        ? SB_SHARED_POLICY_PROXY
        : SB_SHARED_POLICY_BYPASS;
    if ((control->flags & SB_SHARED_FLAG_BYPASS_PRIVATE_ADDRESS) != 0U &&
        ipv6_builtin_bypass(destination)) return SB_SHARED_POLICY_BYPASS;
    __u32 map_policy_flags = control->flags &
        (SB_SHARED_FLAG_HOST_IPV6 | SB_SHARED_FLAG_BYPASS_IPV6);
    if (map_policy_flags == 0U) return SB_SHARED_POLICY_PROXY;
    struct sb_lpm6_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.addr, destination, 16U);
    if ((map_policy_flags & SB_SHARED_FLAG_HOST_IPV6) != 0U && map_lookup(&shared_host_ipv6, &key) != 0) {
        return SB_SHARED_POLICY_BYPASS;
    }
    if ((map_policy_flags & SB_SHARED_FLAG_BYPASS_IPV6) == 0U) return SB_SHARED_POLICY_PROXY;
    return map_lookup(&shared_bypass_ipv6, &key) == 0
        ? SB_SHARED_POLICY_PROXY
        : SB_SHARED_POLICY_CACHE_BYPASS;
}

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
    __builtin_memcpy(scratch->original_value.source_mac, scratch->source_mac.address, 6U);
    copy_address(
        scratch->original_value.addr,
        scratch->original.original_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
}

INLINE void fill_reply(struct sb_shared_scratch *scratch, const struct sb_shared_control *control) {
    __builtin_memset(&scratch->reply_key, 0, sizeof(scratch->reply_key));
    scratch->reply_key.ifindex = scratch->original.ifindex;
    scratch->reply_key.family = scratch->original.family;
    scratch->reply_key.protocol = scratch->original.protocol;
    scratch->reply_key.client_port = scratch->original.client_port;
    scratch->reply_key.listener_port = control->listener_port;
    copy_address(
        scratch->reply_key.client_addr,
        scratch->original.client_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    copy_address(
        scratch->reply_key.token_addr,
        scratch->token.token_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    __builtin_memset(&scratch->reply_value, 0, sizeof(scratch->reply_value));
    scratch->reply_value.original_port = scratch->original.original_port;
    copy_address(
        scratch->reply_value.original_addr,
        scratch->original.original_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
}

NOINLINE bool sync_token(
    struct sb_shared_scratch *scratch,
    const struct sb_shared_control *control,
    __u64 listener_flags) {
    fill_listener(scratch, control);
    fill_reply(scratch, control);
    if (map_update(&shared_listener, &scratch->listener_key, &scratch->original_value, listener_flags) != 0) return false;
    if (map_update(&shared_reply, &scratch->reply_key, &scratch->reply_value, BPF_ANY) != 0) {
        if (listener_flags == BPF_NOEXIST) map_delete(&shared_listener, &scratch->listener_key);
        return false;
    }
    return true;
}

#define SB_SHARED_TOKEN_RETRY 0
#define SB_SHARED_TOKEN_RESERVED 1
#define SB_SHARED_TOKEN_FAILED -1

// Keep each attempt in its own BPF subprogram: LLVM 21 otherwise carries loop
// state in caller-clobbered registers across the hash and map subprogram calls.
NOINLINE int reserve_token_attempt(
    struct sb_shared_scratch *scratch,
    const struct sb_shared_control *control,
    __u32 attempt) {
    __builtin_memset(&scratch->token, 0, sizeof(scratch->token));
    __u32 hash = hash_original(&scratch->original, 0x9e3779b9U * (attempt + 1U));
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
        __u32 second = hash_original(&scratch->original, 0x85ebca6bU ^ attempt);
        scratch->token.token_addr[8] = (__u8)(hash >> 24U);
        scratch->token.token_addr[9] = (__u8)(hash >> 16U);
        scratch->token.token_addr[10] = (__u8)(hash >> 8U);
        scratch->token.token_addr[11] = (__u8)hash;
        scratch->token.token_addr[12] = (__u8)(second >> 24U);
        scratch->token.token_addr[13] = (__u8)(second >> 16U);
        scratch->token.token_addr[14] = (__u8)(second >> 8U);
        scratch->token.token_addr[15] = (__u8)second;
    }
    if (!sync_token(scratch, control, BPF_NOEXIST)) return SB_SHARED_TOKEN_RETRY;
    if (map_update(
            &shared_original_to_token,
            &scratch->original,
            &scratch->token,
            BPF_NOEXIST) == 0) {
        return SB_SHARED_TOKEN_RESERVED;
    }
    map_delete(&shared_reply, &scratch->reply_key);
    map_delete(&shared_listener, &scratch->listener_key);
    struct sb_shared_token_value *existing = map_lookup(
        &shared_original_to_token,
        &scratch->original);
    if (existing != 0) {
        __builtin_memcpy(&scratch->token, existing, sizeof(scratch->token));
        return SB_SHARED_TOKEN_RESERVED;
    }
    return SB_SHARED_TOKEN_FAILED;
}

NOINLINE bool reserve_token(struct sb_shared_scratch *scratch, const struct sb_shared_control *control) {
#pragma clang loop unroll(full)
    for (__u32 attempt = 0U; attempt < SB_SHARED_TOKEN_ATTEMPTS; ++attempt) {
        int result = reserve_token_attempt(scratch, control, attempt);
        if (result == SB_SHARED_TOKEN_RESERVED) return true;
        if (result == SB_SHARED_TOKEN_FAILED) return false;
    }
    return false;
}

INLINE bool load_cached_token(struct sb_shared_scratch *scratch) {
    struct sb_shared_token_value *existing = map_lookup(&shared_original_to_token, &scratch->original);
    if (existing == 0) return false;
    __builtin_memcpy(&scratch->token, existing, sizeof(scratch->token));
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

INLINE bool load_cached_bypass(
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
    cached->last_seen_ns = now;
    return true;
}

INLINE void cache_bypass(
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

INLINE __u64 checksum_flags(__u8 protocol, __u64 size) {
	__u64 flags = size;
	if (protocol == IPPROTO_UDP_VALUE) flags |= BPF_F_MARK_MANGLED_0 | BPF_F_MARK_ENFORCE;
	return flags;
}

INLINE __u64 pseudo_header_checksum_flags(__u8 protocol, __u64 size) {
	return checksum_flags(protocol, size) | BPF_F_PSEUDO_HDR;
}

INLINE int rewrite_ipv4(
    struct __sk_buff *skb,
    __u32 l3_offset,
    __u32 l4_offset,
    bool source,
    __be32 old_address,
    __be32 new_address,
    __be16 old_port,
    __be16 new_port,
    __u8 protocol) {
    __u32 address_offset = l3_offset + (source
        ? __builtin_offsetof(struct ipv4_header, source)
        : __builtin_offsetof(struct ipv4_header, destination));
    __u32 port_offset = l4_offset + (source ? 0U : 2U);
	__u32 checksum_offset = l4_offset + (protocol == IPPROTO_TCP_VALUE
		? __builtin_offsetof(struct tcp_header_min, checksum)
		: __builtin_offsetof(struct udp_header_min, checksum));
	__s64 address_diff = csum_diff(&old_address, 4U, &new_address, 4U, 0U);
	if (address_diff < 0) return TC_ACT_SHOT;
	if (l3_csum_replace(
			skb,
            l3_offset + __builtin_offsetof(struct ipv4_header, checksum),
            old_address,
            new_address,
			4U) != 0) {
		return TC_ACT_SHOT;
	}
	if (l4_csum_replace(skb, checksum_offset, 0U, (__u64)address_diff, pseudo_header_checksum_flags(protocol, 0U)) != 0 ||
		l4_csum_replace(skb, checksum_offset, old_port, new_port, checksum_flags(protocol, 2U)) != 0 ||
        skb_store_bytes(skb, address_offset, &new_address, sizeof(new_address), 0U) != 0 ||
        skb_store_bytes(skb, port_offset, &new_port, sizeof(new_port), 0U) != 0) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE int rewrite_ipv6(
    struct __sk_buff *skb,
    __u32 l3_offset,
    __u32 l4_offset,
    bool source,
    const __u8 old_address[16],
    const __u8 new_address[16],
    __be16 old_port,
    __be16 new_port,
    __u8 protocol) {
    __u32 checksum_offset = l4_offset + (protocol == IPPROTO_TCP_VALUE
        ? __builtin_offsetof(struct tcp_header_min, checksum)
        : __builtin_offsetof(struct udp_header_min, checksum));
    __s64 address_diff = csum_diff(
        (const __be32 *)old_address,
        16U,
        (const __be32 *)new_address,
        16U,
        0U);
    if (address_diff < 0) return TC_ACT_SHOT;
    __u32 address_offset = l3_offset + (source
        ? __builtin_offsetof(struct ipv6_header, source)
        : __builtin_offsetof(struct ipv6_header, destination));
    __u32 port_offset = l4_offset + (source ? 0U : 2U);
	if (l4_csum_replace(skb, checksum_offset, 0U, (__u64)address_diff, pseudo_header_checksum_flags(protocol, 0U)) != 0 ||
        l4_csum_replace(skb, checksum_offset, old_port, new_port, checksum_flags(protocol, 2U)) != 0 ||
        skb_store_bytes(skb, address_offset, new_address, 16U, 0U) != 0 ||
        skb_store_bytes(skb, port_offset, &new_port, sizeof(new_port), 0U) != 0) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE int rewrite_ipv4_fragment(
    struct __sk_buff *skb,
    __u32 l3_offset,
    bool source,
    __be32 old_address,
    __be32 new_address) {
    __u32 address_offset = l3_offset + (source
        ? __builtin_offsetof(struct ipv4_header, source)
        : __builtin_offsetof(struct ipv4_header, destination));
    if (l3_csum_replace(
            skb,
            l3_offset + __builtin_offsetof(struct ipv4_header, checksum),
            old_address,
            new_address,
            4U) != 0 ||
        skb_store_bytes(skb, address_offset, &new_address, sizeof(new_address), 0U) != 0) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE int rewrite_ipv6_fragment(
    struct __sk_buff *skb,
    __u32 l3_offset,
    bool source,
    const __u8 new_address[16]) {
    __u32 address_offset = l3_offset + (source
        ? __builtin_offsetof(struct ipv6_header, source)
        : __builtin_offsetof(struct ipv6_header, destination));
    return skb_store_bytes(skb, address_offset, new_address, 16U, 0U) == 0
        ? TC_ACT_OK
        : TC_ACT_SHOT;
}


INLINE bool ipv4_token_address(__be32 address, const struct sb_shared_control *control) {
    __u32 host = swap32(address);
    __u32 prefix = ((__u32)control->token_ipv4_prefix[0] << 24U) |
        ((__u32)control->token_ipv4_prefix[1] << 16U) |
        ((__u32)control->token_ipv4_prefix[2] << 8U) |
        (__u32)control->token_ipv4_prefix[3];
    __u32 bits = control->token_ipv4_prefix_bits;
    __u32 mask = bits == 0U ? 0U : 0xffffffffU << (32U - bits);
    return (host & mask) == (prefix & mask);
}

INLINE bool ipv6_token_address(const __u8 address[16], const struct sb_shared_control *control) {
    return equal_address(address, control->token_ipv6_prefix, 8U);
}

NOINLINE int ingress_ipv4(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control,
    __u32 source_mac_first,
    __u16 source_mac_last) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv4_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U) return TC_ACT_PIPE;
    if (!selected_protocol(ip->protocol, control)) return TC_ACT_PIPE;
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
            return TC_ACT_PIPE;
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
            return TC_ACT_PIPE;
        }
        if (!ipv4_client_selected(
                scratch->source_mac.address,
                (const __u8 *)&ip->source,
                control)) {
            cache_bypass(scratch, ip->protocol, tcp_sequence);
            if (more_fragments && !store_ipv4_fragment_bypass(scratch, skb, ip)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_PIPE;
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
            return TC_ACT_PIPE;
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
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U) return TC_ACT_PIPE;
    if (!ipv4_token_address(ip->source, control)) return TC_ACT_PIPE;
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
    if (swap16(ports->source) != control->listener_port) return TC_ACT_PIPE;

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
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 4U; ++depth) {
        if (protocol == IPPROTO_TCP_VALUE || protocol == IPPROTO_UDP_VALUE) {
            *protocol_out = protocol;
            return offset;
        }
        if (protocol == 44U) {
            struct ipv6_fragment_header *fragment = data + offset;
            if ((void *)(fragment + 1) > data_end) return IPV6_TRANSPORT_DROP;
            protocol = fragment->next_header;
            if (protocol != IPPROTO_TCP_VALUE && protocol != IPPROTO_UDP_VALUE) {
                if (protocol == 0U || protocol == 43U || protocol == 60U ||
                    protocol == 51U || protocol == 44U) {
                    return IPV6_TRANSPORT_DROP;
                }
                return IPV6_TRANSPORT_BYPASS;
            }
            __u16 fragment_offset = swap16(fragment->fragment_offset);
            offset += sizeof(*fragment);
            if ((fragment_offset & (IPV6_FRAGMENT_OFFSET_MASK | IPV6_FRAGMENT_MORE)) == 0U) {
                *protocol_out = protocol;
                return offset;
            }
            *protocol_out = protocol;
            __u64 fragment_state = (fragment_offset & IPV6_FRAGMENT_OFFSET_MASK) == 0U
                ? SB_SHARED_FRAGMENT_FIRST
                : SB_SHARED_FRAGMENT_LATER;
            return ((__u64)fragment->identification << 32U) |
                (fragment_state << IPV6_FRAGMENT_STATE_SHIFT) |
                (__u64)offset;
        }
        if (protocol != 0U && protocol != 43U && protocol != 60U && protocol != 51U) {
            return IPV6_TRANSPORT_BYPASS;
        }
        struct ipv6_extension_header *extension = data + offset;
        if ((void *)(extension + 1) > data_end) return IPV6_TRANSPORT_DROP;
        __u8 current = protocol;
        protocol = extension->next_header;
        offset += current == 51U
            ? ((__u32)extension->length + 2U) * 4U
            : ((__u32)extension->length + 1U) * 8U;
        if (data + offset > data_end) return IPV6_TRANSPORT_DROP;
    }
    return IPV6_TRANSPORT_DROP;
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
    if ((void *)(ip + 1) > data_end || (swap32(ip->version_flow) >> 28U) != 6U) return TC_ACT_PIPE;
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
    if (transport == IPV6_TRANSPORT_BYPASS) return TC_ACT_PIPE;
    if ((transport & IPV6_TRANSPORT_MASK) < IPV6_TRANSPORT_MIN_OFFSET ||
        (transport & IPV6_TRANSPORT_MASK) > IPV6_TRANSPORT_MAX_OFFSET) {
        return TC_ACT_SHOT;
    }
    transport &= IPV6_TRANSPORT_MASK;
    if (!selected_protocol(protocol, control)) return TC_ACT_PIPE;
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
            return TC_ACT_PIPE;
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
            return TC_ACT_PIPE;
        }
        if (!ipv6_client_selected(scratch->source_mac.address, ip->source, control)) {
            cache_bypass(scratch, protocol, tcp_sequence);
            if (fragment_state == SB_SHARED_FRAGMENT_FIRST &&
                !store_ipv6_fragment_bypass(scratch, skb, ip, protocol, fragment_id)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_PIPE;
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
            return TC_ACT_PIPE;
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
    if ((void *)(ip + 1) > data_end || (swap32(ip->version_flow) >> 28U) != 6U) return TC_ACT_PIPE;
    if (!ipv6_token_address(ip->source, control)) return TC_ACT_PIPE;
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
    if (swap16(source_port_raw) != control->listener_port) return TC_ACT_PIPE;

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

NOINLINE int classify(struct __sk_buff *skb, bool ingress) {
    __u32 zero = 0U;
    struct sb_shared_control *control = map_lookup(&shared_control, &zero);
    if (control == 0 || control->enabled == 0U) return TC_ACT_PIPE;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return TC_ACT_PIPE;
    __u16 protocol = swap16(ethernet->protocol);
    __u32 l3_offset = sizeof(*ethernet);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 2U; ++depth) {
        if (protocol != ETH_P_8021Q_VALUE && protocol != ETH_P_8021AD_VALUE) break;
        struct vlan_header *vlan = data + l3_offset;
        if ((void *)(vlan + 1) > data_end) return TC_ACT_PIPE;
        protocol = swap16(vlan->protocol);
        l3_offset += sizeof(*vlan);
    }
    if (!ingress) {
        if (protocol == ETH_P_IP_VALUE && (control->flags & SB_SHARED_FLAG_IPV4) != 0U) {
            return egress_ipv4(skb, l3_offset, control);
        }
        if (protocol == ETH_P_IPV6_VALUE && (control->flags & SB_SHARED_FLAG_IPV6) != 0U) {
            return egress_ipv6(skb, l3_offset, control);
        }
        return TC_ACT_PIPE;
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
    return TC_ACT_PIPE;
}

SEC("classifier/ingress")
int singbox_shared_ingress(struct __sk_buff *skb) {
    return classify(skb, true);
}

SEC("classifier/egress")
int singbox_shared_egress(struct __sk_buff *skb) {
    return classify(skb, false);
}

char _license[] SEC("license") = "GPL";
