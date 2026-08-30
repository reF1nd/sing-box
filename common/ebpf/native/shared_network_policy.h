// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_SHARED_NETWORK_POLICY_H
#define SING_BOX_EBPF_SHARED_NETWORK_POLICY_H

#include "fakeip_policy.h"

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

INLINE bool shared_port_bypassed(__u8 protocol, __u16 destination_port) {
    struct sb_shared_port_key key = {
        .protocol = protocol,
        .port = destination_port,
    };
    return map_lookup(&shared_bypass_port, &key) != 0;
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

NOINLINE __u8 shared_dns_policy(
    __u8 protocol,
    __u16 source_port,
    __u16 destination_port,
    const struct sb_shared_control *control) {
    if (dhcp_packet(protocol, source_port, destination_port)) return SB_SHARED_POLICY_BYPASS;
    if (destination_port != 53U) return SB_SHARED_POLICY_CONTINUE;
    if (control->dns_mode == SB_SHARED_DNS_MODE_OFF) return SB_SHARED_POLICY_BYPASS;
    if (control->dns_mode == SB_SHARED_DNS_MODE_HIJACK) return SB_SHARED_POLICY_PROXY;
    return SB_SHARED_POLICY_RESPECT_SOURCE;
}

NOINLINE __u8 ipv4_policy(
    const __u8 destination[4],
    __u8 protocol,
    __u16 source_port,
    __u16 destination_port,
    const struct sb_shared_control *control) {
    if (sb_ebpf_ipv4_safety_bypass(destination)) return SB_SHARED_POLICY_BYPASS;
    __u32 map_policy_flags = control->flags &
        (SB_SHARED_FLAG_HOST_IPV4 | SB_SHARED_FLAG_BYPASS_IPV4);
    struct sb_lpm4_key key = {.prefixlen = 32U};
    __builtin_memcpy(key.addr, destination, 4U);
    if ((map_policy_flags & SB_SHARED_FLAG_HOST_IPV4) != 0U &&
        map_lookup(&shared_host_ipv4, &key) != 0) return SB_SHARED_POLICY_BYPASS;
    if (sb_ebpf_must_intercept_fakeip_ipv4(
        destination,
        control->flags,
        SB_SHARED_FLAG_FAKEIP_IPV4,
        control->fakeip_ipv4_prefix,
        control->fakeip_ipv4_mask)) return SB_SHARED_POLICY_PROXY;
    if ((control->flags & SB_SHARED_FLAG_BYPASS_PRIVATE_ADDRESS) != 0U &&
        sb_ebpf_ipv4_private_address(destination)) return SB_SHARED_POLICY_BYPASS;
    if (map_policy_flags == 0U) return SB_SHARED_POLICY_PROXY;
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
    if (sb_ebpf_ipv6_safety_bypass(destination)) return SB_SHARED_POLICY_BYPASS;
    __u32 map_policy_flags = control->flags &
        (SB_SHARED_FLAG_HOST_IPV6 | SB_SHARED_FLAG_BYPASS_IPV6);
    struct sb_lpm6_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.addr, destination, 16U);
    if ((map_policy_flags & SB_SHARED_FLAG_HOST_IPV6) != 0U && map_lookup(&shared_host_ipv6, &key) != 0) {
        return SB_SHARED_POLICY_BYPASS;
    }
    if (sb_ebpf_must_intercept_fakeip_ipv6(
        destination,
        control->flags,
        SB_SHARED_FLAG_FAKEIP_IPV6,
        control->fakeip_ipv6_prefix,
        control->fakeip_ipv6_mask)) return SB_SHARED_POLICY_PROXY;
    if ((control->flags & SB_SHARED_FLAG_BYPASS_PRIVATE_ADDRESS) != 0U &&
        sb_ebpf_ipv6_private_address(destination)) return SB_SHARED_POLICY_BYPASS;
    if (map_policy_flags == 0U) return SB_SHARED_POLICY_PROXY;
    if ((map_policy_flags & SB_SHARED_FLAG_BYPASS_IPV6) == 0U) return SB_SHARED_POLICY_PROXY;
    return map_lookup(&shared_bypass_ipv6, &key) == 0
        ? SB_SHARED_POLICY_PROXY
        : SB_SHARED_POLICY_CACHE_BYPASS;
}

#endif
