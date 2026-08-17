// Copyright 2026, Asterisk4Magisk contributors
// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_SHARED_NETWORK_REWRITE_H
#define SING_BOX_EBPF_SHARED_NETWORK_REWRITE_H

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

#endif
