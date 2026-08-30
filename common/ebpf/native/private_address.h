// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_PRIVATE_ADDRESS_H
#define SING_BOX_EBPF_PRIVATE_ADDRESS_H

#include <linux/types.h>
#include <stdbool.h>

static __attribute__((always_inline)) __u32 sb_ebpf_load_word(const __u8 value[4]) {
    __u32 word;
    __builtin_memcpy(&word, value, sizeof(word));
    return word;
}

static __attribute__((always_inline)) bool sb_ebpf_prefix_word_match(
    const __u8 address[4],
    const __u8 prefix[4],
    const __u8 mask[4]) {
    return ((sb_ebpf_load_word(address) ^ sb_ebpf_load_word(prefix)) &
        sb_ebpf_load_word(mask)) == 0U;
}

static __attribute__((always_inline)) bool sb_ebpf_prefix_match(
    const __u8 address[16],
    const __u8 prefix[16],
    const __u8 mask[16]) {
    return sb_ebpf_prefix_word_match(address, prefix, mask) &&
        sb_ebpf_prefix_word_match(address + 4U, prefix + 4U, mask + 4U) &&
        sb_ebpf_prefix_word_match(address + 8U, prefix + 8U, mask + 8U) &&
        sb_ebpf_prefix_word_match(address + 12U, prefix + 12U, mask + 12U);
}

static __attribute__((always_inline)) bool sb_ebpf_ipv4_prefix_match(
    const __u8 address[4],
    const __u8 prefix[4],
    const __u8 mask[4]) {
    return sb_ebpf_prefix_word_match(address, prefix, mask);
}

static __attribute__((always_inline)) bool sb_ebpf_ipv4_safety_bypass(const __u8 address[4]) {
    return address[0] == 0U || address[0] == 127U || address[0] >= 224U;
}

static __attribute__((always_inline)) bool sb_ebpf_ipv6_safety_bypass(const __u8 address[16]) {
    __u32 words[4];
    __builtin_memcpy(words, address, sizeof(words));
    if ((words[0] | words[1] | words[2] | words[3]) == 0U || address[0] == 0xffU) return true;
    if ((words[0] | words[1] | words[2]) != 0U) return false;
    if (address[12] == 0U && address[13] == 0U && address[14] == 0U && address[15] == 1U) return true;
    return address[12] == 0xffU;
}

static __attribute__((always_inline)) bool sb_ebpf_ipv4_private_address(const __u8 address[4]) {
    if (address[0] == 0U || address[0] == 10U || address[0] == 127U || address[0] >= 224U) return true;
    if (address[0] == 100U && (address[1] & 0xc0U) == 0x40U) return true;
    if (address[0] == 169U && address[1] == 254U) return true;
    if (address[0] == 172U && (address[1] & 0xf0U) == 0x10U) return true;
    return address[0] == 192U && address[1] == 168U;
}

static __attribute__((always_inline)) bool sb_ebpf_ipv6_private_address(const __u8 address[16]) {
    if (address[0] == 0xffU || (address[0] & 0xfeU) == 0xfcU) return true;
    return address[0] == 0xfeU && (address[1] & 0xc0U) == 0x80U;
}

#endif
