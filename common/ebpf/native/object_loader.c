// Copyright 2026, Asterisk4Magisk contributors
// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "runtime.h"

#include <elf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef R_BPF_64_64
#define R_BPF_64_64 1U
#endif
#ifndef R_BPF_64_32
#define R_BPF_64_32 10U
#endif

static bool object_range_valid(size_t offset, size_t size, size_t total) {
    return offset <= total && size <= total - offset;
}

static const Elf64_Shdr *object_section(
    const Elf64_Ehdr *header,
    size_t object_size,
    size_t index) {
    if (index >= header->e_shnum ||
        header->e_shentsize != sizeof(Elf64_Shdr) ||
        !object_range_valid(
            header->e_shoff,
            (size_t)header->e_shnum * sizeof(Elf64_Shdr),
            object_size)) {
        return NULL;
    }
    return (const Elf64_Shdr *)(
        (const uint8_t *)header + header->e_shoff + index * sizeof(Elf64_Shdr));
}

static const char *object_section_name(
    const Elf64_Ehdr *header,
    size_t object_size,
    const Elf64_Shdr *section) {
    const Elf64_Shdr *strings = object_section(header, object_size, header->e_shstrndx);
    if (strings == NULL || strings->sh_type != SHT_STRTAB ||
        !object_range_valid(strings->sh_offset, strings->sh_size, object_size) ||
        section->sh_name >= strings->sh_size) {
        return NULL;
    }
    return (const char *)header + strings->sh_offset + section->sh_name;
}

static const Elf64_Shdr *object_find_section(
    const Elf64_Ehdr *header,
    size_t object_size,
    const char *name,
    size_t *index_out) {
    for (size_t index = 0U; index < header->e_shnum; ++index) {
        const Elf64_Shdr *section = object_section(header, object_size, index);
        const char *current = section == NULL
            ? NULL
            : object_section_name(header, object_size, section);
        if (current != NULL && strcmp(current, name) == 0) {
            if (index_out != NULL) *index_out = index;
            return section;
        }
    }
    errno = ENOENT;
    return NULL;
}

static int object_relocate_section(
    const Elf64_Ehdr *header,
    size_t object_size,
    size_t source_section_index,
    size_t source_base,
    size_t text_section_index,
    size_t text_base,
    struct bpf_insn *instructions,
    size_t instruction_count,
    sb_ebpf_map_fd_resolver resolve_map,
    void *resolve_context) {
    for (size_t index = 0U; index < header->e_shnum; ++index) {
        const Elf64_Shdr *relocations = object_section(header, object_size, index);
        if (relocations == NULL || relocations->sh_type != SHT_REL ||
            relocations->sh_info != source_section_index) {
            continue;
        }
        const Elf64_Shdr *symbols = object_section(header, object_size, relocations->sh_link);
        if (symbols == NULL || symbols->sh_type != SHT_SYMTAB ||
            symbols->sh_entsize != sizeof(Elf64_Sym) ||
            !object_range_valid(symbols->sh_offset, symbols->sh_size, object_size)) {
            errno = ENOEXEC;
            return -1;
        }
        const Elf64_Shdr *strings = object_section(header, object_size, symbols->sh_link);
        if (strings == NULL || strings->sh_type != SHT_STRTAB ||
            !object_range_valid(strings->sh_offset, strings->sh_size, object_size) ||
            relocations->sh_entsize != sizeof(Elf64_Rel) ||
            !object_range_valid(relocations->sh_offset, relocations->sh_size, object_size)) {
            errno = ENOEXEC;
            return -1;
        }
        const Elf64_Rel *entries = (const Elf64_Rel *)(
            (const uint8_t *)header + relocations->sh_offset);
        size_t relocation_count = relocations->sh_size / sizeof(Elf64_Rel);
        const Elf64_Sym *symbol_table = (const Elf64_Sym *)(
            (const uint8_t *)header + symbols->sh_offset);
        size_t symbol_count = symbols->sh_size / sizeof(Elf64_Sym);
        const char *string_table = (const char *)header + strings->sh_offset;
        for (size_t relocation_index = 0U;
             relocation_index < relocation_count;
             ++relocation_index) {
            const Elf64_Rel *relocation = &entries[relocation_index];
            size_t symbol_index = ELF64_R_SYM(relocation->r_info);
            if (symbol_index >= symbol_count ||
                relocation->r_offset % sizeof(struct bpf_insn) != 0U) {
                errno = ENOEXEC;
                return -1;
            }
            size_t instruction_index = source_base + relocation->r_offset / sizeof(struct bpf_insn);
            const Elf64_Sym *symbol = &symbol_table[symbol_index];
            if (instruction_index >= instruction_count || symbol->st_name >= strings->sh_size) {
                errno = ENOEXEC;
                return -1;
            }
            uint32_t relocation_type = ELF64_R_TYPE(relocation->r_info);
            if (relocation_type == R_BPF_64_64) {
                if (instruction_index + 1U >= instruction_count) {
                    errno = ENOEXEC;
                    return -1;
                }
                int map_fd = resolve_map(
                    string_table + symbol->st_name,
                    resolve_context);
                if (map_fd < 0) return -1;
                instructions[instruction_index].src_reg = BPF_PSEUDO_MAP_FD;
                instructions[instruction_index].imm = map_fd;
                instructions[instruction_index + 1U].imm = 0;
            } else if (relocation_type == R_BPF_64_32) {
                size_t target_base;
                if (symbol->st_shndx == text_section_index) {
                    target_base = text_base;
                } else if (symbol->st_shndx == source_section_index) {
                    target_base = source_base;
                } else {
                    errno = ENOEXEC;
                    return -1;
                }
                if (symbol->st_value % sizeof(struct bpf_insn) != 0U) {
                    errno = ENOEXEC;
                    return -1;
                }
                size_t target_index = target_base + symbol->st_value / sizeof(struct bpf_insn);
                if (target_index >= instruction_count) {
                    errno = ENOEXEC;
                    return -1;
                }
                instructions[instruction_index].imm =
                    (int32_t)(target_index - instruction_index - 1U);
            } else {
                errno = ENOEXEC;
                return -1;
            }
        }
    }
    return 0;
}

static bool bpf_object_valid(const uint8_t *object, size_t object_size) {
    if (object == NULL || object_size < sizeof(Elf64_Ehdr)) return false;
    const Elf64_Ehdr *header = (const Elf64_Ehdr *)object;
    return memcmp(header->e_ident, ELFMAG, SELFMAG) == 0 &&
        header->e_ident[EI_CLASS] == ELFCLASS64 &&
        header->e_ident[EI_DATA] == ELFDATA2LSB &&
        header->e_machine == EM_BPF;
}

static int load_object_program_section(
    const Elf64_Ehdr *header,
    size_t object_size,
    const char *section_name,
    const struct sb_ebpf_program_descriptor *program,
    sb_ebpf_map_fd_resolver resolve_map,
    void *resolve_context,
    bool log_error) {
    size_t section_index = 0U;
    size_t text_section_index = SIZE_MAX;
    const Elf64_Shdr *section = object_find_section(
        header,
        object_size,
        section_name,
        &section_index);
    const Elf64_Shdr *text_section = object_find_section(
        header,
        object_size,
        ".text",
        &text_section_index);
    size_t text_size = text_section == NULL ? 0U : text_section->sh_size;
    if (section == NULL || section->sh_size == 0U ||
        section->sh_size % sizeof(struct bpf_insn) != 0U ||
        text_size % sizeof(struct bpf_insn) != 0U ||
        !object_range_valid(section->sh_offset, section->sh_size, object_size) ||
        (text_section != NULL && !object_range_valid(
            text_section->sh_offset, text_size, object_size))) {
        if (log_error) {
            fprintf(
                stderr,
                "%s section validation failed: section=%p text=%p object_size=%zu errno=%d\n",
                section_name,
                (const void *)section,
                (const void *)text_section,
                object_size,
                errno);
        }
        errno = ENOEXEC;
        return -1;
    }
    size_t combined_size = section->sh_size + text_size;
    struct bpf_insn *instructions = malloc(combined_size);
    if (instructions == NULL) return -1;
    memcpy(instructions, (const uint8_t *)header + section->sh_offset, section->sh_size);
    if (text_size != 0U) {
        memcpy(
            (uint8_t *)instructions + section->sh_size,
            (const uint8_t *)header + text_section->sh_offset,
            text_size);
    }
    size_t entry_instruction_count = section->sh_size / sizeof(struct bpf_insn);
    size_t instruction_count = combined_size / sizeof(struct bpf_insn);
    int result = -1;
    int entry_relocation = object_relocate_section(
            header,
            object_size,
            section_index,
            0U,
            text_section_index,
            entry_instruction_count,
            instructions,
            instruction_count,
            resolve_map,
            resolve_context);
    int text_relocation = entry_relocation == 0 && text_size != 0U
        ? object_relocate_section(
            header,
            object_size,
            text_section_index,
            entry_instruction_count,
            text_section_index,
            entry_instruction_count,
            instructions,
            instruction_count,
            resolve_map,
            resolve_context)
        : entry_relocation;
    if (entry_relocation == 0 && text_relocation == 0) {
        result = sb_ebpf_load_prog(
            instructions,
            instruction_count,
            program->name,
            program->type,
            program->attach_type,
            log_error);
    } else if (log_error) {
        fprintf(
            stderr,
            "%s relocation failed: entry=%d text=%d errno=%d\n",
            section_name,
            entry_relocation,
            text_relocation,
            errno);
    }
    int saved_errno = errno;
    free(instructions);
    errno = saved_errno;
    return result;
}

int sb_ebpf_load_object_program(
    const uint8_t *object,
    size_t object_size,
    const char *section_name,
    const struct sb_ebpf_program_descriptor *program,
    sb_ebpf_map_fd_resolver resolve_map,
    void *resolve_context,
    bool log_error) {
    if (!bpf_object_valid(object, object_size) || section_name == NULL ||
        program == NULL || program->fd == NULL || resolve_map == NULL) {
        errno = EINVAL;
        return -1;
    }
    return load_object_program_section(
        (const Elf64_Ehdr *)object,
        object_size,
        section_name,
        program,
        resolve_map,
        resolve_context,
        log_error);
}

int sb_ebpf_resolve_map_fd(
    const char *name,
    const void *runtime,
    const struct sb_ebpf_map_binding *bindings,
    size_t binding_count) {
    if (name == NULL || runtime == NULL || bindings == NULL) {
        errno = EINVAL;
        return -1;
    }
    for (size_t index = 0U; index < binding_count; ++index) {
        if (strcmp(name, bindings[index].name) == 0) {
            return *(const int *)((const uint8_t *)runtime + bindings[index].fd_offset);
        }
    }
    errno = ENOENT;
    return -1;
}
