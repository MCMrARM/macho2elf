//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//
// Darwin's alternative to DWARF based unwind encodings.
//
//===----------------------------------------------------------------------===//
#pragma once

#include <vector>
#include <cstdint>

#include <LIEF/LIEF.hpp>

// architecture independent bits
enum {
    UNWIND_IS_NOT_FUNCTION_START           = 0x80000000,
    UNWIND_HAS_LSDA                        = 0x40000000,
    UNWIND_PERSONALITY_MASK                = 0x30000000,
};

#define UNWIND_PERSONALITY(x) (((x) >> 28) & 3u)

//
// x86_64
//
// 1-bit: start
// 1-bit: has lsda
// 2-bit: personality index
//
// 4-bits: 0=old, 1=rbp based, 2=stack-imm, 3=stack-ind, 4=DWARF
//  rbp based:
//        15-bits (5*3-bits per reg) register permutation
//        8-bits for stack offset
//  frameless:
//        8-bits stack size
//        3-bits stack adjust
//        3-bits register count
//        10-bits register permutation
//
enum {
    UNWIND_X86_64_MODE_MASK                         = 0x0F000000,
    UNWIND_X86_64_MODE_RBP_FRAME                    = 0x01000000,
    UNWIND_X86_64_MODE_STACK_IMMD                   = 0x02000000,
    UNWIND_X86_64_MODE_STACK_IND                    = 0x03000000,
    UNWIND_X86_64_MODE_DWARF                        = 0x04000000,

    UNWIND_X86_64_RBP_FRAME_REGISTERS               = 0x00007FFF,
    UNWIND_X86_64_RBP_FRAME_OFFSET                  = 0x00FF0000,

    UNWIND_X86_64_FRAMELESS_STACK_SIZE              = 0x00FF0000,
    UNWIND_X86_64_FRAMELESS_STACK_ADJUST            = 0x0000E000,
    UNWIND_X86_64_FRAMELESS_STACK_REG_COUNT         = 0x00001C00,
    UNWIND_X86_64_FRAMELESS_STACK_REG_PERMUTATION   = 0x000003FF,

    UNWIND_X86_64_DWARF_SECTION_OFFSET              = 0x00FFFFFF,
};

enum {
    UNWIND_X86_64_REG_NONE       = 0,
    UNWIND_X86_64_REG_RBX        = 1,
    UNWIND_X86_64_REG_R12        = 2,
    UNWIND_X86_64_REG_R13        = 3,
    UNWIND_X86_64_REG_R14        = 4,
    UNWIND_X86_64_REG_R15        = 5,
    UNWIND_X86_64_REG_RBP        = 6,
};

struct CompactUnwindInfo {
    struct Entry {
        uint32_t functionOffset;
        uint32_t encoding;
        uint32_t lsda;
    };

    std::vector<uint32_t> personalities;
    std::vector<Entry> entries;
};

CompactUnwindInfo decodeCompactUnwindTable(LIEF::MachO::Binary& binary);

void decodeCompatEncodingPermutation(uint32_t regCount, uint32_t permutation, int registersSaved[6]);