#include "unwind_compact_decoder.h"
#include "dwarf2.h"
#include "unwind_registers.h"
#include "unwind_rewriter.h"

void UnwindRewriter::convert(LIEF::MachO::Binary& bin, CompactUnwindInfo const& info) {
    dwarfParser.parse(bin);

    auto origEhFrame = bin.get_section("__eh_frame");
    auto origEhFrameContent = origEhFrame->content();
    writer.write(origEhFrameContent.subspan(0, origEhFrameContent.size() - 4)); // remove the null terminator

    LIEF::MachO::Section const* section = nullptr;
    auto count = info.entries.size();
    for (size_t i = 0; i < count; i++) {
        auto& entry = info.entries[i];
        auto faddr = entry.functionOffset;
        if (!section || !(base + faddr >= section->address() && base + faddr < section->address() + section->size())) {
            section = nullptr;
            for (auto const& sec : bin.sections()) {
                if (base + faddr >= sec.address() && base + faddr < sec.address() + sec.size()) {
                    section = &sec;
                    break;
                }
            }
        }

        size_t fend = section ? (section->address() + section->size()) : (size_t)-1;
        if (i + 1 < count && info.entries[i + 1].functionOffset < fend)
            fend = info.entries[i + 1].functionOffset;
        if (fend == (size_t)-1) {
            std::cout << "Could not guess function size for " << std::hex << faddr << std::dec << " (" << i << ")\n";
            continue;
        }

        switch (entry.encoding & UNWIND_X86_64_MODE_MASK) {
            case UNWIND_X86_64_MODE_RBP_FRAME:
            case UNWIND_X86_64_MODE_STACK_IMMD:
            case UNWIND_X86_64_MODE_STACK_IND:
                convertEntry(bin, info, entry, fend - faddr);
                continue;
            case UNWIND_X86_64_MODE_DWARF:
                searchMap.emplace_back(entry.functionOffset, entry.encoding & UNWIND_X86_64_DWARF_SECTION_OFFSET);
                continue;
            default:
                continue;
        }
    }

    writer.write<uint32_t>(0);
    std::sort(searchMap.begin(), searchMap.end());
}

void UnwindRewriter::writeCie(uint32_t personality) {
    auto pLength = writer.tellp();
    writer.write<uint32_t>(0); // length
    writer.write<uint32_t>(0); // cieOffset

    writer.write<uint8_t>(1); // version
    writer.write<char>('z');
    if (personality != 0) {
        writer.write<char>('P');
        writer.write<char>('L');
    }
    writer.write<char>('R');
    writer.write<char>(0);
    writer.write_uleb128(1); // codeAlignFactor
    writer.write_sleb128(-8); // dataAlignFactor
    writer.write_uleb128(16); // raReg

    // Argumentation data
    writer.write_uleb128((personality != 0 ? (5 + 1) : 0) + 1);
    if (personality != 0) {
        // P
        writer.write<uint8_t>(DW_EH_PE_indirect | DW_EH_PE_pcrel | DW_EH_PE_sdata4); // personalityEncoding
        relocations.push_back(writer.tellp());
        printf("personality %x %x\n", (uint32_t)writer.tellp(), personality);
        writer.write<int32_t>(personality - (uint32_t)writer.tellp()); // personality
        // L
        writer.write<uint8_t>(DW_EH_PE_pcrel | DW_EH_PE_sdata4); // lsdaEncoding
    }
    // R
    writer.write<uint8_t>(DW_EH_PE_pcrel | DW_EH_PE_sdata4); // pointerEncoding

    // Instructions
    writer.write<uint8_t>(DW_CFA_def_cfa);
    writer.write_uleb128(UNW_X86_64_RSP);
    writer.write_uleb128(8);
    writer.write<uint8_t>(DW_CFA_offset | UNW_X86_64_RIP);
    writer.write_uleb128(1);
    writer.align(8);

    auto p = writer.tellp();
    writer.seekp(pLength);
    writer.write<uint32_t>(p - pLength - 4);
    writer.seekp(p);
}

void UnwindRewriter::convertEntry(LIEF::MachO::Binary& bin, const CompactUnwindInfo& info, CompactUnwindInfo::Entry entry, size_t length) {
    auto hasLsda = entry.encoding & UNWIND_HAS_LSDA;

    auto pCie = writer.tellp();
    writeCie(hasLsda ? info.personalities.at(UNWIND_PERSONALITY(entry.encoding) - 1) : 0);

    auto pLength = writer.tellp();
    searchMap.emplace_back(entry.functionOffset, (uint32_t) pLength);
    writer.write<uint32_t>(0); // length
    writer.write<uint32_t>(writer.tellp() - pCie); // cieOffset

    relocations.push_back(writer.tellp());
    writer.write<uint32_t>(entry.functionOffset - (uint32_t)writer.tellp());
    writer.write<int32_t>((int32_t) length);

    // Argumentation data
    if (hasLsda) {
        writer.write_uleb128(4); // length
        relocations.push_back(writer.tellp());
        writer.write<int32_t>(entry.lsda - writer.tellp());
    } else {
        writer.write_uleb128(0); // length
    }

    // Instructions
    switch (entry.encoding & UNWIND_X86_64_MODE_MASK) {
        case UNWIND_X86_64_MODE_RBP_FRAME:
            convertRbpFrameEncoding(entry.encoding);
            break;
        case UNWIND_X86_64_MODE_STACK_IMMD:
            convertFramelessEncoding(bin, entry, false);
            break;
        case UNWIND_X86_64_MODE_STACK_IND:
            convertFramelessEncoding(bin, entry, true);
            break;
        default:
            break;
    }
    writer.align(8);

    auto p = writer.tellp();
    writer.seekp(pLength);
    writer.write<uint32_t>(p - pLength - 4);
    writer.seekp(p);
}

#define EXTRACT_BITS(value, mask)                                              \
  ((value >> __builtin_ctz(mask)) & (((1 << __builtin_popcount(mask))) - 1))

static inline uint32_t compactRegisterMap[] = {
        0, UNW_X86_64_RBX, UNW_X86_64_R12, UNW_X86_64_R13, UNW_X86_64_R14, UNW_X86_64_R15, UNW_X86_64_RBP
};

void UnwindRewriter::convertRbpFrameEncoding(uint32_t encoding) {
    uint32_t savedRegistersOffset =
            EXTRACT_BITS(encoding, UNWIND_X86_64_RBP_FRAME_OFFSET);
    uint32_t savedRegistersLocations =
            EXTRACT_BITS(encoding, UNWIND_X86_64_RBP_FRAME_REGISTERS);

    // encoding for: push rbp
    writer.write<uint8_t>(DW_CFA_def_cfa_offset);
    writer.write_uleb128(16);
    writer.write<uint8_t>(DW_CFA_offset | UNW_X86_64_RBP);
    writer.write_uleb128(2);
    // encoding for: mov rbp, rsp
    writer.write<uint8_t>(DW_CFA_def_cfa_register);
    writer.write_uleb128(UNW_X86_64_RBP);

    int64_t savedRegisters = savedRegistersOffset + 2;
    for (int i = 0; i < 5; ++i) {
        uint32_t reg = savedRegistersLocations & 0x7;
        if (reg == 0)
            continue;
        writer.write<uint8_t>(DW_CFA_offset | compactRegisterMap[reg]);
        writer.write_sleb128(savedRegisters--);

        savedRegistersLocations = (savedRegistersLocations >> 3);
    }
}

void UnwindRewriter::convertFramelessEncoding(LIEF::MachO::Binary& bin, CompactUnwindInfo::Entry entry, bool indirectStackSize) {
    auto encoding = entry.encoding;
    uint32_t stackSizeEncoded =
            EXTRACT_BITS(encoding, UNWIND_X86_64_FRAMELESS_STACK_SIZE);
    uint32_t stackAdjust =
            EXTRACT_BITS(encoding, UNWIND_X86_64_FRAMELESS_STACK_ADJUST);
    uint32_t regCount =
            EXTRACT_BITS(encoding, UNWIND_X86_64_FRAMELESS_STACK_REG_COUNT);
    uint32_t permutation =
            EXTRACT_BITS(encoding, UNWIND_X86_64_FRAMELESS_STACK_REG_PERMUTATION);

    uint32_t stackSize = stackSizeEncoded * 8;
    if (indirectStackSize) {
        // stack size is encoded in subl $xxx,%esp instruction
        auto content = bin.get_content_from_virtual_address(base + entry.functionOffset + stackSizeEncoded, 4);
        if (content.size() != 4)
            throw std::runtime_error("Failed to get subl");
        auto subl = *(uint32_t*)content.data();
//        uint32_t subl = addressSpace.get32(functionStart + stackSizeEncoded);
        stackSize = subl + 8 * stackAdjust;
    }

    int registersSaved[6];
    decodeCompatEncodingPermutation(regCount, permutation, registersSaved);

    writer.write<uint8_t>(DW_CFA_def_cfa_offset);
    writer.write_uleb128(stackSize);

    int64_t savedRegisters = 1 + regCount;
    for (uint32_t i = 0; i < regCount; ++i) {
        writer.write<uint8_t>(DW_CFA_offset | compactRegisterMap[registersSaved[i]]);
        writer.write_sleb128(savedRegisters--);
    }

}

void UnwindRewriter::fixup(uint32_t addr) {
    auto& p = writer.raw();
    for (auto e : relocations) {
        auto& val = (uint32_t&) p[e];
        val -= addr;
    }
    for (auto e : dwarfParser.pcrelUsages) {
        auto enc = e.encoding & 0xf;
        if (enc == DW_EH_PE_sdata4) {
            auto& val = (uint32_t&) p[e.address];
            val += addr - dwarfParser.sectionBegin;
        } else {
            std::cout << "cannot fixup original dwarf relocation: " << std::hex << enc << std::dec << '\n';
        }
    }
}