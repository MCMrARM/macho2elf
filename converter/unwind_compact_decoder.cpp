#include <LIEF/LIEF.hpp>
#include "LIEF/BinaryStream/SpanStream.hpp"
#include "unwind_compact_decoder.h"
#include "unwind_compact_structures.h"

static uint32_t findLsda(const unwind_info_section_header_lsda_index_entry* lsdaTab, size_t lsdaCount, uint32_t funcOff);

CompactUnwindInfo decodeCompactUnwindTable(LIEF::MachO::Binary &binary) {
    static constexpr size_t UNWIND_COMPRESSED = 3;
    static constexpr size_t UNWIND_UNCOMPRESSED = 2;

    CompactUnwindInfo ret;

    const auto *unwind_section = binary.get_section("__unwind_info");
    if (unwind_section == nullptr) {
        std::cout << "No __unwind_info section\n";
        return ret;
    }

    LIEF::SpanStream vs = unwind_section->content();

    // Get section content
    const auto hdr = vs.read<unwind_info_section_header>();
    if (!hdr)
        throw std::runtime_error("Can't read unwind section header!");

    ret.personalities.resize(hdr->personalityArrayCount);
    vs.setpos(hdr->personalityArraySectionOffset);
    for (size_t i = 0; i < hdr->personalityArrayCount; i++)
        ret.personalities[i] = *vs.read<uint32_t>();

    uint32_t compact_encodings[256];
    size_t common_encoding_count = hdr->commonEncodingsArrayCount;
    if (common_encoding_count > 256)
        throw std::runtime_error("Too many common encodings");

    vs.setpos(hdr->commonEncodingsArraySectionOffset);
    for (size_t i = 0; i < common_encoding_count; i++)
        compact_encodings[i] = *vs.read<uint32_t>();

    vs.setpos(hdr->indexSectionOffset);

    for (size_t i = 0; i < hdr->indexCount; ++i) {
        const auto sectionHdr = vs.read<unwind_info_section_header_index_entry>();
        auto nextSectionHdr = vs.peek<unwind_info_section_header_index_entry>();
        if (!sectionHdr)
            throw std::runtime_error("Can't read function information at index " + std::to_string(i));

        const size_t secondLvlOff = sectionHdr->secondLevelPagesSectionOffset;
        const size_t lsdaOff = sectionHdr->lsdaIndexArraySectionOffset;
        const size_t lsdaEnd = i + 1 < hdr->indexCount ? nextSectionHdr->lsdaIndexArraySectionOffset : lsdaOff;
        const size_t lsdaCount = (lsdaEnd - lsdaOff) / sizeof(unwind_info_section_header_lsda_index_entry);
        auto lsdaTab = (const unwind_info_section_header_lsda_index_entry*) ((uintptr_t) unwind_section->content().data() + lsdaOff);

        if (secondLvlOff > 0 && vs.can_read<unwind_info_regular_second_level_page_header>(secondLvlOff)) {
            const size_t saved_pos = vs.pos();

            vs.setpos(secondLvlOff);
            const auto lvlHdr = vs.peek<unwind_info_regular_second_level_page_header>(secondLvlOff);
            if (!lvlHdr) {
                break;
            }

//            std::cout << "==== " << lvlHdr->kind << '\n';
            if (lvlHdr->kind == UNWIND_COMPRESSED) {
                const auto lvlCompressedHdr = vs.read<unwind_info_compressed_second_level_page_header>();
                if (!lvlCompressedHdr)
                    throw std::runtime_error("Can't read lvlCompressedHdr");

                if (lvlCompressedHdr->encodingsCount + common_encoding_count > 256)
                    throw std::runtime_error("Too many encodings");

                vs.setpos(secondLvlOff + lvlCompressedHdr->encodingsPageOffset);
                for (size_t j = 0; j < lvlCompressedHdr->encodingsCount; ++j) {
                    compact_encodings[common_encoding_count + j] = *vs.read<uint32_t>();
                }

                vs.setpos(secondLvlOff + lvlCompressedHdr->entryPageOffset);
                for (size_t j = 0; j < lvlCompressedHdr->entryCount; ++j) {
                    auto entry = vs.read<uint32_t>();
                    uint32_t funcOff = sectionHdr->functionOffset + (*entry & 0xffffff);
                    uint32_t encoding = compact_encodings[*entry >> 24];
//                    std::cout << std::hex << funcOff << ' ' << encoding << '\n';
                    uint32_t lsda = encoding & UNWIND_HAS_LSDA ? findLsda(lsdaTab, lsdaCount, funcOff) : 0;
                    ret.entries.push_back({funcOff, encoding, lsda});
                }
            } else if (lvlHdr->kind == UNWIND_UNCOMPRESSED) {
                const auto lvlRegularHdr = vs.read<unwind_info_regular_second_level_page_header>();
                if (!lvlRegularHdr)
                    throw std::runtime_error("Can't read lvlRegularHdr");

                vs.setpos(secondLvlOff + lvlRegularHdr->entryPageOffset);
                for (size_t j = 0; j < lvlRegularHdr->entryCount; ++j) {
                    auto entry = vs.read<unwind_info_regular_second_level_entry>();
//                    std::cout << std::hex << entry->functionOffset << ' ' << entry->encoding << '\n';
                    uint32_t lsda = entry->encoding & UNWIND_HAS_LSDA ? findLsda(lsdaTab, lsdaCount, entry->functionOffset) : 0;
                    ret.entries.push_back({entry->functionOffset, entry->encoding, lsda});
                }
            } else {
                throw std::runtime_error("Unknown 2nd level kind: " + std::to_string(lvlHdr->kind));
            }

            vs.setpos(saved_pos);
        }

    }

    return ret;
}


static uint32_t findLsda(const unwind_info_section_header_lsda_index_entry* lsdaTab, size_t lsdaCount, uint32_t funcOff) {
    auto it = std::lower_bound(lsdaTab, lsdaTab + lsdaCount, unwind_info_section_header_lsda_index_entry{funcOff, 0},
                               [&](auto const& a, auto const& b) { return a.functionOffset < b.functionOffset; });
    if (it == lsdaTab + lsdaCount || it->functionOffset != funcOff)
        throw std::runtime_error("Failed to find the functionOffset in the lsda table!");
    return it->lsdaOffset;
}

void decodeCompatEncodingPermutation(uint32_t regCount, uint32_t permutation, int registersSaved[6]) {
    uint32_t permunreg[6];
    switch (regCount) {
        case 6:
            permunreg[0] = permutation / 120;
            permutation -= (permunreg[0] * 120);
            permunreg[1] = permutation / 24;
            permutation -= (permunreg[1] * 24);
            permunreg[2] = permutation / 6;
            permutation -= (permunreg[2] * 6);
            permunreg[3] = permutation / 2;
            permutation -= (permunreg[3] * 2);
            permunreg[4] = permutation;
            permunreg[5] = 0;
            break;
        case 5:
            permunreg[0] = permutation / 120;
            permutation -= (permunreg[0] * 120);
            permunreg[1] = permutation / 24;
            permutation -= (permunreg[1] * 24);
            permunreg[2] = permutation / 6;
            permutation -= (permunreg[2] * 6);
            permunreg[3] = permutation / 2;
            permutation -= (permunreg[3] * 2);
            permunreg[4] = permutation;
            break;
        case 4:
            permunreg[0] = permutation / 60;
            permutation -= (permunreg[0] * 60);
            permunreg[1] = permutation / 12;
            permutation -= (permunreg[1] * 12);
            permunreg[2] = permutation / 3;
            permutation -= (permunreg[2] * 3);
            permunreg[3] = permutation;
            break;
        case 3:
            permunreg[0] = permutation / 20;
            permutation -= (permunreg[0] * 20);
            permunreg[1] = permutation / 4;
            permutation -= (permunreg[1] * 4);
            permunreg[2] = permutation;
            break;
        case 2:
            permunreg[0] = permutation / 5;
            permutation -= (permunreg[0] * 5);
            permunreg[1] = permutation;
            break;
        case 1:
            permunreg[0] = permutation;
            break;
    }
    // re-number registers back to standard numbers
    bool used[7] = { false, false, false, false, false, false, false };
    for (uint32_t i = 0; i < regCount; ++i) {
        uint32_t renum = 0;
        for (int u = 1; u < 7; ++u) {
            if (!used[u]) {
                if (renum == permunreg[i]) {
                    registersSaved[i] = u;
                    used[u] = true;
                    break;
                }
                ++renum;
            }
        }
    }
}