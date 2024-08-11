#pragma once

#include <LIEF/iostream.hpp>
#include "unwind_dwarf.h"

struct UnwindRewriter {

public:
    using addr_t = uint64_t;

private:
    const addr_t base;
    LIEF::vector_iostream writer;
    std::vector<uint32_t> relocations;

    DwarfUnwindParser dwarfParser;

    void writeCie(uint32_t personality);

    void convertEntry(LIEF::MachO::Binary& bin, CompactUnwindInfo const& info, CompactUnwindInfo::Entry entry, size_t length);

    void convertRbpFrameEncoding(uint32_t encoding);
    void convertFramelessEncoding(LIEF::MachO::Binary& bin, CompactUnwindInfo::Entry entry, bool indirectStackSize);

public:
    std::vector<std::pair<uint32_t, uint32_t>> searchMap;

    explicit UnwindRewriter(addr_t base) : base(base) {}

    void convert(LIEF::MachO::Binary& bin, CompactUnwindInfo const& info);

    std::size_t size() const {
        return writer.size();
    }

    const std::vector<uint8_t>& data() {
        return writer.raw();
    }

    void fixup(uint32_t addr);

};