#pragma once

#include <LIEF/LIEF.hpp>
#include <LIEF/BinaryStream/BinaryStream.hpp>
#include "dwarf2.h"

class DwarfUnwindParser {

private:
    struct CieInfo {
        bool fdesHaveAugmentationData = false;
        uint8_t pointerEncoding = 0;
        uint8_t lsdaEncoding = DW_EH_PE_omit;
    };

    struct EncodedValueInfo {
        uint64_t address;
        uint8_t encoding;
    };

    uint64_t readEncoded(LIEF::BinaryStream& stream, uint8_t encoding, bool& isIndirect);

    void readInstructions(LIEF::BinaryStream& stream, CieInfo& cie, size_t size);

public:
    uint64_t sectionBegin = 0, sectionEnd = 0;
    std::vector<EncodedValueInfo> pcrelUsages;

    void parse(LIEF::MachO::Binary &binary);

};