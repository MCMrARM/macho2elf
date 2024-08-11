#include <iostream>
#include <cstdio>
#include <LIEF/LIEF.hpp>

#include "unwind_compact_decoder.h"
#include "unwind_dwarf.h"


int main(int argc, char* argv[]) {
    auto macho = LIEF::MachO::Parser::parse(std::string(argv[1]));
    std::cout << "Binary count: " << macho->size() << '\n';
    auto& binary = *macho->at(0);

    bool isExe = binary.header().file_type() == LIEF::MachO::FILE_TYPES::MH_EXECUTE;

    std::cout << "==============\n";
    std::cout << "COMMANDS\n";
    std::cout << "==============\n";

    for (const auto& command : binary.commands()) {
        std::cout << command << '\n';
    }

    std::cout << '\n';
    std::cout << "==============\n";
    std::cout << "RELOCATIONS\n";
    std::cout << "==============\n";

    for (const auto& reloc : binary.relocations()) {
        std::cout << reloc << '\n';
    }

//    DwarfUnwindParser dwarfParser;
//    dwarfParser.parse(binary);

    std::cout << '\n';
    std::cout << "==============\n";
    std::cout << "COMPACT UNWIND\n";
    std::cout << "==============\n";


    auto tab = decodeCompactUnwindTable(binary);
    for (auto& et : tab.personalities) {
        std::cout << "Personality: " << std::hex << et << '\n';
    }
    std::cout << '\n';
    for (auto& et : tab.entries) {
        std::cout << std::hex << et.functionOffset << ' ' << et.encoding << '\n';
    }

    return 0;
}
