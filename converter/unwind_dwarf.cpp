#include "unwind_dwarf.h"

#include <LIEF/BinaryStream/SpanStream.hpp>

void DwarfUnwindParser::parse(LIEF::MachO::Binary &binary) {
    const auto *ehframe_section = binary.get_section("__eh_frame");
    if (ehframe_section == nullptr) {
        std::cout << "No __eh_frame section\n";
        return;
    }

    sectionBegin = ehframe_section->address();
    sectionEnd = ehframe_section->address() + ehframe_section->size();

    char argStr[256];
    CieInfo cie;

    LIEF::SpanStream vs = ehframe_section->content();
    uint32_t p = 0;
    bool isIndirect;
    while (p < vs.size()) {
        vs.setpos(p);
        auto length = *vs.read<uint32_t>();
        auto cieOffset = *vs.read<uint32_t>();
        std::cout << std::hex << p << ' ' << length << ' ' << cieOffset << ' ';
        if (cieOffset == 0) {
            std::cout << "CIE\n";

            cie = CieInfo();

            auto version = *vs.read<uint8_t>();
            if (version != 1 && version != 3) {
                std::cout << "CIE version is not 1 or 3\n";
                return;
            }
            for (int i = 0; i < sizeof(argStr); i ++) {
                argStr[i] = *vs.read<char>();
                if (argStr[i] == 0)
                    break;
            }
            vs.read_uleb128(); // codeAlignFactor
            vs.read_sleb128(); // dataAlignFactor
            vs.read_uleb128(); // raReg

            if (argStr[0] == 'z') {
                vs.read_uleb128(); // argumentation data length
                for (int i = 0; i < sizeof(argStr) && argStr[i] != 0; i++) {
                    switch (argStr[i]) {
                        case 'z':
                            cie.fdesHaveAugmentationData = true;
                            break;
                        case 'P': {
                            auto personalityEncoding = *vs.read<uint8_t>();
                            readEncoded(vs, personalityEncoding, isIndirect);
                            break;
                        }
                        case 'L':
                            cie.lsdaEncoding = *vs.read<uint8_t>();
                            break;
                        case 'R':
                            cie.pointerEncoding = *vs.read<uint8_t>();
                            break;
                        default:
                            break;
                    }
                }
            }
            readInstructions(vs, cie, p + 4 + length - vs.pos());
        } else {
            std::cout << "FDE\n";
            readEncoded(vs, cie.pointerEncoding, isIndirect); // pcStart
            readEncoded(vs, cie.pointerEncoding & 0xf, isIndirect); // pcRange
            if (cie.fdesHaveAugmentationData) {
                auto augLen = *vs.read_uleb128();
                auto augEnd = vs.pos() + augLen;
                if (cie.lsdaEncoding != DW_EH_PE_omit && augLen > 0) {
                    auto lsdaStart = vs.pos();
                    if (readEncoded(vs, cie.lsdaEncoding & 0xf, isIndirect) != 0) {
                        // Reset pointer and re-parse LSDA address.
                        vs.setpos(lsdaStart);
                        readEncoded(vs, cie.lsdaEncoding, isIndirect);
                    }
                }
                vs.setpos(augEnd);
            }

            readInstructions(vs, cie, p + 4 + length - vs.pos());
        }

        p += 4 + length;
    }
}

void DwarfUnwindParser::readInstructions(LIEF::BinaryStream& stream, DwarfUnwindParser::CieInfo& cieInfo, size_t size) {
    auto instructionsEnd = stream.pos() + size;
    while (stream.pos() < instructionsEnd) {
        uint64_t reg;
        uint64_t reg2;
        int64_t offset;
        uint64_t length;
        uint8_t opcode = *stream.read<uint8_t>();
        uint8_t operand;
        bool isIndirect;
        switch (opcode) {
            case DW_CFA_nop:
                break;
            case DW_CFA_set_loc:
                readEncoded(stream, cieInfo.pointerEncoding, isIndirect);
                break;
            case DW_CFA_advance_loc1:
                stream.setpos(stream.pos() + 1);
                break;
            case DW_CFA_advance_loc2:
                stream.setpos(stream.pos() + 2);
                break;
            case DW_CFA_advance_loc4:
                stream.setpos(stream.pos() + 4);
                break;
            case DW_CFA_offset_extended:
                stream.read_uleb128();
                stream.read_uleb128();
                break;
            case DW_CFA_restore_extended:
                stream.read_uleb128();
                break;
            case DW_CFA_undefined:
                stream.read_uleb128();
                break;
            case DW_CFA_same_value:
                stream.read_uleb128();
                break;
            case DW_CFA_register:
                stream.read_uleb128();
                stream.read_uleb128();
                break;
            case DW_CFA_def_cfa:
                stream.read_uleb128();
                stream.read_uleb128();
                break;
            case DW_CFA_def_cfa_register:
                stream.read_uleb128();
                break;
            case DW_CFA_def_cfa_offset:
                stream.read_uleb128();
                break;
            case DW_CFA_def_cfa_expression://TODO:?
            case DW_CFA_expression://TODO:?
                length = *stream.read_uleb128();
                stream.setpos(stream.pos() + length);
                length = *stream.read_uleb128();
                stream.setpos(stream.pos() + length);
                break;
            case DW_CFA_offset_extended_sf:
                stream.read_uleb128();
                stream.read_sleb128();
                break;
            case DW_CFA_def_cfa_sf:
                stream.read_uleb128();
                stream.read_sleb128();
                break;
            case DW_CFA_def_cfa_offset_sf:
                stream.read_sleb128();
                break;
            case DW_CFA_val_offset:
                stream.read_uleb128();
                stream.read_uleb128();
                break;
            case DW_CFA_val_offset_sf:
                stream.read_uleb128();
                stream.read_sleb128();
                break;
            case DW_CFA_val_expression:
                stream.read_uleb128();
                stream.read_uleb128();
                break;
            case DW_CFA_GNU_args_size:
                stream.read_uleb128();
                break;
            case DW_CFA_GNU_negative_offset_extended:
                stream.read_uleb128();
                stream.read_uleb128();
                break;

            default:
                operand = opcode & 0x3F;
                switch (opcode & 0xC0) {
                    case DW_CFA_offset:
                        reg = operand;
                        stream.read_uleb128();
                        break;
                    case DW_CFA_advance_loc:
                        break;
                    case DW_CFA_restore:
                        reg = operand;
                        break;
                    default:
                        throw std::runtime_error("unknown CFA opcode");
                }
        }
    }

}

uint64_t DwarfUnwindParser::readEncoded(LIEF::BinaryStream& stream, uint8_t encoding, bool& isIndirect) {
    uint64_t result;
    uint64_t addr = sectionBegin + stream.pos();

    // first get value
    switch (encoding & 0x0F) {
        case DW_EH_PE_ptr:
            result = *stream.read<uint64_t>();
            break;
        case DW_EH_PE_uleb128:
            result = *stream.read_uleb128();
            break;
        case DW_EH_PE_udata2:
            result = *stream.read<uint16_t>();
            break;
        case DW_EH_PE_udata4:
            result = *stream.read<uint32_t>();
            break;
        case DW_EH_PE_udata8:
            result = *stream.read<uint64_t>();
            break;
        case DW_EH_PE_sleb128:
            result = (uint64_t) *stream.read<int64_t>();
            break;
        case DW_EH_PE_sdata2:
            // Sign extend from signed 16-bit value.
            result = (uint64_t) *stream.read<int16_t>();
            break;
        case DW_EH_PE_sdata4:
            // Sign extend from signed 32-bit value.
            result = (uint64_t) *stream.read<int32_t>();
            break;
        case DW_EH_PE_sdata8:
            result = (uint64_t) *stream.read<int64_t>();
            break;
        default:
            throw std::runtime_error("unknown pointer encoding");
    }

    // then add relative offset
    switch (encoding & 0x70) {
        case DW_EH_PE_absptr:
            // do nothing
            break;
        case DW_EH_PE_pcrel:
            result += addr;
            std::cout << "Encountered pcrel: " << std::hex << (addr - sectionBegin) << ' ' << result << ' ' << (encoding&0xf) << '\n';
            pcrelUsages.push_back({addr - sectionBegin, (uint8_t) (encoding & 0xf)});
            break;
        case DW_EH_PE_textrel:
            throw std::runtime_error("DW_EH_PE_textrel pointer encoding not supported");
        case DW_EH_PE_datarel:
            throw std::runtime_error("DW_EH_PE_datarel pointer encoding not supported");
        case DW_EH_PE_funcrel:
            throw std::runtime_error("DW_EH_PE_funcrel pointer encoding not supported");
        case DW_EH_PE_aligned:
            throw std::runtime_error("DW_EH_PE_aligned pointer encoding not supported");
        default:
            throw std::runtime_error("unknown pointer encoding");
    }

    isIndirect = (encoding & DW_EH_PE_indirect);
    if (encoding & DW_EH_PE_indirect) {
        if (result >= sectionBegin && result < sectionEnd)
            throw std::runtime_error("DW_EH_PE_indirect pointer encoding to the eh_frame section is not supported");
    }

    return result;
}