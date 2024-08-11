#include <iostream>
#include <cstdio>
#include <LIEF/LIEF.hpp>
#include <elfio/elfio.hpp>
#include "translation_helper.h"
#include "unwind_compact_decoder.h"
#include "unwind_rewriter.h"
#include "str_data.h"

using namespace ELFIO;

static Elf_Word convert_section_type(LIEF::MachO::MACHO_SECTION_TYPES type);
static Elf_Word map_prot(LIEF::MachO::VM_PROTECTIONS prot);

static void setup_elf(elfio& writer, bool isExe) {
    writer.create(ELFCLASS64, ELFDATA2LSB);
    writer.set_os_abi(ELFOSABI_LINUX);
    writer.set_type(isExe ? ET_EXEC : ET_DYN);
    writer.set_machine(EM_X86_64);

    auto phdr = writer.segments.add();
    phdr->set_type(PT_PHDR);
    phdr->set_flags(PF_R | PF_X);
    phdr->set_align(8);
    phdr->set_virtual_address(writer.get_base() + 0x40);
    phdr->set_physical_address(writer.get_base() + 0x40);

    auto interpSec = writer.sections.add(".interp");
    auto interpName = "/lib64/ld-linux-x86-64.so.2";
    interpSec->set_data(interpName, strlen(interpName) + 1);
    interpSec->set_type(SHT_PROGBITS);
    interpSec->set_flags(SHF_ALLOC);
    interpSec->set_addr_align(1);
    auto interp = writer.segments.add();
    interp->set_type(PT_INTERP);
    interp->set_flags(PF_R);
    interp->add_section(interpSec, 1);
    interp->set_align(1);
}

struct DynBuilder {

private:
    struct SymbolInfo {
        std::string name;
        unsigned char st_info;
        Elf64_Half shndx = 0;
        Elf64_Addr value;
        Elf_Xword size;
    };

    std::vector<Elf64_Dyn> dyn;
    StrData dynstr;
    std::size_t tagDynStr, tagDynStrSz;
    std::size_t tagDynSym;
    std::size_t tagGnuHash;
    std::size_t tagDynRela, tagDynRelaSz;
    std::size_t tagFini;
    std::vector<SymbolInfo> symbols;
    std::vector<Elf64_Rela> rela;

    inline std::size_t addDyn(Elf_Sxword tag, Elf_Xword val) {
        auto ret = dyn.size();
        Elf64_Dyn d = {tag};
        d.d_un.d_val = val;
        dyn.push_back(d);
        return ret;
    }

public:
    section* dynstrSec;
    section* dynsymSec;
    section* dynamicSec;
    section* gnuHashSec;
    section* relaDynSec;

    std::map<std::string, Elf64_Word> symbolMap;

    DynBuilder() {
        symbols.push_back({});
    }

    void build(elfio& writer, Elf64_Addr base, std::vector<std::string> const& neededLibs, section* elfInitSec) {
        dynstrSec = writer.sections.add(".dynstr");
        dynstrSec->set_type(SHT_STRTAB);
        dynstrSec->set_flags(SHF_ALLOC);
        dynstrSec->set_addr_align(1);

        dynsymSec = writer.sections.add(".dynsym");
        dynsymSec->set_type(SHT_DYNSYM);
        dynsymSec->set_flags(SHF_ALLOC);
        dynsymSec->set_entry_size(sizeof(Elf64_Sym));
        dynsymSec->set_addr_align(8);
        dynsymSec->set_link(dynstrSec->get_index());

        gnuHashSec = writer.sections.add(".gnu.hash");
        gnuHashSec->set_type(SHT_DYNAMIC);
        gnuHashSec->set_flags(SHF_ALLOC | SHF_WRITE);
        gnuHashSec->set_entry_size(sizeof(Elf64_Dyn));
        gnuHashSec->set_addr_align(8);
        gnuHashSec->set_link(dynstrSec->get_index());

        relaDynSec = writer.sections.add(".rela.dyn");
        relaDynSec->set_type(SHT_RELA);
        relaDynSec->set_flags(SHF_ALLOC);
        relaDynSec->set_entry_size(sizeof(Elf64_Rela));
        relaDynSec->set_addr_align(8);
        relaDynSec->set_link(dynsymSec->get_index());

        dynamicSec = writer.sections.add(".dynamic");
        dynamicSec->set_type(SHT_DYNAMIC);
        dynamicSec->set_flags(SHF_ALLOC | SHF_WRITE);
        dynamicSec->set_entry_size(sizeof(Elf64_Dyn));
        dynamicSec->set_addr_align(8);
        dynamicSec->set_link(dynstrSec->get_index());

        auto dynamic = writer.segments.add();
        dynamic->set_type(PT_DYNAMIC);
        dynamic->set_flags(PF_R | PF_W);
        dynamic->set_virtual_address(base);
        dynamic->set_physical_address(base);
        dynamic->add_section(dynamicSec, 8);

        for (auto const& lib : neededLibs)
            addDyn(DT_NEEDED, dynstr.add(lib));
//        addDyn(DT_RUNPATH, dynstr.add("$ORIGIN"));
        tagDynStr = addDyn(DT_STRTAB, 0);
        tagDynStrSz = addDyn(DT_STRSZ, 0);
        tagDynSym = addDyn(DT_SYMTAB, 0);
        tagGnuHash = addDyn(DT_GNU_HASH, 0);
        addDyn(DT_SYMENT, sizeof(Elf64_Sym));
        tagDynRela = addDyn(DT_RELA, 0);
        tagDynRelaSz = addDyn(DT_RELASZ, 0);
        addDyn(DT_RELAENT, sizeof(Elf64_Rela));
        if (elfInitSec) {
            addDyn(DT_INIT_ARRAY, elfInitSec->get_address());
            addDyn(DT_INIT_ARRAYSZ, elfInitSec->get_size());
        }
        tagFini = addDyn(DT_FINI, 0);
        addDyn(DT_DEBUG, 0);
        addDyn(DT_NULL, 0);

        dynamicSec->set_data((const char*) dyn.data(), dyn.size() * sizeof(Elf64_Dyn));
    }

    void addSymbol(std::string name, unsigned char st_info, Elf64_Half shndx = 0, Elf64_Addr value = 0, Elf_Xword size = 0) {
        symbols.push_back({std::move(name), st_info, shndx, value, size});
    }

    std::size_t getSymbolCount() const {
        return symbols.size();
    }

    static inline std::size_t roundUpToPowerOf2(std::size_t v) {
        std::size_t ret = 1;
        while (ret < v)
            ret*=2;
        return ret;
    }

    void buildGnuHash(Elf64_Word symndx) {
        // taken from ExeLayout.hpp : 272
        using HashWord = uint64_t;

        const std::size_t shift2 = 26;
        auto nBuckets = std::max<std::size_t>((symbols.size() - symndx) / 4, 1);
        std::size_t maskWords = 1;
        if ((symbols.size() - symndx) > 0) {
            maskWords = roundUpToPowerOf2((symbols.size() - symndx) * 12 / (sizeof(HashWord) * 8));
        }

        std::stable_sort(symbols.begin() + symndx, symbols.end(), [&nBuckets] (const auto& a, const auto& b) {
            return (LIEF::ELF::dl_new_hash(a.name.c_str()) % nBuckets) < (LIEF::ELF::dl_new_hash(b.name.c_str()) % nBuckets);
        });

        std::vector<HashWord> bloomFilters(maskWords, 0);
        const unsigned c = 64;
        for (size_t i = symndx; i < symbols.size(); ++i) {
            const uint32_t hash = LIEF::ELF::dl_new_hash(symbols[i].name.c_str());
            const size_t pos = (hash / c) & (maskWords - 1);
            HashWord V = (static_cast<HashWord>(1) << (hash % c)) |
                         (static_cast<HashWord>(1) << ((hash >> shift2) % c));
            bloomFilters[pos] |= V;
        }


        // Write buckets and hash
        int previousBucket = -1;
        size_t hashValueIdx = 0;
        std::vector<uint32_t> buckets(nBuckets, 0);
        std::vector<uint32_t> hashValues(symbols.size() - symndx, 0);

        for (size_t i = symndx; i < symbols.size(); ++i) {
            const uint32_t hash = LIEF::ELF::dl_new_hash(symbols[i].name.c_str());
            int bucket = (int) (hash % nBuckets);
            if (bucket < previousBucket)
                throw std::runtime_error("Previous bucket is greater than the current one");

            if (bucket != previousBucket) {
                buckets[bucket] = i;
                previousBucket = bucket;
                if (hashValueIdx > 0) {
                    hashValues[hashValueIdx - 1] |= 1;
                }
            }

            hashValues[hashValueIdx] = hash & ~1;
            ++hashValueIdx;
        }

        if (hashValueIdx > 0) {
            hashValues[hashValueIdx - 1] |= 1;
        }

        std::vector<uint8_t> data;
        data.resize(
                sizeof(uint32_t) * 4 +
                sizeof(HashWord) * bloomFilters.size() +
                sizeof(uint32_t) * buckets.size() +
                sizeof(uint32_t) * hashValues.size());

        auto header = (uint32_t*) &data[0];
        header[0] = nBuckets;
        header[1] = symndx;
        header[2] = maskWords;
        header[3] = shift2;

        auto dataBloomFilters = (HashWord*) &header[4];
        memcpy(dataBloomFilters, bloomFilters.data(), sizeof(HashWord) * bloomFilters.size());

        auto dataBucketData = (uint32_t*) &dataBloomFilters[bloomFilters.size()];
        memcpy(dataBucketData, buckets.data(), sizeof(uint32_t) * buckets.size());
        memcpy(dataBucketData + buckets.size(), hashValues.data(), sizeof(uint32_t) * hashValues.size());

        gnuHashSec->set_data((const char*) data.data(), data.size());
    }

    void buildDynsym(std::size_t exportSymbolStart) {
        std::vector<Elf64_Sym> syms;

        buildGnuHash(exportSymbolStart);

        for (auto& sym : symbols) {
            symbolMap[sym.name] = syms.size();
            syms.push_back({(Elf_Word) dynstr.add(sym.name), sym.st_info, 0, sym.shndx, sym.value, sym.size});
        }

        dynsymSec->set_data((const char*) syms.data(), syms.size() * sizeof(Elf64_Sym));
    }

    std::size_t addRelocation(Elf64_Addr offset, Elf64_Word symbol, Elf64_Word type, Elf_Sxword addend = 0) {
        auto ret = rela.size();
        rela.push_back({offset, ((Elf_Xword) symbol << 32) | type, addend});
        return ret;
    }

    void updateRelocationOffset(std::size_t index, Elf64_Addr offset) {
        rela[index].r_offset = offset;
    }

    void buildDynRela() {
        relaDynSec->set_data((const char*) rela.data(), rela.size() * sizeof(Elf64_Rela));
    }

    void setFinalizer(Elf64_Addr addr) {
        dyn[tagFini].d_un.d_ptr = addr;
    }

    void finalize() {
        dynstrSec->set_data(dynstr.data());
    }

    void fixup() {
        dyn[tagDynStr].d_un.d_ptr = dynstrSec->get_address();
        dyn[tagDynStrSz].d_un.d_ptr = dynstrSec->get_size();
        dyn[tagDynSym].d_un.d_ptr = dynsymSec->get_address();
        dyn[tagGnuHash].d_un.d_ptr = gnuHashSec->get_address();
        dyn[tagDynRela].d_un.d_ptr = relaDynSec->get_address();
        dyn[tagDynRelaSz].d_un.d_ptr = relaDynSec->get_size();
        dynamicSec->set_data((const char*) dyn.data(), dyn.size() * sizeof(Elf64_Dyn));
        relaDynSec->set_data((const char*) rela.data(), rela.size() * sizeof(Elf64_Rela));
    }

};

struct EmbeddedCodeBuilder {

    static constexpr std::size_t MAGIC_RELOCATION_COUNT = 4;
    static constexpr std::size_t EMBEDDED_SYMBOL_COUNT = 2;

    static constexpr std::size_t SYM_START = 0;
    static constexpr std::size_t SYM_FINALIZE = 1;

    section* dataSec;
    section* textSec;
    std::size_t relocationStartIndex;
    std::vector<uint8_t> embeddedBlobData;
    std::vector<std::size_t> embeddedSymbols;

    void build(elfio& writer, DynBuilder& dyn) {
        dataSec = writer.sections.add(".compat.data");
        dataSec->set_type(SHT_PROGBITS);
        dataSec->set_flags(SHF_ALLOC);
        dataSec->set_addr_align(8);

        textSec = writer.sections.add(".compat.text");
        textSec->set_type(SHT_PROGBITS);
        textSec->set_flags(SHF_ALLOC);
        textSec->set_addr_align(8);

        auto embeddedBlobFile = fopen("../macoscompat/embedded", "rb");
        fseek(embeddedBlobFile, 0, SEEK_END);
        auto size = ftell(embeddedBlobFile);
        if (size < EMBEDDED_SYMBOL_COUNT * 8)
            throw std::runtime_error("blob too small");
        fseek(embeddedBlobFile, 0, SEEK_SET);
        size -= EMBEDDED_SYMBOL_COUNT * 8;
        embeddedBlobData.resize(size);
        if (fread(embeddedBlobData.data(), 1, size, embeddedBlobFile) != size)
            throw std::runtime_error("failed to read blob");
        embeddedSymbols.resize(EMBEDDED_SYMBOL_COUNT);
        if (fread(embeddedSymbols.data(), sizeof(std::size_t), EMBEDDED_SYMBOL_COUNT, embeddedBlobFile) != EMBEDDED_SYMBOL_COUNT)
            throw std::runtime_error("failed to read blob symbols");
        fclose(embeddedBlobFile);

        std::string dataData;
        dataData.resize(8 * MAGIC_RELOCATION_COUNT);
        dataSec->set_data(dataData);
        textSec->set_size(embeddedBlobData.size());

        dyn.addSymbol("__libc_start_main",  ELF_ST_INFO(STB_GLOBAL, STT_FUNC));
        dyn.addSymbol("__cxa_finalize",  ELF_ST_INFO(STB_GLOBAL, STT_FUNC));
    }

    void createRelocations(DynBuilder& dyn, Elf64_Addr base, Elf64_Addr oldEntrypoint) {
        relocationStartIndex = dyn.addRelocation(0, dyn.symbolMap.at("__libc_start_main"), ELFIO::R_X86_64_64, 0);
        dyn.addRelocation(0, 0, ELFIO::R_X86_64_RELATIVE, (Elf_Sxword) oldEntrypoint);
        dyn.addRelocation(0, dyn.symbolMap.at("__cxa_finalize"), ELFIO::R_X86_64_64, 0);
        dyn.addRelocation(0, 0, ELFIO::R_X86_64_RELATIVE, (Elf_Sxword) base);
    }

    void fixup(DynBuilder& dyn) {
        auto codeAddr = textSec->get_address();
        auto dataAddr = dataSec->get_address();
        for (int i = 0; i < MAGIC_RELOCATION_COUNT; i++)
            dyn.updateRelocationOffset(relocationStartIndex + i, dataAddr + 8 * i);

        for (int i = 0; i <= (int) embeddedBlobData.size() - 4; i++) {
            auto& as_uint32 = *(uint32_t*) &embeddedBlobData[i];
            if ((as_uint32 & 0xFFFFFF00u) == 0x13374200u) {
                auto num = as_uint32 & 0xFFu;
                as_uint32 = (dataAddr - (codeAddr + i + 4)) + num * 8;
            }
        }
        textSec->set_data((const char*) embeddedBlobData.data(), embeddedBlobData.size());

        dyn.setFinalizer(getSymAddr(SYM_FINALIZE));
    }

    Elf64_Addr getSymAddr(std::size_t i) const {
        return textSec->get_address() + embeddedSymbols[i];
    }

};

class SectionHelper {

private:
    std::vector<std::tuple<Elf64_Addr, Elf64_Addr, section*>> sections;
    int cachedIndex = 0;

public:
    void addSection(section* s) {
        sections.emplace_back(s->get_address(), s->get_address() + s->get_size(), s);
    }

    section* findSectionByVA(Elf64_Addr addr) {
        Elf64_Addr start, end;
        if (cachedIndex < sections.size()) {
            std::tie(start, end, std::ignore) = sections[cachedIndex];
            if (addr >= start && addr < end)
                return std::get<2>(sections[cachedIndex]);
        }
        for (int i = 0; i < (int)sections.size(); i++) {
            std::tie(start, end, std::ignore) = sections[i];
            if (addr >= start && addr < end) {
                cachedIndex = i;
                return std::get<2>(sections[i]);
            }
        }
        return nullptr;
    }

};

struct EhFrameBuilder {

    section* hdrSec;
    std::vector<uint8_t> data;

    void build(elfio& writer, std::vector<std::pair<uint32_t, uint32_t>> const& map) {
        hdrSec = writer.sections.add(".eh_frame_hdr");
        hdrSec->set_type(SHT_PROGBITS);
        hdrSec->set_flags(SHF_ALLOC);
        hdrSec->set_addr_align(4);
        hdrSec->set_size(12 + map.size() * 8);
    }

    void writeAtFixup(section* ehFrameSec, std::vector<std::pair<uint32_t, uint32_t>> const& map) {
        std::vector<uint8_t> data (12 + map.size() * 8);

        data[0] = 1; // version: 1
        data[1] = 0x1B; // eh_frame ptr encoding: rel int32
        data[2] = 3; // fde count encoding: uint32
        data[3] = 0x3B; // binary table encoding: rel
        (uint32_t&)data[4] = (ehFrameSec ? ehFrameSec->get_address() : 0) - (hdrSec->get_address() + 4);
        (uint32_t&)data[8] = map.size();
        int32_t* table = (int32_t*) &data[12];
        int32_t funcAddrAdjust = -hdrSec->get_address();
        int32_t frameAddrAdjust = ehFrameSec->get_address() - hdrSec->get_address();
        for (auto const& it : map) {
            *table++ = it.first + funcAddrAdjust;
            *table++ = it.second + frameAddrAdjust;
        }

        hdrSec->set_data((const char*) data.data(), data.size());
    }

};

int main(int argc, char* argv[]) {
    TranslationHelper trHelper;
    trHelper.load("../macoscompat/translation.txt");

    auto macho = LIEF::MachO::Parser::parse(std::string(argv[1]));
    std::cout << "Binary count: " << macho->size() << '\n';
    auto& binary = *macho->at(0);

    bool isExe = binary.header().file_type() == LIEF::MachO::FILE_TYPES::MH_EXECUTE;

    elfio writer;
    for (const auto& cmd : binary.commands()) {
        if (cmd.command() == LIEF::MachO::LOAD_COMMAND_TYPES::LC_SEGMENT_64) {
            auto seg = static_cast<const LIEF::MachO::SegmentCommand*>(&cmd);
            if (!seg->sections().empty()) {
                std::cout << "Using " << std::hex << seg->virtual_address() << " as base\n" << std::dec;
                writer.set_base(seg->virtual_address());
                break;
            }
        }
    }
    setup_elf(writer, isExe);

    std::cout << "== Sections ==" << '\n';
    std::unordered_map<LIEF::MachO::Section const*, section*> sectionMap;
    SectionHelper sectionVaHelper;
    section* elfInitSec = nullptr;
    for (const auto& section : binary.sections()) {
        std::cout << section << '\n';
        auto name = section.name();
        if (name[0] == '_' && name[1] == '_') {
            name[1] = '.';
            name = name.substr(1);
        }
        if (name == ".eh_frame")
            name = ".eh_frame_bak";
        auto elfSection = writer.sections.add(name);
        elfSection->set_type(convert_section_type(section.type()));
        Elf_Xword flags = SHF_ALLOC;
        if (section.flags() & (uint32_t) LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_SOME_INSTRUCTIONS)
            flags |= SHF_EXECINSTR;
        elfSection->set_flags(flags);
        elfSection->set_addr_align(1 << section.alignment());
        elfSection->set_address(section.address());
        elfSection->set_data((const char*) section.content().data(), section.content().size());
        elfSection->set_size(section.size());
        sectionMap[&section] = elfSection;
        sectionVaHelper.addSection(elfSection);

        if (section.type() == LIEF::MachO::MACHO_SECTION_TYPES::S_MOD_INIT_FUNC_POINTERS)
            elfInitSec = elfSection;
    }

    std::cout << "== Segments ==" << '\n';
    Elf64_Addr ourBase = 0;
    for (const auto& cmd : binary.commands()) {
        if (cmd.command() == LIEF::MachO::LOAD_COMMAND_TYPES::LC_SEGMENT_64) {
            auto seg = static_cast<const LIEF::MachO::SegmentCommand*>(&cmd);
            std::cout << "Segment64:" << '\n';

            segment* elfSeg = nullptr;
            for (auto& sec : seg->sections()) {
                auto elfSec = sectionMap.find(&sec);
                if (elfSec != sectionMap.end()) {
                    if (!elfSeg) {
                        elfSeg = writer.segments.add();
                        elfSeg->set_type(PT_LOAD);
                        elfSeg->set_virtual_address(seg->virtual_address());
                        elfSeg->set_physical_address(seg->virtual_address());
                        elfSeg->set_memory_size(seg->virtual_size());
                        elfSeg->set_flags(map_prot((LIEF::MachO::VM_PROTECTIONS) seg->init_protection()));
                        elfSeg->set_align(0x1000);
                        if (seg->virtual_address() == writer.get_base()) {
                            elfSeg->add_section(writer.sections[0], writer.sections[0]->get_addr_align()); // elf header
                            elfSeg->add_section(writer.sections[2], writer.sections[2]->get_addr_align()); // interp
                        }
                    }
                    std::cout << "  " << sec.name() << '\n';
                    elfSeg->add_section(elfSec->second, elfSec->second->get_addr_align());
                }
            }

            if (seg->virtual_address() + seg->virtual_size() > ourBase)
                ourBase = seg->virtual_address() + seg->virtual_size();
        }
    }
    ourBase = (ourBase + 0xfffu) &~ 0xfffLLu;

    DynBuilder dyn;

    std::vector<std::string> neededLibs;
    neededLibs.emplace_back("libc.so.6");
    for (const auto& lib : binary.libraries()) {
        trHelper.registerLibrary(lib, neededLibs);
    }

    dyn.build(writer, ourBase, neededLibs, elfInitSec);

    EmbeddedCodeBuilder embeddedCode;
    embeddedCode.build(writer, dyn);

    const auto getSymbolInfo = [](uint16_t desc, bool isObj = false) -> unsigned char {
        auto isWeak = desc & ((uint32_t)LIEF::MachO::SYMBOL_DESCRIPTIONS::N_WEAK_REF | (uint32_t)LIEF::MachO::SYMBOL_DESCRIPTIONS::N_WEAK_DEF);
        isObj |= desc & 0x800u;
        return ELF_ST_INFO(isWeak ? STB_WEAK : STB_GLOBAL, isObj ? STT_OBJECT : STT_FUNC);
    };

//    for (const auto& symbol : binary.symbols()) {
    for (const auto& binding : binary.dyld_info()->bindings()) {
        const auto& symbol = *binding.symbol();
        auto targetName = trHelper.mapSymbol(binding).targetName;
        if (targetName.empty()) {
            std::cout << "Missing symbol: " << (binding.library() ? binding.library()->name() : "null") << ' ' << symbol.name() << '\n';
            continue;
        }
        dyn.addSymbol(targetName, getSymbolInfo(symbol.description()), 0, 0, symbol.size());
    }
    auto exportedSymbolStart = dyn.getSymbolCount();
    for (const auto& symbol : binary.exported_symbols()) {
        auto section = sectionVaHelper.findSectionByVA(symbol.value());
        if (section == nullptr) {
            std::cout << "Warning: Missing section for exported symbol " << symbol.name() << ' ' << std::hex << symbol.value() << std::dec << '\n';
            continue;
        }
        auto sectionNdx = section ? section->get_index() : 0;
        auto name = symbol.name();
        if (name[0] == '_')
            name = name.substr(1);
        auto useAsObj = section->get_name() != "__text"; //TODO:
        dyn.addSymbol(name, getSymbolInfo(symbol.description(), useAsObj), sectionNdx, symbol.value(), symbol.size());
    }
    dyn.buildDynsym(exportedSymbolStart);

    embeddedCode.createRelocations(dyn, writer.get_base(), binary.has_entrypoint() ? binary.entrypoint() : writer.get_base());


    for (const auto& reloc : binary.relocations()) {
//        std::cout << reloc << "\n";
        switch ((LIEF::MachO::REBASE_TYPES) reloc.type()) {
            case LIEF::MachO::REBASE_TYPES::REBASE_TYPE_POINTER: {
                auto data = binary.get_content_from_virtual_address(reloc.address(), 8);
                dyn.addRelocation(reloc.address(), 0, ELFIO::R_X86_64_RELATIVE, *(Elf_Sxword *)data.data());
                break;
            }
            default:
                abort();
        }
    }

    for (const auto& binding : binary.dyld_info()->bindings()) {
        Elf64_Word type;

        switch (binding.binding_type()) {
            case LIEF::MachO::BIND_TYPES::BIND_TYPE_POINTER:
                type = ELFIO::R_X86_64_64;
                break;
            default:
                abort();
        }
//        std::cout << binding.binding_type() << "\n";
//        std::cout << *binding.symbol() << binding.symbol()->type() << "\n";

        auto name = trHelper.mapSymbol(binding).targetName;
        if (name.empty())
            continue;
        auto symbol = dyn.symbolMap.find(name);
        if (symbol != dyn.symbolMap.end())
            dyn.addRelocation(binding.address(), symbol->second, type, binding.addend());
    }
    dyn.buildDynRela();

    auto compactUnwindInfo = decodeCompactUnwindTable(binary);

    UnwindRewriter unwindRewriter (writer.get_base());
    unwindRewriter.convert(binary, compactUnwindInfo);

    EhFrameBuilder ehFrameBuilder;
    ehFrameBuilder.build(writer, unwindRewriter.searchMap);

    auto ehFrameSec = writer.sections.add(".eh_frame");
    ehFrameSec->set_type(SHT_PROGBITS);
    ehFrameSec->set_flags(SHF_ALLOC);
    ehFrameSec->set_addr_align(8);
    ehFrameSec->set_size(unwindRewriter.size());

    auto cLoadData = writer.segments.add();
    cLoadData->set_type(PT_LOAD);
    cLoadData->set_flags(PF_R | PF_W);
    cLoadData->add_section(dyn.dynamicSec, 8);
    cLoadData->add_section(dyn.dynstrSec, 8);
    cLoadData->add_section(dyn.dynsymSec, 8);
    cLoadData->add_section(dyn.gnuHashSec, 8);
    cLoadData->add_section(dyn.relaDynSec, 8);
    cLoadData->add_section(ehFrameSec, 8);
    cLoadData->add_section(ehFrameBuilder.hdrSec, 8);
    cLoadData->add_section(embeddedCode.dataSec, 8);
    cLoadData->set_virtual_address(ourBase);
    cLoadData->set_physical_address(ourBase);
    cLoadData->set_align(0x1000);

    auto cLoadText = writer.segments.add();
    cLoadText->set_type(PT_LOAD);
    cLoadText->set_flags(PF_R | PF_X);
    cLoadText->set_align(0x1000);
    cLoadText->add_section(embeddedCode.textSec, 8);
    cLoadText->set_virtual_address((Elf64_Addr)-1);
    cLoadText->set_physical_address((Elf64_Addr)-1);

    auto cEhFrame = writer.segments.add();
    cEhFrame->set_type(PT_GNU_EH_FRAME);
    cEhFrame->set_flags(PF_R);
    cEhFrame->set_align(4);
    cEhFrame->set_memory_size(ehFrameBuilder.hdrSec->get_size());
    cEhFrame->set_file_size(ehFrameBuilder.hdrSec->get_size());

    dyn.finalize();

    writer.layout();
    cEhFrame->set_virtual_address(ehFrameBuilder.hdrSec->get_address());
    cEhFrame->set_physical_address(ehFrameBuilder.hdrSec->get_address());
    cEhFrame->set_offset(ehFrameBuilder.hdrSec->get_offset());

    embeddedCode.fixup(dyn);
    dyn.fixup();
/*
    section* ehFrameSec = nullptr;
    for (auto& s : sectionMap) {
        if (s.second->get_name() == ".eh_frame_bak")
            ehFrameSec = s.second;
    }*/
    unwindRewriter.fixup((uint32_t) (ehFrameSec->get_address() - writer.get_base()));
    ehFrameSec->set_data((const char*) unwindRewriter.data().data(), unwindRewriter.size());
    ehFrameBuilder.writeAtFixup(ehFrameSec, unwindRewriter.searchMap);

    if (isExe)
        writer.set_entry(embeddedCode.getSymAddr(EmbeddedCodeBuilder::SYM_START));

    writer.save(argv[2]);

    std::cout << "=================\n";
    std::cout << "Final ELF layout:\n";
    std::cout << "=================\n";
    std::cout << "\nSections:\n";
    std::cout << std::hex;
    for (auto& section : writer.sections) {
        std::cout << section->get_address() << ' ' << section->get_offset() << ' ' << section->get_name() << '\n';
    }
    std::cout << "\nSegments:\n";
    for (auto& segment : writer.segments) {
        std::cout << segment->get_virtual_address() << ' ' << segment->get_offset() << ' ' << segment->get_type() << '\n';
    }


    return 0;
}

static Elf_Word convert_section_type(LIEF::MachO::MACHO_SECTION_TYPES type) {
    switch (type) {
        case LIEF::MachO::MACHO_SECTION_TYPES::S_MOD_INIT_FUNC_POINTERS:
            return SHT_INIT_ARRAY;
        case LIEF::MachO::MACHO_SECTION_TYPES::S_ZEROFILL:
            return SHT_NOBITS;
        default:
            return SHT_PROGBITS;
    }
}

static Elf_Word map_prot(LIEF::MachO::VM_PROTECTIONS prot) {
    Elf_Word ret = 0;
    if ((size_t) prot & (size_t) LIEF::MachO::VM_PROTECTIONS::VM_PROT_READ)
        ret |= PF_R;
    if ((size_t) prot & (size_t) LIEF::MachO::VM_PROTECTIONS::VM_PROT_WRITE)
        ret |= PF_W;
    if ((size_t) prot & (size_t) LIEF::MachO::VM_PROTECTIONS::VM_PROT_EXECUTE)
        ret |= PF_X;
    return ret;
}