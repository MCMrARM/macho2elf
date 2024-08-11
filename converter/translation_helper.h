#pragma once

#include <string>
#include <map>
#include <memory>
#include "LIEF/LIEF.hpp"

class TranslationHelper {

public:
    struct SymbolTranslation {
        std::string targetLibName;
        std::string targetName;
    };

private:
    struct LibTranslation {
        std::vector<std::string> targetLibNames;
        std::map<std::string, SymbolTranslation> symbolMap;
    };

    std::map<std::string, std::shared_ptr<LibTranslation>> libraries;
    std::map<LIEF::MachO::DylibCommand const*, std::shared_ptr<LibTranslation>> libTranslationMap;

public:
    void load(std::string const& path);

    void registerLibrary(LIEF::MachO::DylibCommand const& library, std::vector<std::string>& referencedSoNames);

    SymbolTranslation mapSymbol(LIEF::MachO::BindingInfo const& binding);

};