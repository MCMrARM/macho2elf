#include "translation_helper.h"

#include <fstream>

void TranslationHelper::load(const std::string &path) {
    const auto trim = [](std::string str) {
        auto f = str.find_first_not_of(" \t");
        auto l = str.find_last_not_of(" \t");
        if (f == std::string::npos || l == std::string::npos || f > l)
            return std::string();
        return str.substr(f, l - f + 1);
    };

    std::shared_ptr<LibTranslation> activeTranslation;
    std::string currentTargetLib;

    std::ifstream fs (path);
    std::string line;
    while (std::getline(fs, line)) {
        if (line.empty() || line[0] == '#')
            continue;

        bool isLibDecl = line[0] == '@';
        size_t index = isLibDecl ? 1 : 0;

        size_t split = line.find("->", index);
        if (split == std::string::npos)
            continue;

        auto key = trim(line.substr(index, split - index));
        auto value = trim(line.substr(split + 2));

        if (isLibDecl) {
            if (!libraries[key])
                libraries[key] = std::make_shared<LibTranslation>();
            activeTranslation = libraries[key];
            activeTranslation->targetLibNames.push_back(value);
            currentTargetLib = value;
            continue;
        }

        if (!activeTranslation)
            throw std::runtime_error("Symbol mappings in the translation file can not appear before a library mapping has been defined");

        activeTranslation->symbolMap[key] = {currentTargetLib, value};
    }
}

void TranslationHelper::registerLibrary(LIEF::MachO::DylibCommand const& library, std::vector<std::string>& referencedSoNames) {
    auto it = libraries.find(library.name());
    if (it == libraries.end())
        return;

    libTranslationMap[&library] = it->second;
    for (auto const& lib : it->second->targetLibNames)
        referencedSoNames.push_back(lib); //TODO: deduplicate
}

TranslationHelper::SymbolTranslation TranslationHelper::mapSymbol(LIEF::MachO::BindingInfo const& binding) {
    auto it = libTranslationMap.find(binding.library());
    if (it == libTranslationMap.end())
        return {};

    auto it2 = it->second->symbolMap.find(binding.symbol()->name());
    if (it2 == it->second->symbolMap.end()) {
        auto& name = binding.symbol()->name();
        return {it->second->targetLibNames[0], name[0] == '_' ? name.substr(1) : name};
    }
    return it2->second;
}