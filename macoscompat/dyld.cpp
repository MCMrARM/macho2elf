#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <array>
#include <vector>
#include <mutex>
#include <string>
#include <link.h>
#include <fcntl.h>

extern "C" {

uint64_t system___stack_chk_guard = 0;

void dyld_stub_binder() {
    //
}
intptr_t _dyld_get_image_vmaddr_slide(uint32_t index) {
    if (index != 0) {
        fprintf(stderr, "_dyld_get_image_vmaddr_slide: only supported for index 0\n");
        abort();
    }

    auto mainExe = (struct link_map*) dlopen(nullptr, RTLD_LAZY);
    dlclose(mainExe);
    return (intptr_t) mainExe->l_addr;
}

const char* getsectdata(const char* segname, const char* sectname, unsigned long* size) {
    // TODO: Support segname, maybe use some alternative section table?

    auto mainExeFile = fopen("/proc/self/exe", "rb");
    if (mainExeFile == nullptr)
        return nullptr;

    Elf64_Ehdr ehdr {};
    if (fread(&ehdr, sizeof(ehdr), 1, mainExeFile) != 1)
        return nullptr;

    std::vector<uint8_t> sectionData (ehdr.e_shnum * ehdr.e_shentsize);
    fseek(mainExeFile, ehdr.e_shoff, SEEK_SET);
    if (fread(sectionData.data(), ehdr.e_shentsize, ehdr.e_shnum, mainExeFile) != ehdr.e_shnum)
        return nullptr;

    const auto getSection = [&](int index) { return (Elf64_Shdr*) (sectionData.data() + index * ehdr.e_shentsize); };
    std::vector<uint8_t> shstr (getSection(ehdr.e_shstrndx)->sh_size);
    fseek(mainExeFile, getSection(ehdr.e_shstrndx)->sh_offset, SEEK_SET);
    if (fread(shstr.data(), 1, shstr.size(), mainExeFile) != shstr.size())
        return nullptr;

    std::string tmpStr;
    if (sectname[0] == '_' && sectname[1] == '_') {
        tmpStr = &sectname[1];
        tmpStr[0] = '.';
        sectname = tmpStr.c_str();
    }

    for (int i = 0; i < ehdr.e_shnum; i++) {
        auto section = getSection(i);
        auto name = (const char*) &shstr[section->sh_name];
        if (!strcmp(name, sectname)) {
            auto ret = (const char*) section->sh_addr;
            *size = section->sh_size;
            return ret;
        }
    }

    return nullptr;
}

static thread_local char buf[0x1000];
void* _tlv_bootstrap_impl(){ //TODO:
    auto ret = buf;
    return ret;
}

}