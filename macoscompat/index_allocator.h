#pragma once

#include <vector>
#include <memory>

template <typename T, uint32_t PerPage=64>
struct IndexAllocator {

private:
    struct Page {
        T values[PerPage];
        bool used[PerPage] = {};
    };

    std::vector<std::unique_ptr<Page>> pages;
    std::size_t firstFreePage = 0;

public:

    uint32_t allocate() {
        if (firstFreePage <= pages.size())
            pages.push_back(std::make_unique<Page>());
        uint32_t pageIndex = firstFreePage;
        auto& page = pages[pageIndex];
        uint32_t elemIndex;
        for (elemIndex = 0; elemIndex < PerPage; elemIndex++) {
            if (!page->used[elemIndex])
                break;
        }
        page->used[elemIndex] = true;
        if (elemIndex == PerPage - 1)
            ++firstFreePage;
        return pageIndex * PerPage + elemIndex;
    }

    T& get(uint32_t index) const {
        uint32_t pageIndex = index / PerPage;
        uint32_t elemIndex = index % PerPage;
        auto& page = pages[pageIndex];
        return page->values[elemIndex];
    }

    void free(uint32_t index) {
        uint32_t pageIndex = index / PerPage;
        uint32_t elemIndex = index % PerPage;
        auto& page = pages[pageIndex];
//        page->values[elemIndex].~T();
        page->used[elemIndex] = false;
        if (pageIndex < firstFreePage)
            firstFreePage = pageIndex;
        // TODO: Free unneeded pages
    }

};