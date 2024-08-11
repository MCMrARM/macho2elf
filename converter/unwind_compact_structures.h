#include <cstdint>

struct unwind_info_section_header {
    uint32_t    version;            // UNWIND_SECTION_VERSION
    uint32_t    commonEncodingsArraySectionOffset;
    uint32_t    commonEncodingsArrayCount;
    uint32_t    personalityArraySectionOffset;
    uint32_t    personalityArrayCount;
    uint32_t    indexSectionOffset;
    uint32_t    indexCount;
    // compact_unwind_encoding_t[]
    // uint32_t personalities[]
    // unwind_info_section_header_index_entry[]
    // unwind_info_section_header_lsda_index_entry[]
};


struct unwind_info_section_header_index_entry {
    uint32_t        functionOffset;
    uint32_t        secondLevelPagesSectionOffset;  // section offset to start of regular or compress page
    uint32_t        lsdaIndexArraySectionOffset;    // section offset to start of lsda_index array for this range
};

struct unwind_info_section_header_lsda_index_entry {
    uint32_t        functionOffset;
    uint32_t        lsdaOffset;
};


struct unwind_info_regular_second_level_entry {
    uint32_t functionOffset;
    uint32_t encoding;
};

struct unwind_info_regular_second_level_page_header {
    uint32_t    kind;    // UNWIND_SECOND_LEVEL_REGULAR
    uint16_t    entryPageOffset;
    uint16_t    entryCount;
    // entry array
};


struct unwind_info_compressed_second_level_page_header {
    uint32_t    kind;    // UNWIND_SECOND_LEVEL_COMPRESSED
    uint16_t    entryPageOffset;
    uint16_t    entryCount;
    uint16_t    encodingsPageOffset;
    uint16_t    encodingsCount;
    // 32-bit entry array
    // encodings array
};