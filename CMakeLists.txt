cmake_minimum_required(VERSION 3.23)
project(macho2elf)

enable_language(CXX C ASM)

set(CMAKE_CXX_STANDARD 17)

include(lief.cmake)

add_executable(converter converter/main.cpp converter/translation_helper.cpp converter/translation_helper.h converter/unwind_compact_decoder.cpp converter/unwind_dwarf.cpp converter/unwind_rewriter.cpp)
target_link_libraries(converter PUBLIC LIEF::LIEF)
target_include_directories(converter PUBLIC ${CMAKE_SOURCE_DIR})

add_executable(info_print converter/info_print.cpp converter/unwind_compact_decoder.cpp converter/unwind_dwarf.cpp)
target_link_libraries(info_print PUBLIC LIEF::LIEF)

add_library(macoscompat SHARED macoscompat/main.cpp macoscompat/math.cpp macoscompat/fs.cpp macoscompat/locale/table.c macoscompat/locale/none.c macoscompat/locale/utf8.c macoscompat/locale/nomacros.c macoscompat/locale/isctype.c macoscompat/locale/xlocale.c macoscompat/dyld.cpp macoscompat/dyld.s)

add_dependencies(converter macoscompat)