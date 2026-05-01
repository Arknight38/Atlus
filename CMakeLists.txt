cmake_minimum_required(VERSION 3.16)
project(Atlus VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Qt6 MOC / RCC auto-generation (applied only to Qt targets to avoid warnings in third_party)
set(CMAKE_AUTOUIC OFF)

# ============================================================================
# Dependencies
# ============================================================================

# Zydis (git submodule)
add_subdirectory(third_party/zydis)

# Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Concurrent)

# ============================================================================
# Atlus Core static library
# ============================================================================
add_library(atlus_core STATIC
    src/core/loader.cpp
    src/core/pe_parser.cpp
    src/core/disassembler.cpp
    src/core/analyzer.cpp
    src/core/diff_engine.cpp
    src/core/pattern_scanner.cpp
    src/core/formatter.cpp
    src/core/revng_decompiler.cpp
    src/core/thread_pool.cpp
    src/core/md5.cpp
    src/core/ir_identity.cpp
    src/core/ir_governance.cpp
    src/core/ir.cpp
    src/core/ir_serialization.cpp
    src/core/address_space.cpp
    src/core/type_system.cpp
    src/core/invalidation.cpp
    src/core/analysis_pipeline.cpp
    src/core/index.cpp
    src/core/query.cpp
    src/core/disassembly_cache.cpp
    src/core/cfg_builder.cpp
    src/core/xref_analyzer.cpp
    src/core/string_analyzer.cpp
    src/core/switch_analyzer.cpp
    src/core/structure_analyzer.cpp
    src/core/pe_import_export.cpp
    src/core/patch_engine.cpp
    src/core/ida_integration.cpp
    src/core/elf_macho_parsers.cpp
    src/core/bookmarks.cpp
    src/core/sha256.cpp
    src/platform/dialogs.cpp
)

target_include_directories(atlus_core PUBLIC
    include
    src
    third_party/zydis/include
    third_party/zydis/dependencies/zycore/include
    third_party/zydis/src
)

target_compile_definitions(atlus_core PUBLIC
    ZYDIS_STATIC_BUILD
    ZYCORE_STATIC_BUILD
)

target_link_libraries(atlus_core PUBLIC Zydis)

# ============================================================================
# Atlus GUI executable (Qt6)
# ============================================================================
add_executable(Atlus
    src/ui/qt/main.cpp
    src/ui/qt/mainwindow.cpp
    src/ui/qt/theme.cpp
    src/ui/qt/decompiler_worker.cpp
    src/ui/qt/models/functions_model.cpp
    src/ui/qt/models/sections_model.cpp
    src/ui/qt/models/imports_model.cpp
    src/ui/qt/models/disassembly_model.cpp
    src/ui/qt/models/xrefs_model.cpp
    src/ui/qt/models/aob_model.cpp
    src/ui/qt/panels/functions_panel.cpp
    src/ui/qt/panels/sections_panel.cpp
    src/ui/qt/panels/imports_panel.cpp
    src/ui/qt/panels/hex_panel.cpp
    src/ui/qt/panels/hex_view.cpp
    src/ui/qt/panels/disassembly_panel.cpp
    src/ui/qt/panels/pseudocode_panel.cpp
    src/ui/qt/panels/xrefs_panel.cpp
    src/ui/qt/panels/aob_panel.cpp
    src/ui/qt/panels/cfg_panel.cpp
    src/ui/qt/panels/callgraph_panel.cpp
    src/ui/qt/dialogs/settings_dialog.cpp
    src/ui/qt/dialogs/analysis_options_dialog.cpp
)


set_target_properties(Atlus PROPERTIES AUTOMOC ON AUTORCC ON)

target_include_directories(Atlus PRIVATE
    include
    src
    src/ui/qt
)

target_link_libraries(Atlus PRIVATE
    atlus_core
    Qt6::Core
    Qt6::Widgets
    Qt6::Concurrent
)

# ============================================================================
# Compiler warnings / options
# ============================================================================
if (MSVC)
    target_compile_options(Atlus PRIVATE /W3)
    target_compile_options(atlus_core PRIVATE /W3)
else()
    target_compile_options(Atlus PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_compile_options(atlus_core PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()
