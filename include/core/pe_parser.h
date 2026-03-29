#pragma once
#include "loader.h"
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace atlus {

// ── PE structures ─────────────────────────────────────────────────────────────

struct PESection {
    std::string          name;       // e.g. ".text", ".data"
    uint32_t             vaddr;      // Virtual address (RVA)
    uint32_t             vsize;      // Virtual size
    uint32_t             raw_offset; // File offset
    uint32_t             raw_size;   // Size on disk
    uint32_t             flags;      // Section characteristics
    std::vector<uint8_t> data;       // Raw bytes of this section
};

struct ImportEntry {
    std::string dll;
    std::vector<std::string> functions;
};

struct PEInfo {
    bool     is_64bit   = false;
    uint16_t machine    = 0;     // IMAGE_FILE_MACHINE_*
    uint32_t entry_rva  = 0;     // AddressOfEntryPoint
    uint64_t image_base = 0;
    uint16_t subsystem  = 0;

    std::vector<PESection>   sections;
    std::vector<ImportEntry> imports;

    // Convenience: find a section by name (returns nullptr if absent)
    const PESection* find_section(const std::string& name) const;

    bool valid = false;
};

// ── Parser ────────────────────────────────────────────────────────────────────

class PEParser {
public:
    // Parse PE headers and sections from a loaded binary.
    // Returns PEInfo with valid=false on parse failure.
    static PEInfo parse(const BinaryFile& file);

    // Convert a relative virtual address to a file offset.
    // Returns nullopt if the RVA falls outside all sections.
    static std::optional<uint32_t> rva_to_offset(const PEInfo& pe, uint32_t rva);
};

} // namespace atlus
