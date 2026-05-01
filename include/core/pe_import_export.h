#pragma once
#include "ir.h"
#include <vector>
#include <string>
#include <unordered_map>

namespace atlus {

// ── PE Import/Export Analyzer ────────────────────────────────────────────────
// Analyzes PE import and export tables.
// Reconstructs imports from IAT scans and parses export tables.

struct ImportEntry {
    std::string dll_name;
    std::string function_name;
    uint32_t ordinal;          // Ordinal if imported by ordinal (0 if by name)
    uint64_t iat_address;      // IAT entry address
    uint64_t int_address;      // Import Name Table entry address (if by name)
    bool is_ordinal;
    
    // Runtime resolved info
    uint64_t resolved_address; // Function address after binding
};

struct ImportDirectory {
    std::string dll_name;
    uint64_t original_first_thunk;  // INT (Import Name Table) RVA
    uint64_t first_thunk;           // IAT (Import Address Table) RVA
    uint64_t name_rva;              // DLL name RVA
    std::vector<ImportEntry> entries;
};

struct ExportEntry {
    uint32_t ordinal;          // Export ordinal (base + index)
    std::string function_name; // Name (empty if exported by ordinal only)
    uint64_t address;          // Function RVA
    bool has_name;             // Has named export
    bool is_forwarder;         // Is a forwarder export
    std::string forwarder;     // Forwarder string (e.g., "NTDLL.RtlInitString")
};

struct ExportDirectory {
    std::string dll_name;
    uint32_t ordinal_base;
    uint32_t export_count;
    uint32_t name_count;       // Number of named exports
    std::vector<ExportEntry> exports;
    
    // Index by ordinal for fast lookup
    std::unordered_map<uint32_t, const ExportEntry*> ordinal_to_export;
    // Index by name
    std::unordered_map<std::string, const ExportEntry*> name_to_export;
};

struct ImportAnalysisResult {
    bool success = false;
    size_t dll_count = 0;
    size_t total_imports = 0;
    std::vector<ImportDirectory> imports;
    
    // Flat lookup
    std::vector<const ImportEntry*> all_entries;
};

struct ExportAnalysisResult {
    bool success = false;
    uint32_t total_exports = 0;
    uint32_t named_exports = 0;
    uint32_t ordinal_exports = 0;
    std::vector<ExportEntry> exports;
};

class PEImportExportAnalyzer {
public:
    PEImportExportAnalyzer() = default;
    
    // Analyze imports from PE headers
    ImportAnalysisResult analyze_imports(const Binary& binary);
    
    // Analyze exports from PE headers
    ExportAnalysisResult analyze_exports(const Binary& binary);
    
    // Reconstruct imports from IAT scanning (when headers are stripped)
    ImportAnalysisResult reconstruct_from_iat(const Binary& binary);
    
    // Get import at specific IAT address
    const ImportEntry* get_import_by_iat(uint64_t iat_addr, const ImportAnalysisResult& result);
    
    // Get export by ordinal
    const ExportEntry* get_export_by_ordinal(uint32_t ordinal, const ExportAnalysisResult& result);
    
    // Get export by name
    const ExportEntry* get_export_by_name(const std::string& name, const ExportAnalysisResult& result);

private:
    // PE parsing helpers
    bool parse_import_directory(const uint8_t* data, size_t size,
                                   uint64_t import_dir_rva, 
                                   ImportAnalysisResult& result);
    bool parse_export_directory(const uint8_t* data, size_t size,
                                   uint64_t export_dir_rva,
                                   ExportAnalysisResult& result);
    
    // Read ASCIIZ string at RVA
    std::string read_rva_string(const uint8_t* data, size_t size, uint64_t rva);
    
    // Read 32/64 bit value based on architecture
    uint64_t read_ptr(const uint8_t* data, uint64_t offset, bool is_64bit);
    
    // Check if address is valid RVA
    bool is_valid_rva(uint64_t rva, size_t image_size);
};

// ── Display Helpers ───────────────────────────────────────────────────────

std::string ordinal_to_string(uint32_t ordinal);
std::string format_import(const ImportEntry& imp);
std::string format_export(const ExportEntry& exp);

} // namespace atlus
