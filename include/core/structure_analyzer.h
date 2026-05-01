#pragma once
#include "core/ir.h"
#include <vector>
#include <optional>

namespace atlus {

// ── Structure Analyzer ──────────────────────────────────────────────────────
// Detects common data structures in binaries:
// - Virtual function tables (vtables)
// - C++ RTTI (Run-Time Type Information)
// - Function pointer tables
// - Common string patterns

enum class StructureType {
    Unknown,
    VTable,              // Virtual function table
    RTTIComplete,        // Complete RTTI descriptor
    RTTIClassHierarchy,  // Class hierarchy descriptor
    FunctionPtrArray,    // Array of function pointers
    StringTable,         // Array of string pointers
    JumpTable,           // Switch jump table (already handled by switch_analyzer)
    ImportTable,         // Import Address/Name Table
    ExportTable,         // Export Address Table
    TLSCallbackTable     // TLS callback array
};

struct StructureMember {
    size_t offset;       // Byte offset from structure start
    size_t size;         // Size in bytes
    std::string type;    // Type name (e.g., "func_ptr", "char_ptr", "uint32")
    uint64_t value;      // Resolved value if known
    std::string comment;
};

struct DetectedStructure {
    StructureType type;
    std::string name;
    uint64_t address;    // Memory address of structure
    size_t size;         // Total size in bytes
    size_t element_count; // Number of elements (for arrays/tables)
    size_t element_size;  // Size of each element
    
    std::vector<StructureMember> members;
    
    // For vtables
    std::string class_name;      // Demangled class name if available
    bool has_rtti;               // Has associated RTTI
    uint64_t rtti_address;       // RTTI descriptor address
    
    // Confidence score 0-100
    int confidence;
};

struct StructureAnalysisResult {
    bool success = false;
    size_t structure_count = 0;
    std::vector<DetectedStructure> structures;
    
    // Filtered by type
    std::vector<const DetectedStructure*> vtables;
    std::vector<const DetectedStructure*> rtti_entries;
    std::vector<const DetectedStructure*> func_tables;
};

class StructureAnalyzer {
public:
    StructureAnalyzer() = default;
    
    // Analyze binary for structures
    StructureAnalysisResult analyze(const ir::Binary& binary);
    
    // Specific detection methods
    std::vector<DetectedStructure> find_vtables(const ir::Binary& binary);
    std::vector<DetectedStructure> find_rtti(const ir::Binary& binary);
    std::vector<DetectedStructure> find_function_tables(const ir::Binary& binary);
    std::vector<DetectedStructure> find_tls_callbacks(const ir::Binary& binary);
    
    // Check if an address looks like a vtable
    std::optional<DetectedStructure> analyze_potential_vtable(
        uint64_t addr, 
        const ir::Binary& binary,
        int min_funcs = 2
    );

private:
    // Helpers
    bool is_valid_code_pointer(uint64_t ptr, const ir::Binary& binary);
    bool is_valid_data_pointer(uint64_t ptr, const ir::Binary& binary);
    bool points_to_rtti(uint64_t ptr, const ir::Binary& binary);
    
    // Read pointer from memory (handles 32/64 bit)
    uint64_t read_pointer(const uint8_t* data, size_t offset, bool is_64bit);
    
    // Try to demangle C++ type name
    std::string demangle_type_name(const std::string& mangled);
    
    // Validate vtable candidate
    bool validate_vtable(const DetectedStructure& vtable, const ir::Binary& binary);
    
    // Detect MSVC RTTI patterns
    std::optional<DetectedStructure> parse_msvc_rtti(
        uint64_t rtti_addr,
        const ir::Binary& binary
    );
};

// ── Display Helpers ───────────────────────────────────────────────────────

const char* structure_type_name(StructureType type);
const char* structure_icon(StructureType type);

} // namespace atlus
