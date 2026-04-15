#pragma once
#include "core/ir.h"
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <optional>

namespace atlus::index {

// ─= Index Types ───────────────────────────────────────────────────────────────

/**
 * IndexType - Types of indexes maintained for fast lookup.
 */
enum class IndexType : uint32_t {
    SymbolByName,       // Name -> SymbolId
    SymbolByAddress,    // Address -> SymbolId
    FunctionByAddress,  // Address -> FunctionId
    StringLiteral,      // String content -> SymbolId
    XRefIncoming,       // Address -> XRef[] (incoming refs)
    XRefOutgoing,       // Address -> XRef[] (outgoing refs)
    InstructionByAddress, // Address -> InstructionId
    BasicBlockByAddress,  // Address -> BasicBlockId
    
    Count
};

// ─= Query Types ───────────────────────────────────────────────────────────────

/**
 * SearchQuery - Unified query structure for indexed search.
 */
struct SearchQuery {
    enum class Type {
        Exact,          // Exact string/address match
        Prefix,         // Starts with
        Substring,      // Contains
        Regex,          // Regular expression
        AddressRange,   // Address range
    };
    
    Type type = Type::Exact;
    std::string text;           // For text searches
    ir::Address start_addr;     // For address range
    ir::Address end_addr;
    bool case_sensitive = false;
    
    // Result limits
    size_t max_results = 1000;
};

/**
 * SearchResult - Unified result structure.
 */
struct SearchResult {
    enum class EntityType { None, Symbol, Function, Instruction, String };
    
    EntityType entity_type = EntityType::None;
    float relevance = 1.0f;  // For ranking
    
    union {
        ir::SymbolId symbol;
        ir::FunctionId function;
        ir::InstructionId instruction;
    } id;
    
    std::string display_text;
    ir::Address address;
};

// ─= Index Interface ───────────────────────────────────────────────────────────

/**
 * Index - Abstract base for all index implementations.
 */
class Index {
public:
    virtual ~Index() = default;
    virtual IndexType type() const = 0;
    virtual void build(const ir::Binary& binary) = 0;
    virtual void clear() = 0;
    virtual size_t size() const = 0;
};

// ─= GlobalIndex - Multi-index System ───────────────────────────────────────────

/**
 * GlobalIndex - Maintains all indexes for a binary.
 * 
 * This provides fast search across all entity types:
 *   - Symbol names (exact, prefix, substring)
 *   - Addresses (reverse lookup)
 *   - String literals
 *   - Cross-references
 */
class GlobalIndex {
public:
    GlobalIndex();
    ~GlobalIndex();
    
    // Build all indexes from binary
    void build(const ir::Binary& binary);
    
    // Build specific index only
    void build_index(IndexType type, const ir::Binary& binary);
    
    // Clear all or specific
    void clear();
    void clear_index(IndexType type);
    
    // Query methods
    std::vector<SearchResult> search(const SearchQuery& query) const;
    
    // Typed lookups
    std::vector<ir::SymbolId> find_symbols_by_name(const std::string& name) const;
    std::vector<ir::SymbolId> find_symbols_by_prefix(const std::string& prefix) const;
    std::vector<ir::SymbolId> find_symbols_by_substring(const std::string& pattern) const;
    
    std::optional<ir::SymbolId> find_symbol_at(ir::Address addr) const;
    std::optional<ir::FunctionId> find_function_at(ir::Address addr) const;
    std::optional<ir::InstructionId> find_instruction_at(ir::Address addr) const;
    
    std::vector<ir::SymbolId> find_strings_by_content(const std::string& content) const;
    
    std::vector<ir::XRef> find_xrefs_to(ir::Address addr) const;
    std::vector<ir::XRef> find_xrefs_from(ir::Address addr) const;
    std::vector<ir::XRef> find_xrefs_to_function(ir::FunctionId fn) const;
    
    // Navigation helpers
    std::optional<ir::Address> get_next_symbol(ir::Address current) const;
    std::optional<ir::Address> get_prev_symbol(ir::Address current) const;
    std::optional<ir::Address> get_next_function(ir::Address current) const;
    std::optional<ir::Address> get_prev_function(ir::Address current) const;
    
    // Statistics
    size_t index_size(IndexType type) const;
    bool has_index(IndexType type) const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ─= Persistent Index (SQLite-backed) ────────────────────────────────────────────

/**
 * PersistentIndex - SQLite-backed index for large binaries.
 * 
 * For very large files (100MB+), keeping indexes in memory can be expensive.
 * This option stores indexes on disk for memory-efficient operation.
 */
class PersistentIndex {
public:
    PersistentIndex();
    ~PersistentIndex();
    
    // Open/create database
    bool open(const std::string& db_path);
    void close();
    bool is_open() const;
    
    // Build from binary (incremental updates supported)
    void build_from(const ir::Binary& binary);
    
    // Same query interface as GlobalIndex
    std::vector<SearchResult> search(const SearchQuery& query) const;
    std::vector<ir::SymbolId> find_symbols_by_name(const std::string& name) const;
    std::optional<ir::SymbolId> find_symbol_at(ir::Address addr) const;
    std::vector<ir::XRef> find_xrefs_to(ir::Address addr) const;
    
    // Session management
    void begin_transaction();
    void commit_transaction();
    void rollback();
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ─= Search Utilities ──────────────────────────────────────────────────────────

/**
 * Advanced search combining multiple criteria.
 */
struct AdvancedSearch {
    std::optional<std::string> name_pattern;
    std::optional<ir::Address> address_range_start;
    std::optional<ir::Address> address_range_end;
    std::optional<ir::Symbol::Type> symbol_type;
    bool include_imports = true;
    bool include_exports = true;
    bool include_strings = false;
};

std::vector<SearchResult> advanced_search(
    const GlobalIndex& index,
    const AdvancedSearch& criteria
);

} // namespace atlus::index
