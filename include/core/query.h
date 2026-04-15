#pragma once
#include "core/ir.h"
#include "core/index.h"
#include "core/address_space.h"
#include <vector>
#include <functional>
#include <optional>

namespace atlus::query {

// ── Query Layer ───────────────────────────────────────────────────────────────

/**
 * Unified Query API over IR + Index + Pipeline.
 * 
 * This layer provides:
 * - Consistent search semantics across all entity types
 * - Reusable backend logic for UI / CLI / plugins  
 * - Clean separation from storage details
 * 
 * Think: "SQL layer over IR graph"
 * 
 * Example queries:
 *   - Find all functions calling X
 *   - Find all references to address Y  
 *   - Find BBs matching pattern Z
 *   - Find symbols by name with type constraint
 */

// ── Query Primitives ───────────────────────────────────────────────────────────

/**
 * QueryResult - Unified result container.
 */
struct QueryResult {
    enum class EntityType { None, Section, Function, BasicBlock, Instruction, Symbol, XRef };
    
    EntityType type = EntityType::None;
    float relevance = 1.0f;  // For ranking
    
    union {
        ir::SectionId section;
        ir::FunctionId function;
        ir::BasicBlockId block;
        ir::InstructionId instruction;
        ir::SymbolId symbol;
    } id;
    
    // Human-readable description
    std::string display_name;
    ir::QualifiedAddress address;
    
    // Access typed result
    template<typename T>
    T get_id() const;
};

template<>
inline ir::FunctionId QueryResult::get_id<ir::FunctionId>() const {
    return function;
}
template<>
inline ir::SymbolId QueryResult::get_id<ir::SymbolId>() const {
    return symbol;
}

// ── Query Filters ──────────────────────────────────────────────────────────────

/**
 * AddressFilter - Filter by address range or space.
 */
struct AddressFilter {
    std::optional<ir::AddressRange> range;
    std::optional<ir::AddressSpace> space;
    std::optional<ir::SectionId> in_section;
    
    bool matches(ir::QualifiedAddress addr) const {
        if (space && addr.space != *space) return false;
        if (in_section && addr.section != *in_section) return false;
        if (range && !range->contains(addr)) return false;
        return true;
    }
};

/**
 * SymbolFilter - Filter symbols by type and properties.
 */
struct SymbolFilter {
    std::optional<ir::Symbol::Type> type;
    std::optional<std::string> name_pattern;  // Substring match
    std::optional<std::string> dll_name;      // For imports
    bool include_imports = true;
    bool include_exports = true;
    bool include_user_defined = true;
    bool include_discovered = true;
    
    bool matches(const ir::Symbol& sym) const;
};

/**
 * FunctionFilter - Filter functions by properties.
 */
struct FunctionFilter {
    std::optional<std::string> name_pattern;
    std::optional<size_t> min_size;
    std::optional<size_t> max_size;
    std::optional<ir::Function::Type> type;
    std::optional<bool> has_xrefs_in;
    std::optional<bool> has_xrefs_out;
    std::optional<bool> is_leaf_function;  // No calls out
    
    bool matches(const ir::Function& fn, const ir::Binary& binary) const;
};

/**
 * XRefFilter - Filter cross-references.
 */
struct XRefFilter {
    std::optional<ir::XRef::Type> type;
    std::optional<ir::QualifiedAddress> from_address;
    std::optional<ir::QualifiedAddress> to_address;
    std::optional<ir::FunctionId> from_function;
    std::optional<ir::FunctionId> to_function;
    
    bool matches(const ir::XRef& xref) const;
};

// ── Query Builders ─────────────────────────────────────────────────────────────

/**
 * QueryBuilder - Fluent interface for complex queries.
 */
class QueryBuilder {
public:
    // Entity selection
    QueryBuilder& select_functions();
    QueryBuilder& select_symbols();
    QueryBuilder& select_instructions();
    QueryBuilder& select_xrefs();
    
    // Filters (AND logic)
    QueryBuilder& where(const AddressFilter& filter);
    QueryBuilder& where(const SymbolFilter& filter);
    QueryBuilder& where(const FunctionFilter& filter);
    QueryBuilder& where(const XRefFilter& filter);
    
    // Custom predicate
    QueryBuilder& where(std::function<bool(const QueryResult&)> predicate);
    
    // Relationships
    QueryBuilder& callers_of(ir::FunctionId target);
    QueryBuilder& callees_of(ir::FunctionId source);
    QueryBuilder& xrefs_to(ir::QualifiedAddress addr);
    QueryBuilder& xrefs_from(ir::QualifiedAddress addr);
    QueryBuilder& in_function(ir::FunctionId fn);
    
    // Navigation
    QueryBuilder& within_range(ir::AddressRange range);
    QueryBuilder& in_section(ir::SectionId section);
    
    // Ordering and limits
    QueryBuilder& order_by_address();
    QueryBuilder& order_by_name();
    QueryBuilder& order_by_relevance();
    QueryBuilder& limit(size_t max_results);
    
    // Execution
    std::vector<QueryResult> execute(const ir::Binary& binary) const;
    std::vector<QueryResult> execute(const ir::Binary& binary, const index::GlobalIndex& index) const;
    
private:
    enum class TargetEntity { None, Functions, Symbols, Instructions, XRefs };
    TargetEntity target_ = TargetEntity::None;
    
    std::vector<std::function<bool(const QueryResult&)>> filters_;
    size_t limit_ = 1000;
    bool use_index_ = true;
};

// ── Predefined Queries ─────────────────────────────────────────────────────────

/**
 * Common query patterns as reusable functions.
 */
namespace queries {

// Navigation queries
std::vector<QueryResult> find_function_by_name(
    const ir::Binary& binary,
    const std::string& name,
    bool exact_match = false
);

std::vector<QueryResult> find_symbol_by_address(
    const ir::Binary& binary,
    ir::QualifiedAddress addr
);

std::optional<QueryResult> find_instruction_at(
    const ir::Binary& binary,
    ir::QualifiedAddress addr
);

// Relationship queries
std::vector<QueryResult> find_callers(
    const ir::Binary& binary,
    ir::FunctionId target
);

std::vector<QueryResult> find_callees(
    const ir::Binary& binary,
    ir::FunctionId source
);

std::vector<QueryResult> find_xrefs_to_address(
    const ir::Binary& binary,
    ir::QualifiedAddress addr
);

std::vector<QueryResult> find_xrefs_from_function(
    const ir::Binary& binary,
    ir::FunctionId fn
);

// Code discovery queries
std::vector<QueryResult> find_functions_in_range(
    const ir::Binary& binary,
    ir::AddressRange range
);

std::vector<QueryResult> find_unreferenced_functions(
    const ir::Binary& binary
);

std::vector<QueryResult> find_entry_points(
    const ir::Binary& binary
);  // No callers

// Data discovery queries
std::vector<QueryResult> find_strings_referenced_by(
    const ir::Binary& binary,
    ir::FunctionId fn
);

std::vector<QueryResult> find_imports_used_by(
    const ir::Binary& binary,
    ir::FunctionId fn
);

// Control flow queries
std::vector<QueryResult> get_cfg_successors(
    const ir::Binary& binary,
    ir::BasicBlockId bb
);

std::vector<QueryResult> get_cfg_predecessors(
    const ir::Binary& binary,
    ir::BasicBlockId bb
);

std::vector<QueryResult> find_path_between(
    const ir::Binary& binary,
    ir::BasicBlockId from,
    ir::BasicBlockId to,
    size_t max_depth = 100
);

} // namespace queries

// ── Query Context ───────────────────────────────────────────────────────────────

/**
 * QueryContext - Maintains query state for incremental results.
 * 
 * Useful for:
 * - UI search boxes with debounced queries
 * - Background search tasks
 * - Caching recent results
 */
class QueryContext {
public:
    explicit QueryContext(const ir::Binary& binary);
    
    // Set index for accelerated queries
    void set_index(const index::GlobalIndex& index);
    
    // Execute query (cached)
    std::vector<QueryResult> execute(const QueryBuilder& builder);
    
    // Refresh (invalidate cache)
    void refresh();
    
    // Partial refresh (when specific entities change)
    void refresh_functions(const std::vector<ir::FunctionId>& changed);
    void refresh_symbols(const std::vector<ir::SymbolId>& changed);
    
private:
    const ir::Binary& binary_;
    const index::GlobalIndex* index_ = nullptr;
    
    struct Cache;
    std::unique_ptr<Cache> cache_;
};

// ── Query Plan (Advanced) ───────────────────────────────────────────────────────

/**
 * QueryPlan - Optimization layer for complex queries.
 * 
 * For expensive queries (path finding, call graph traversal),
 * the query engine builds an execution plan.
 */
struct QueryPlan {
    enum class StepType { 
        IndexLookup,    // O(1) hash lookup
        RangeScan,      // O(N) scan with filter
        GraphTraverse,  // BFS/DFS traversal
        Join,           // Combine results
        Filter          // Apply predicate
    };
    
    struct Step {
        StepType type;
        std::string description;
        size_t estimated_cost = 0;
    };
    
    std::vector<Step> steps;
    size_t total_estimated_cost = 0;
};

/**
 * QueryPlanner - Builds optimized query plans.
 */
class QueryPlanner {
public:
    QueryPlan plan(const QueryBuilder& builder, const index::GlobalIndex& index);
    
    // Optimization hints
    static bool should_use_index(const QueryBuilder& builder);
    static bool requires_full_scan(const QueryBuilder& builder);
    static bool is_graph_query(const QueryBuilder& builder);
};

} // namespace atlus::query
