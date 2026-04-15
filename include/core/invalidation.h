#pragma once
#include "core/ir.h"
#include "core/ir_identity.h"
#include "core/address_space.h"
#include <functional>
#include <vector>
#include <unordered_set>

namespace atlus::analysis {

// ── Invalidation Triggers ───────────────────────────────────────────────────────

/**
 * InvalidationTrigger - Events that cause IR node invalidation.
 * 
 * Each trigger maps to a set of AnalysisStageDependencies that must re-run.
 */
enum class InvalidationTrigger {
    // Binary-level changes
    BinaryLoaded,           // New binary loaded (full reset)
    BinaryPatched,          // Bytes modified at specific address
    BinaryRebased,          // Image base changed (ASLR/rebase)
    SectionAdded,           // New section discovered
    SectionRemoved,         // Section deleted
    
    // Analysis-level changes
    DisassemblyConfigChanged, // Disassembler mode (x86/x64) changed
    HeuristicTuningChanged,   // Prologue patterns adjusted
    TypeDatabaseUpdated,      // New type signatures loaded
    
    // User actions
    ManualFunctionBoundaries, // User redefined function start/end
    SymbolRenamed,          // User renamed symbol
    TypeAnnotationAdded,    // User added type information
    
    // External inputs
    DebugSymbolsLoaded,     // PDB/DWARF loaded
    ImportTableReconstructed, // Import analysis updated
};

/**
 * InvalidationRule - Defines which stages invalidate for each trigger.
 */
struct InvalidationRule {
    InvalidationTrigger trigger;
    ir::DependencyMask affected_stages;
    bool cascade_to_dependents = true;
    bool requires_full_reanalysis = false;
    
    // Optional: specific address range for targeted invalidation
    std::optional<ir::AddressRange> affected_range;
};

// ── Predefined Invalidation Rules ─────────────────────────────────────────────

/**
 * Get canonical invalidation rules for each trigger type.
 */
InvalidationRule get_invalidation_rule(InvalidationTrigger trigger);

// Rule definitions (documented):
// 
// BinaryLoaded:
//   - affected: ALL stages (full reset)
//   - cascade: true
//   - requires_full_reanalysis: true
//
// BinaryPatched at address A:
//   - affected: MapSections (if in different section)
//            Disassemble (instruction at A)
//            BuildBasicBlocks (BB containing A)
//            BuildCFG (if branch target)
//            AnalyzeXRefs (if A was a reference site)
//   - cascade: true (to dependents)
//   - targeted: only functions containing A
//
// BinaryRebased:
//   - affected: NONE (addresses are space-qualified, not absolute)
//   - cascade: false
//   - Note: Runtime space updates, IR stays valid
//
// DisassemblyConfigChanged:
//   - affected: Disassemble, BuildBasicBlocks, BuildCFG, AnalyzeXRefs
//   - cascade: true
//   - requires_full_reanalysis: true
//
// HeuristicTuningChanged:
//   - affected: ScanFunctions
//   - cascade: true (functions → BBs → CFG → XRefs)
//   - requires_full_reanalysis: false (incremental function scan)
//
// TypeDatabaseUpdated:
//   - affected: TypeInference only
//   - cascade: false (type changes don't affect structure)
//   - iterative: true (type propagation continues)
//
// ManualFunctionBoundaries:
//   - affected: Disassemble (for that function)
//            BuildBasicBlocks, BuildCFG, AnalyzeXRefs (that function only)
//   - cascade: false (don't invalidate other functions)
//   - targeted: specific function
//
// DebugSymbolsLoaded:
//   - affected: ScanFunctions (merge with debug info)
//            TypeInference (apply debug types)
//   - cascade: true
//   - merge: true (augment, don't replace)

// ── Invalidation Engine ────────────────────────────────────────────────────────

/**
 * InvalidationEngine - Applies invalidation rules to IR.
 */
class InvalidationEngine {
public:
    InvalidationEngine();
    ~InvalidationEngine();
    
    // Initialize with current binary
    void set_binary(ir::Binary* binary);
    
    // Apply invalidation for a trigger
    void invalidate(InvalidationTrigger trigger);
    void invalidate(InvalidationTrigger trigger, ir::AddressRange range);
    void invalidate(InvalidationTrigger trigger, ir::FunctionId specific_function);
    
    // Get all nodes marked for update/rebuild
    std::vector<ir::FunctionId> get_dirty_functions() const;
    std::vector<ir::BasicBlockId> get_dirty_blocks() const;
    std::vector<ir::InstructionId> get_dirty_instructions() const;
    
    // Check if specific node is dirty
    bool is_dirty(ir::FunctionId fn) const;
    bool is_dirty(ir::BasicBlockId bb) const;
    bool is_dirty(ir::InstructionId insn) const;
    
    // Cascade dirty flag to dependents
    void cascade_invalidation();
    
    // Clear dirty flags after re-analysis
    void mark_clean(ir::FunctionId fn);
    void mark_clean(ir::BasicBlockId bb);
    void mark_all_clean();
    
    // Statistics
    struct Stats {
        size_t nodes_invalidated = 0;
        size_t nodes_updated = 0;
        size_t nodes_rebuilt = 0;
        size_t cascade_steps = 0;
    };
    Stats get_stats() const;
    void reset_stats();
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ── Incremental Analysis State ────────────────────────────────────────────────

/**
 * IncrementalState - Tracks what needs re-analysis after invalidation.
 */
struct IncrementalState {
    // Stages that need re-run (from pipeline)
    std::unordered_set<ir::AnalysisStageDependency> dirty_stages;
    
    // Specific entities needing attention (for targeted re-analysis)
    std::unordered_set<ir::FunctionId> dirty_functions;
    std::unordered_set<ir::BasicBlockId> dirty_blocks;
    
    // Addresses that changed (for binary patching)
    std::vector<ir::AddressRange> patched_regions;
    
    // Whether we can do incremental or need full re-analysis
    bool can_incremental = true;
    
    // Clear all dirty state
    void clear();
    
    // Check if anything is dirty
    bool is_dirty() const {
        return !dirty_stages.empty() || 
               !dirty_functions.empty() || 
               !patched_regions.empty();
    }
};

// ── Utility: Address-to-Node Resolution ─────────────────────────────────────────

/**
 * Find which IR nodes contain a given address.
 */
struct NodeResolution {
    ir::SectionId section{ir::SectionId::Invalid};
    ir::FunctionId function{ir::FunctionId::Invalid};
    ir::BasicBlockId block{ir::BasicBlockId::Invalid};
    ir::InstructionId instruction{ir::InstructionId::Invalid};
};

NodeResolution resolve_address(
    const ir::Binary& binary,
    ir::QualifiedAddress addr
);

/**
 * Find all nodes affected by a patched region.
 */
std::vector<ir::FunctionId> find_affected_functions(
    const ir::Binary& binary,
    ir::AddressRange range
);

} // namespace atlus::analysis
