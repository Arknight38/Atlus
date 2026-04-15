#pragma once
#include "core/ir.h"
#include "core/ir_identity.h"
#include <string>

namespace atlus::ir {

// ── IR Entity Governance ───────────────────────────────────────────────────────

/**
 * Governance rules for each IR entity type.
 * 
 * Every entity MUST define:
 * 1. Identity rule - How is this entity uniquely identified?
 * 2. Ownership rule - Who owns this entity's lifetime?
 * 3. Mutation rule - What modifications are allowed and when?
 * 4. Invalidation dependencies - Which analysis stages affect this entity?
 * 
 * This prevents "IR inflation" where entities accumulate without
 * clear invariants, becoming a "data dump graph" instead of a
 * semantic model.
 */

// ── Function Governance ──────────────────────────────────────────────────────────

/**
 * Function identity is derived from:
 * - Content: Hash of first N instructions (prologue)
 * - Address: Start address in Image space
 * - Context: Parent binary + section
 * 
 * Two functions in different binaries may have same content hash
 * but different IDs (binary-scoped namespace).
 */
struct FunctionGovernance {
    // Identity
    static ContentHash compute_identity(
        QualifiedAddress start_addr,
        const uint8_t* prologue_bytes,
        size_t prologue_len
    );
    
    // Ownership
    // - Owned by ir::Binary via std::unique_ptr<Function>
    // - Lifetime: Binary lifetime
    // - References: BasicBlock IDs stored in Function (owned by Binary)
    
    // Mutation Rules
    enum class Mutability {
        Immutable,      // Analysis complete, frozen
        StructureOnly,  // Can add/remove BBs, but not change start address
        FullAnalysis    // During initial analysis, everything mutable
    };
    
    static bool can_modify_start_address(Mutability state) {
        return state == Mutability::FullAnalysis;
    }
    static bool can_modify_instructions(Mutability state) {
        return state != Mutability::Immutable;
    }
    
    // Invalidation Dependencies
    static DependencyMask get_invalidation_deps() {
        DependencyMask mask;
        mask.add(AnalysisStageDependency::ScanFunctions);
        mask.add(AnalysisStageDependency::Disassemble);
        mask.add(AnalysisStageDependency::BuildBasicBlocks);
        return mask;
    }
    
    // Cross-entity dependencies
    // - Invalidates: BasicBlocks (cascade), XRefs (references to this function)
    // - Invalidated by: Section boundaries changing, binary rebasing
};

// ── BasicBlock Governance ────────────────────────────────────────────────────────

/**
 * BasicBlock identity is content-addressed:
 * - Content: Hash of instruction sequence
 * - Address: Start address
 * 
 * Deduplication: BBs with identical instruction sequences (e.g., thunk stubs)
 * can share a single instance with multiple parent functions.
 */
struct BasicBlockGovernance {
    // Identity
    static ContentHash compute_identity(
        const std::vector<InstructionId>& instructions,
        const Binary& binary  // For accessing instruction bytes
    );
    
    // Ownership
    // - Owned by ir::Binary via std::unique_ptr<BasicBlock>
    // - Referenced by: Function (parent), other BBs (successors/predecessors)
    // - NOTE: A BB may be referenced by multiple functions (shared thunks)
    
    // Mutation Rules
    enum class Mutability {
        Immutable,      // CFG complete
        EdgesOnly,      // Can modify successor/predecessor edges
        FullAnalysis    // During BB detection
    };
    
    static bool can_modify_edges(Mutability state) {
        return state != Mutability::Immutable;
    }
    static bool can_modify_instructions(Mutability state) {
        return state == Mutability::FullAnalysis;
    }
    
    // Invalidation Dependencies
    static DependencyMask get_invalidation_deps() {
        DependencyMask mask;
        mask.add(AnalysisStageDependency::Disassemble);
        mask.add(AnalysisStageDependency::BuildBasicBlocks);
        mask.add(AnalysisStageDependency::BuildCFG);
        return mask;
    }
    
    // Content-based deduplication support
    static bool is_deduplication_candidate(const BasicBlock& bb) {
        // Thunk stubs, common prologues, etc.
        return bb.instructions.size() <= 3;  // Small BBs likely duplicates
    }
};

// ── Instruction Governance ──────────────────────────────────────────────────────

/**
 * Instruction identity is immutable once decoded:
 * - Content: Raw instruction bytes
 * - Address: Location in binary
 * - Context: Parent basic block
 * 
 * Instructions are NEVER modified after creation. They are recreated
 * if disassembly changes (e.g., switching x86/x64 mode).
 */
struct InstructionGovernance {
    // Identity
    static ContentHash compute_identity(
        QualifiedAddress addr,
        const uint8_t* bytes,
        size_t len
    );
    
    // Ownership
    // - Owned by ir::Binary via std::unique_ptr<Instruction>
    // - Referenced by: BasicBlock (parent)
    // - Lifetime: Tied to parent BasicBlock
    
    // Mutation Rule: IMMUTABLE after creation
    // If disassembly changes, create new Instruction with new ID
    // Old instruction marked Invalid, removed during compaction
    
    static constexpr bool is_mutable = false;
    
    // Invalidation Dependencies
    static DependencyMask get_invalidation_deps() {
        DependencyMask mask;
        mask.add(AnalysisStageDependency::Disassemble);
        return mask;
    }
    
    // Recreation rule
    static bool requires_recreation(
        const Instruction& old_insn,
        const uint8_t* new_bytes,
        size_t new_len
    ) {
        // Any byte change = new instruction
        if (new_len != old_insn.bytes.size()) return true;
        return memcmp(new_bytes, old_insn.bytes.data(), new_len) != 0;
    }
};

// ── Symbol Governance ────────────────────────────────────────────────────────────

/**
 * Symbol identity has two modes:
 * 1. Import/Export: Name-based (e.g., "kernel32!CreateFileW")
 * 2. Discovered: Address-based (e.g., string at 0x1400001000)
 * 
 * Name symbols are unique by name. Address symbols are unique by address.
 */
struct SymbolGovernance {
    // Identity
    static ContentHash compute_identity_by_name(const std::string& name);
    static ContentHash compute_identity_by_address(QualifiedAddress addr);
    
    // Ownership
    // - Owned by ir::Binary
    // - Referenced by: Functions, XRefs, UI selection state
    
    // Mutation Rules
    enum class Mutability {
        Immutable,      // Fully analyzed
        NameEditable,   // User can rename (display only)
        TypeEditable,   // User can change type info
        FullEditable    // Analysis in progress
    };
    
    static bool can_rename(Mutability state) {
        return state == Mutability::NameEditable || 
               state == Mutability::FullEditable;
    }
    static bool can_change_type(Mutability state) {
        return state == Mutability::TypeEditable || 
               state == Mutability::FullEditable;
    }
    
    // User annotations vs. discovered
    static bool is_user_defined(const Symbol& sym) {
        // Symbols from imports/exports = discovered
        // Symbols user created = user-defined
        return sym.identity.dependencies.is_empty();  // No analysis produced this
    }
    
    // Invalidation Dependencies (minimal - symbols are persistent)
    static DependencyMask get_invalidation_deps() {
        DependencyMask mask;
        // Only ScanFunctions can discover new function symbols
        mask.add(AnalysisStageDependency::ScanFunctions);
        return mask;
    }
};

// ── XRef Governance ─────────────────────────────────────────────────────────────

/**
 * XRef identity is relationship-based:
 * - Content: (from_address, to_address, type) tuple
 * 
 * XRefs are derived data, recomputed by AnalyzeXRefs stage.
 */
struct XRefGovernance {
    // Identity
    static ContentHash compute_identity(
        QualifiedAddress from,
        QualifiedAddress to,
        XRef::Type type
    );
    
    // Ownership
    // - Owned by parent entity (Instruction for code refs, Symbol for data refs)
    // - Also indexed globally by target address for reverse lookup
    
    // Mutation Rule: DERIVED ONLY
    // Never manually created. Always produced by AnalyzeXRefs stage.
    static constexpr bool is_user_creatable = false;
    
    // Invalidation Dependencies
    static DependencyMask get_invalidation_deps() {
        DependencyMask mask;
        mask.add(AnalysisStageDependency::AnalyzeXRefs);
        return mask;
    }
    
    // Consistency rule: XRefs must match actual instruction operands
    static bool validate(
        const XRef& xref,
        const Instruction& from_insn,
        const Binary& binary
    );
};

// ── TypeInfo Governance ─────────────────────────────────────────────────────────

/**
 * Type identity is content-based (structural equality):
 * - Content: Canonical type descriptor
 * 
 * Types are deduplicated globally within a binary.
 */
struct TypeInfoGovernance {
    // Identity
    static ContentHash compute_identity(const TypeInfo& type);
    
    // Ownership
    // - Owned by ir::Binary
    // - Referenced by: Symbols (data), Functions (params/return), 
    //                  Instructions (operand types)
    
    // Mutation Rules
    // Types are immutable after creation. New types get new IDs.
    // Type equivalence is by content hash, not ID.
    static constexpr bool is_mutable = false;
    
    // Forward declaration handling
    static TypeId create_forward_declaration(const std::string& name);
    static bool resolve_forward_declaration(TypeId id, const TypeInfo& definition);
};

// ── Entity Lifecycle ────────────────────────────────────────────────────────────

/**
 * Lifecycle state machine for IR entities.
 */
enum class EntityLifecycle {
    Pending,        // Created but not yet analyzed
    Analyzing,      // Currently being analyzed
    Complete,       // Analysis complete, immutable
    Dirty,          // Needs update (dependencies changed)
    Invalid         // Should be removed
};

/**
 * EntityGovernance - Runtime governance checker.
 */
class EntityGovernance {
public:
    // Check if operation is allowed
    static bool can_modify(const Function& fn, FunctionGovernance::Mutability op);
    static bool can_modify(const BasicBlock& bb, BasicBlockGovernance::Mutability op);
    static bool can_modify(const Symbol& sym, SymbolGovernance::Mutability op);
    
    // Get current lifecycle state
    static EntityLifecycle get_lifecycle(const IRNodeIdentity& identity);
    
    // Validate entity consistency
    static bool validate(const Function& fn, const Binary& binary);
    static bool validate(const BasicBlock& bb, const Binary& binary);
    static bool validate(const Instruction& insn, const Binary& binary);
    
    // Log governance violation (for debugging)
    static void report_violation(
        const std::string& entity_type,
        EntityId id,
        const std::string& operation,
        const std::string& reason
    );
};

} // namespace atlus::ir
