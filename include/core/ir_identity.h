#pragma once
#include <cstdint>
#include <array>
#include <string>
#include <functional>

namespace atlus::ir {

// Forward declarations from ir.h
struct FunctionId;
struct BasicBlockId;
struct InstructionId;

// ── IR Identity System ─────────────────────────────────────────────────────────

/**
 * IdentityVersion - Version stamp for IR node provenance.
 * 
 * Every IR node tracks which analysis stage produced it and when.
 * This enables precise incremental invalidation.
 */
struct IdentityVersion {
    uint32_t stage_sequence = 0;     // Monotonic counter per analysis run
    uint64_t timestamp = 0;          // For debugging/auditing
    uint32_t pass_iteration = 0;     // For iterative analyses (type propagation)
    
    bool operator==(const IdentityVersion& other) const {
        return stage_sequence == other.stage_sequence &&
               pass_iteration == other.pass_iteration;
    }
    bool operator!=(const IdentityVersion& other) const {
        return !(*this == other);
    }
    bool is_newer_than(const IdentityVersion& other) const {
        if (stage_sequence != other.stage_sequence) 
            return stage_sequence > other.stage_sequence;
        return pass_iteration > other.pass_iteration;
    }
};

/**
 * ContentHash - 128-bit content-addressed identity.
 * 
 * For deterministic reconstruction and deduplication.
 * Used for: basic blocks with identical instruction sequences,
 * type definitions, string literals.
 */
struct ContentHash {
    std::array<uint8_t, 16> bytes{};
    
    bool operator==(const ContentHash& other) const {
        return bytes == other.bytes;
    }
    
    std::string to_string() const;
    static ContentHash from_data(const uint8_t* data, size_t len);
    static ContentHash from_string(const std::string& str);
    
    // Compute hash of instruction bytes + metadata
    static ContentHash of_instruction_sequence(
        const uint8_t* bytes, 
        size_t len,
        uint64_t base_address
    );
};

// Hash support for ContentHash
struct ContentHashHasher {
    size_t operator()(const ContentHash& h) const {
        // FNV-1a on first 8 bytes (sufficient for hash tables)
        size_t hash = 14695981039346656037ull;
        for (int i = 0; i < 8; ++i) {
            hash ^= h.bytes[i];
            hash *= 1099511628211ull;
        }
        return hash;
    }
};

// ── Dependency Tracking ────────────────────────────────────────────────────────

/**
 * AnalysisDependency - Tracks which analysis stages contributed to an IR node.
 * 
 * This enables precise invalidation:
 * - If stage X is re-run, invalidate all nodes where dependencies[X] == true
 * - Avoids over-invalidating unrelated nodes
 */
enum class AnalysisStageDependency : uint32_t {
    ParsePE          = 0,
    MapSections      = 1,
    ScanFunctions    = 2,
    Disassemble      = 3,
    BuildBasicBlocks = 4,
    BuildCFG         = 5,
    AnalyzeXRefs     = 6,
    TypeInference    = 7,
    DataFlow         = 8,
    
    MaxStages = 32  // Bitmask size limit
};

/**
 * DependencyMask - Bitmask of analysis dependencies.
 */
struct DependencyMask {
    uint32_t bits = 0;
    
    void add(AnalysisStageDependency stage) {
        bits |= (1u << static_cast<uint32_t>(stage));
    }
    void remove(AnalysisStageDependency stage) {
        bits &= ~(1u << static_cast<uint32_t>(stage));
    }
    bool has(AnalysisStageDependency stage) const {
        return (bits & (1u << static_cast<uint32_t>(stage))) != 0;
    }
    bool has_any(const DependencyMask& other) const {
        return (bits & other.bits) != 0;
    }
    bool is_empty() const { return bits == 0; }
    void clear() { bits = 0; }
};

/**
 * DirtyFlags - Per-node invalidation state.
 */
enum class DirtyFlag : uint32_t {
    Clean        = 0,
    NeedsUpdate  = 1,  // Stage re-run, recompute derived data
    NeedsRebuild = 2,  // Dependencies changed significantly
    Invalid      = 3   // Node should be removed
};

/**
 * IRNodeIdentity - Identity metadata attached to every IR node.
 * 
 * This struct is embedded in (or parallel to) every IR entity:
 *   - Instruction::identity
 *   - BasicBlock::identity  
 *   - Function::identity
 *   - etc.
 */
struct IRNodeIdentity {
    // Content-addressed ID (for deduplication, deterministic reconstruction)
    ContentHash content_hash;
    
    // Provenance: which analysis stages created this node
    DependencyMask dependencies;
    
    // When this node was last updated
    IdentityVersion version;
    
    // Invalidation state
    DirtyFlag dirty_flag = DirtyFlag::Clean;
    
    // For type inference tracking (which passes have run)
    uint32_t type_pass_count = 0;
    
    bool is_dirty() const { return dirty_flag != DirtyFlag::Clean; }
    bool needs_rebuild() const { return dirty_flag == DirtyFlag::NeedsRebuild; }
    bool is_invalid() const { return dirty_flag == DirtyFlag::Invalid; }
    
    void mark_dirty(DirtyFlag flag = DirtyFlag::NeedsUpdate) {
        dirty_flag = flag;
    }
    void mark_clean() {
        dirty_flag = DirtyFlag::Clean;
    }
    
    // Check if this node depends on any stage in the mask
    bool depends_on(const DependencyMask& stages) const {
        return dependencies.has_any(stages);
    }
};

// ── Identity Generation ─────────────────────────────────────────────────────────

/**
 * IdentityGenerator - Produces stable identities during analysis.
 */
class IdentityGenerator {
public:
    explicit IdentityGenerator(uint32_t run_seed);
    
    // Generate identity for a newly created node
    IRNodeIdentity create(
        AnalysisStageDependency primary_stage,
        const uint8_t* content_data = nullptr,
        size_t content_len = 0
    );
    
    // Update existing identity (incremental analysis)
    void update(IRNodeIdentity& identity, AnalysisStageDependency stage);
    
    // Get current version for new nodes
    IdentityVersion current_version() const { return current_version_; }
    
    // Advance to next analysis phase
    void next_stage();
    
private:
    uint32_t run_seed_;           // Per-analysis-run seed
    uint32_t stage_counter_ = 0;  // Monotonic stage sequence
    uint32_t node_counter_ = 0;   // Per-stage node counter
    IdentityVersion current_version_;
};

// ── Node References with Identity ────────────────────────────────────────────────

/**
 * StableRef - Reference to an IR node that survives re-analysis.
 * 
 * Uses content_hash + version for re-resolution after invalidation.
 */
template<typename IdType>
struct StableRef {
    ContentHash content_hash;   // Persistent identity
    IdType current_id;          // May change after re-analysis
    IdentityVersion last_seen_version;
    
    bool is_resolved() const {
        return current_id != IdType::Invalid;
    }
    void invalidate() {
        current_id = IdType::Invalid;
    }
};

using StableFunctionRef = StableRef<FunctionId>;
using StableBlockRef = StableRef<BasicBlockId>;
using StableInstructionRef = StableRef<InstructionId>;

} // namespace atlus::ir
