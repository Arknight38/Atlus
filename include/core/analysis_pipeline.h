#pragma once
#include "core/ir.h"
#include "core/error.h"
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <any>

namespace atlus::analysis {

// ─= Analysis Stage Definitions ────────────────────────────────────────────────

/**
 * AnalysisStage - Unique identifier for each analysis pass.
 * 
 * The pipeline is a DAG where nodes are stages and edges are dependencies.
 * Each stage produces artifacts that downstream stages consume.
 */
enum class AnalysisStage : uint32_t {
    // Input layer
    LoadBinary = 0,       // Binary loaded from disk
    ParsePE,              // PE headers parsed
    
    // Section layer
    MapSections,          // Section boundaries established
    
    // Disassembly layer  
    ScanFunctionEntries,  // Prologue heuristic scan
    DisassembleFunctions, // Full function disassembly
    BuildBasicBlocks,     // BB detection from disassembly
    
    // CFG layer
    BuildCFG,             // Control flow graph per function
    
    // XRef layer
    AnalyzeXRefs,         // Cross-reference analysis
    
    // Data layer
    FindStrings,          // String literal detection
    FindImports,          // Import table analysis
    FindExports,          // Export table analysis
    
    // Type layer (future)
    // TypePropagation,
    // StructRecovery,
    
    // Diff layer
    ComputeDiff,          // Byte/section/function diff
    GenerateSignatures,   // AOB pattern generation
    
    Count  // Must be last
};

const char* stage_name(AnalysisStage stage);

// ─= Artifacts (Stage Outputs) ────────────────────────────────────────────────

/**
 * AnalysisArtifact - Typed output from an analysis stage.
 * 
 * Each stage produces strongly-typed artifacts that are cached and
 * can be invalidated when upstream dependencies change.
 */
struct AnalysisArtifact {
    enum class Type {
        Empty,
        SectionList,        // std::vector<ir::SectionId>
        FunctionList,       // std::vector<ir::FunctionId>
        BasicBlockGraph,    // std::vector<ir::BasicBlockId> + edges
        XRefList,           // std::vector<ir::XRef>
        StringList,         // std::vector<ir::SymbolId> (string symbols)
        DiffResult,         // Diff artifacts
        Custom              // Extension point for plugins
    };
    
    Type type = Type::Empty;
    std::any data;
    
    template<typename T>
    const T* get() const {
        if (type == Type::Empty) return nullptr;
        return std::any_cast<T>(&data);
    }
};

// ─= Stage Configuration ───────────────────────────────────────────────────────

/**
 * StageConfig - Per-stage configuration options.
 */
struct StageConfig {
    // Whether this stage can run incrementally on partial changes
    bool incremental = false;
    
    // Maximum time budget (0 = unlimited)
    uint32_t timeout_ms = 0;
    
    // Whether to cache results
    bool cacheable = true;
    
    // Whether to skip on error
    bool skip_on_error = false;
};

// ─= Pipeline Node ───────────────────────────────────────────────────────────

/**
 * StageRunner - Interface for analysis stage implementations.
 */
class StageRunner {
public:
    virtual ~StageRunner() = default;
    
    virtual AnalysisStage stage() const = 0;
    virtual std::vector<AnalysisStage> dependencies() const = 0;
    virtual StageConfig config() const = 0;
    
    // Execute the stage. Returns artifacts on success.
    virtual Result<AnalysisArtifact> run(
        ir::Binary& binary,
        const std::unordered_map<AnalysisStage, const AnalysisArtifact*>& inputs
    ) = 0;
    
    // Check if stage needs re-run (e.g., incremental change detection)
    virtual bool is_stale(const ir::Binary& binary) const { return true; }
};

// ─= Analysis Pipeline ─────────────────────────────────────────────────────────

/**
 * AnalysisPipeline - Manages the DAG of analysis stages.
 * 
 * Features:
 *   - Dependency-aware execution order (topological sort)
 *   - Incremental re-computation
 *   - Artifact caching
 *   - Parallel execution where safe
 */
class AnalysisPipeline {
public:
    AnalysisPipeline();
    ~AnalysisPipeline();
    
    // Register a stage implementation
    void register_stage(std::unique_ptr<StageRunner> runner);
    
    // Build execution plan for requested stages
    std::vector<AnalysisStage> build_plan(
        const std::vector<AnalysisStage>& targets
    ) const;
    
    // Run full pipeline or specific stages
    Result<void> run_all(ir::Binary& binary);
    Result<void> run_stages(ir::Binary& binary, const std::vector<AnalysisStage>& stages);
    
    // Run single stage (dependencies must be satisfied)
    Result<AnalysisArtifact> run_stage(ir::Binary& binary, AnalysisStage stage);
    
    // Cache management
    void clear_cache();
    void clear_stage_cache(AnalysisStage stage);
    bool has_cached(AnalysisStage stage) const;
    const AnalysisArtifact* get_cached(AnalysisStage stage) const;
    
    // Invalidation
    void invalidate(AnalysisStage stage);  // Invalidate this stage and all dependents
    void invalidate_from(AnalysisStage stage);  // Invalidate downstream stages
    
    // Progress callback
    using ProgressCallback = std::function<void(AnalysisStage stage, float progress)>;
    void set_progress_callback(ProgressCallback cb);
    
    // Query
    bool is_stage_registered(AnalysisStage stage) const;
    std::vector<AnalysisStage> get_registered_stages() const;
    std::vector<AnalysisStage> get_dependents(AnalysisStage stage) const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ─= Predefined Stage Runners ──────────────────────────────────────────────────

/**
 * Factory functions for built-in analysis stages.
 */
std::unique_ptr<StageRunner> create_parsing_stage();
std::unique_ptr<StageRunner> create_section_mapping_stage();
std::unique_ptr<StageRunner> create_function_scan_stage();
std::unique_ptr<StageRunner> create_disassembly_stage();
std::unique_ptr<StageRunner> create_basic_block_stage();
std::unique_ptr<StageRunner> create_cfg_stage();
std::unique_ptr<StageRunner> create_xref_stage();
std::unique_ptr<StageRunner> create_string_finder_stage();

/**
 * Register all built-in stages with a pipeline.
 */
void register_builtin_stages(AnalysisPipeline& pipeline);

// ─= Analysis Context ──────────────────────────────────────────────────────────

/**
 * AnalysisContext - High-level interface for running analysis.
 * 
 * This is the main entry point for the analysis system.
 * It owns the pipeline and provides simplified APIs.
 */
class AnalysisContext {
public:
    AnalysisContext();
    ~AnalysisContext();
    
    // Analyze a binary from scratch
    Result<std::unique_ptr<ir::Binary>> analyze(const std::string& path);
    
    // Analyze with custom stage selection
    Result<std::unique_ptr<ir::Binary>> analyze_partial(
        const std::string& path,
        const std::vector<AnalysisStage>& stages
    );
    
    // Re-analyze after changes (incremental)
    Result<void> reanalyze(ir::Binary& binary, const std::vector<AnalysisStage>& stages);
    
    // Access pipeline for advanced usage
    AnalysisPipeline& pipeline() { return pipeline_; }
    
private:
    AnalysisPipeline pipeline_;
};

} // namespace atlus::analysis
