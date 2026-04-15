#include "core/analysis_pipeline.h"
#include <queue>
#include <algorithm>

namespace atlus::analysis {

const char* stage_name(AnalysisStage stage) {
    switch (stage) {
        case AnalysisStage::LoadBinary: return "LoadBinary";
        case AnalysisStage::ParsePE: return "ParsePE";
        case AnalysisStage::MapSections: return "MapSections";
        case AnalysisStage::ScanFunctionEntries: return "ScanFunctionEntries";
        case AnalysisStage::DisassembleFunctions: return "DisassembleFunctions";
        case AnalysisStage::BuildBasicBlocks: return "BuildBasicBlocks";
        case AnalysisStage::BuildCFG: return "BuildCFG";
        case AnalysisStage::AnalyzeXRefs: return "AnalyzeXRefs";
        case AnalysisStage::FindStrings: return "FindStrings";
        case AnalysisStage::FindImports: return "FindImports";
        case AnalysisStage::FindExports: return "FindExports";
        case AnalysisStage::ComputeDiff: return "ComputeDiff";
        case AnalysisStage::GenerateSignatures: return "GenerateSignatures";
        default: return "Unknown";
    }
}

// Pipeline implementation
struct AnalysisPipeline::Impl {
    std::unordered_map<AnalysisStage, std::unique_ptr<StageRunner>> stages;
    std::unordered_map<AnalysisStage, AnalysisArtifact> cache;
    std::unordered_map<AnalysisStage, bool> stale_flags;
    ProgressCallback progress_cb;
    
    // Get all dependencies for a stage (transitive)
    std::vector<AnalysisStage> get_all_dependencies(AnalysisStage stage) const {
        std::vector<AnalysisStage> result;
        std::unordered_set<AnalysisStage> visited;
        std::queue<AnalysisStage> to_visit;
        
        auto it = stages.find(stage);
        if (it == stages.end()) return result;
        
        for (auto dep : it->second->dependencies()) {
            to_visit.push(dep);
        }
        
        while (!to_visit.empty()) {
            AnalysisStage current = to_visit.front();
            to_visit.pop();
            
            if (visited.count(current)) continue;
            visited.insert(current);
            result.push_back(current);
            
            auto dep_it = stages.find(current);
            if (dep_it != stages.end()) {
                for (auto d : dep_it->second->dependencies()) {
                    if (!visited.count(d)) {
                        to_visit.push(d);
                    }
                }
            }
        }
        
        return result;
    }
};

AnalysisPipeline::AnalysisPipeline() : impl_(std::make_unique<Impl>()) {}
AnalysisPipeline::~AnalysisPipeline() = default;

void AnalysisPipeline::register_stage(std::unique_ptr<StageRunner> runner) {
    impl_->stages[runner->stage()] = std::move(runner);
}

std::vector<AnalysisStage> AnalysisPipeline::build_plan(
    const std::vector<AnalysisStage>& targets
) const {
    std::vector<AnalysisStage> result;
    std::unordered_set<AnalysisStage> visited;
    
    // Collect all dependencies
    std::vector<AnalysisStage> needed = targets;
    for (size_t i = 0; i < needed.size(); ++i) {
        auto deps = impl_->get_all_dependencies(needed[i]);
        for (auto dep : deps) {
            if (std::find(needed.begin(), needed.end(), dep) == needed.end()) {
                needed.push_back(dep);
            }
        }
    }
    
    // Topological sort (simplified: just sort by stage enum value)
    // In full implementation, use proper topological sort
    std::sort(needed.begin(), needed.end(), 
        [](AnalysisStage a, AnalysisStage b) {
            return static_cast<uint32_t>(a) < static_cast<uint32_t>(b);
        });
    
    return needed;
}

Result<void> AnalysisPipeline::run_all(ir::Binary& binary) {
    // Run all stages in order
    std::vector<AnalysisStage> all_stages;
    for (const auto& [stage, _] : impl_->stages) {
        all_stages.push_back(stage);
    }
    
    return run_stages(binary, all_stages);
}

Result<void> AnalysisPipeline::run_stages(
    ir::Binary& binary, 
    const std::vector<AnalysisStage>& stages
) {
    auto plan = build_plan(stages);
    
    for (AnalysisStage stage : plan) {
        auto result = run_stage(binary, stage);
        if (result.is_err()) {
            return result.error();
        }
        
        if (impl_->progress_cb) {
            impl_->progress_cb(stage, 1.0f);
        }
    }
    
    return Result<void>{};
}

Result<AnalysisArtifact> AnalysisPipeline::run_stage(ir::Binary& binary, AnalysisStage stage) {
    auto it = impl_->stages.find(stage);
    if (it == impl_->stages.end()) {
        return ATLUS_MAKE_ERROR(ErrorCode::NotFound, "Stage not registered");
    }
    
    // Check cache
    if (!it->second->config().cacheable) {
        impl_->cache.erase(stage);
    } else if (impl_->cache.count(stage) && !impl_->stages[stage]->is_stale(binary)) {
        return impl_->cache[stage];
    }
    
    // Collect input artifacts from dependencies
    std::unordered_map<AnalysisStage, const AnalysisArtifact*> inputs;
    for (auto dep : it->second->dependencies()) {
        auto dep_result = run_stage(binary, dep);
        if (dep_result.is_err()) {
            if (it->second->config().skip_on_error) {
                inputs[dep] = nullptr;
            } else {
                return dep_result.error();
            }
        } else {
            inputs[dep] = &impl_->cache[dep];
        }
    }
    
    // Run the stage
    auto result = it->second->run(binary, inputs);
    if (result.is_ok() && it->second->config().cacheable) {
        impl_->cache[stage] = result.value();
    }
    
    return result;
}

void AnalysisPipeline::clear_cache() {
    impl_->cache.clear();
}

void AnalysisPipeline::clear_stage_cache(AnalysisStage stage) {
    impl_->cache.erase(stage);
}

bool AnalysisPipeline::has_cached(AnalysisStage stage) const {
    return impl_->cache.count(stage) > 0;
}

const AnalysisArtifact* AnalysisPipeline::get_cached(AnalysisStage stage) const {
    auto it = impl_->cache.find(stage);
    if (it == impl_->cache.end()) return nullptr;
    return &it->second;
}

void AnalysisPipeline::invalidate(AnalysisStage stage) {
    impl_->cache.erase(stage);
    
    // Also invalidate dependents
    for (const auto& [s, runner] : impl_->stages) {
        auto deps = runner->dependencies();
        if (std::find(deps.begin(), deps.end(), stage) != deps.end()) {
            invalidate(s);
        }
    }
}

void AnalysisPipeline::invalidate_from(AnalysisStage stage) {
    // Invalidate this stage and all later stages
    for (const auto& [s, _] : impl_->stages) {
        if (static_cast<uint32_t>(s) >= static_cast<uint32_t>(stage)) {
            invalidate(s);
        }
    }
}

void AnalysisPipeline::set_progress_callback(ProgressCallback cb) {
    impl_->progress_cb = cb;
}

bool AnalysisPipeline::is_stage_registered(AnalysisStage stage) const {
    return impl_->stages.count(stage) > 0;
}

std::vector<AnalysisStage> AnalysisPipeline::get_registered_stages() const {
    std::vector<AnalysisStage> result;
    for (const auto& [stage, _] : impl_->stages) {
        result.push_back(stage);
    }
    return result;
}

std::vector<AnalysisStage> AnalysisPipeline::get_dependents(AnalysisStage stage) const {
    std::vector<AnalysisStage> result;
    for (const auto& [s, runner] : impl_->stages) {
        auto deps = runner->dependencies();
        if (std::find(deps.begin(), deps.end(), stage) != deps.end()) {
            result.push_back(s);
        }
    }
    return result;
}

// Built-in stage runners (stubs)

class ParsingStage : public StageRunner {
public:
    AnalysisStage stage() const override { return AnalysisStage::ParsePE; }
    std::vector<AnalysisStage> dependencies() const override {
        return {AnalysisStage::LoadBinary};
    }
    StageConfig config() const override {
        StageConfig cfg;
        cfg.cacheable = false;  // Always re-parse
        return cfg;
    }
    Result<AnalysisArtifact> run(
        ir::Binary& binary,
        const std::unordered_map<AnalysisStage, const AnalysisArtifact*>& inputs
    ) override {
        AnalysisArtifact artifact;
        artifact.type = AnalysisArtifact::Type::SectionList;
        // Would populate section list from PE parsing
        return artifact;
    }
};

class SectionMappingStage : public StageRunner {
public:
    AnalysisStage stage() const override { return AnalysisStage::MapSections; }
    std::vector<AnalysisStage> dependencies() const override {
        return {AnalysisStage::ParsePE};
    }
    StageConfig config() const override { return StageConfig{}; }
    Result<AnalysisArtifact> run(
        ir::Binary& binary,
        const std::unordered_map<AnalysisStage, const AnalysisArtifact*>& inputs
    ) override {
        AnalysisArtifact artifact;
        artifact.type = AnalysisArtifact::Type::SectionList;
        return artifact;
    }
};

class FunctionScanStage : public StageRunner {
public:
    AnalysisStage stage() const override { return AnalysisStage::ScanFunctionEntries; }
    std::vector<AnalysisStage> dependencies() const override {
        return {AnalysisStage::MapSections};
    }
    StageConfig config() const override { return StageConfig{}; }
    Result<AnalysisArtifact> run(
        ir::Binary& binary,
        const std::unordered_map<AnalysisStage, const AnalysisArtifact*>& inputs
    ) override {
        AnalysisArtifact artifact;
        artifact.type = AnalysisArtifact::Type::FunctionList;
        return artifact;
    }
};

class DisassemblyStage : public StageRunner {
public:
    AnalysisStage stage() const override { return AnalysisStage::DisassembleFunctions; }
    std::vector<AnalysisStage> dependencies() const override {
        return {AnalysisStage::ScanFunctionEntries};
    }
    StageConfig config() const override { return StageConfig{}; }
    Result<AnalysisArtifact> run(
        ir::Binary& binary,
        const std::unordered_map<AnalysisStage, const AnalysisArtifact*>& inputs
    ) override {
        AnalysisArtifact artifact;
        return artifact;
    }
};

class BasicBlockStage : public StageRunner {
public:
    AnalysisStage stage() const override { return AnalysisStage::BuildBasicBlocks; }
    std::vector<AnalysisStage> dependencies() const override {
        return {AnalysisStage::DisassembleFunctions};
    }
    StageConfig config() const override { return StageConfig{}; }
    Result<AnalysisArtifact> run(
        ir::Binary& binary,
        const std::unordered_map<AnalysisStage, const AnalysisArtifact*>& inputs
    ) override {
        AnalysisArtifact artifact;
        artifact.type = AnalysisArtifact::Type::BasicBlockGraph;
        return artifact;
    }
};

class CFGStage : public StageRunner {
public:
    AnalysisStage stage() const override { return AnalysisStage::BuildCFG; }
    std::vector<AnalysisStage> dependencies() const override {
        return {AnalysisStage::BuildBasicBlocks};
    }
    StageConfig config() const override { return StageConfig{}; }
    Result<AnalysisArtifact> run(
        ir::Binary& binary,
        const std::unordered_map<AnalysisStage, const AnalysisArtifact*>& inputs
    ) override {
        AnalysisArtifact artifact;
        artifact.type = AnalysisArtifact::Type::BasicBlockGraph;
        return artifact;
    }
};

class XRefStage : public StageRunner {
public:
    AnalysisStage stage() const override { return AnalysisStage::AnalyzeXRefs; }
    std::vector<AnalysisStage> dependencies() const override {
        return {AnalysisStage::BuildCFG};
    }
    StageConfig config() const override { return StageConfig{}; }
    Result<AnalysisArtifact> run(
        ir::Binary& binary,
        const std::unordered_map<AnalysisStage, const AnalysisArtifact*>& inputs
    ) override {
        AnalysisArtifact artifact;
        artifact.type = AnalysisArtifact::Type::XRefList;
        return artifact;
    }
};

class StringFinderStage : public StageRunner {
public:
    AnalysisStage stage() const override { return AnalysisStage::FindStrings; }
    std::vector<AnalysisStage> dependencies() const override {
        return {AnalysisStage::MapSections};
    }
    StageConfig config() const override { return StageConfig{}; }
    Result<AnalysisArtifact> run(
        ir::Binary& binary,
        const std::unordered_map<AnalysisStage, const AnalysisArtifact*>& inputs
    ) override {
        AnalysisArtifact artifact;
        artifact.type = AnalysisArtifact::Type::StringList;
        return artifact;
    }
};

std::unique_ptr<StageRunner> create_parsing_stage() {
    return std::make_unique<ParsingStage>();
}

std::unique_ptr<StageRunner> create_section_mapping_stage() {
    return std::make_unique<SectionMappingStage>();
}

std::unique_ptr<StageRunner> create_function_scan_stage() {
    return std::make_unique<FunctionScanStage>();
}

std::unique_ptr<StageRunner> create_disassembly_stage() {
    return std::make_unique<DisassemblyStage>();
}

std::unique_ptr<StageRunner> create_basic_block_stage() {
    return std::make_unique<BasicBlockStage>();
}

std::unique_ptr<StageRunner> create_cfg_stage() {
    return std::make_unique<CFGStage>();
}

std::unique_ptr<StageRunner> create_xref_stage() {
    return std::make_unique<XRefStage>();
}

std::unique_ptr<StageRunner> create_string_finder_stage() {
    return std::make_unique<StringFinderStage>();
}

void register_builtin_stages(AnalysisPipeline& pipeline) {
    pipeline.register_stage(create_parsing_stage());
    pipeline.register_stage(create_section_mapping_stage());
    pipeline.register_stage(create_function_scan_stage());
    pipeline.register_stage(create_disassembly_stage());
    pipeline.register_stage(create_basic_block_stage());
    pipeline.register_stage(create_cfg_stage());
    pipeline.register_stage(create_xref_stage());
    pipeline.register_stage(create_string_finder_stage());
}

// AnalysisContext implementation
AnalysisContext::AnalysisContext() {
    register_builtin_stages(pipeline_);
}

AnalysisContext::~AnalysisContext() = default;

Result<std::unique_ptr<ir::Binary>> AnalysisContext::analyze(const std::string& path) {
    // Load and analyze
    auto binary = std::make_unique<ir::Binary>(path, 0x140000000, true);
    
    auto result = pipeline_.run_all(*binary);
    if (result.is_err()) {
        return result.error();
    }
    
    return binary;
}

Result<std::unique_ptr<ir::Binary>> AnalysisContext::analyze_partial(
    const std::string& path,
    const std::vector<AnalysisStage>& stages
) {
    auto binary = std::make_unique<ir::Binary>(path, 0x140000000, true);
    
    auto result = pipeline_.run_stages(*binary, stages);
    if (result.is_err()) {
        return result.error();
    }
    
    return binary;
}

Result<void> AnalysisContext::reanalyze(
    ir::Binary& binary, 
    const std::vector<AnalysisStage>& stages
) {
    return pipeline_.run_stages(binary, stages);
}

} // namespace atlus::analysis
