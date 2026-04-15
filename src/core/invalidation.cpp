#include "core/invalidation.h"
#include <algorithm>

namespace atlus::analysis {

// Get canonical invalidation rule for each trigger
InvalidationRule get_invalidation_rule(InvalidationTrigger trigger) {
    InvalidationRule rule;
    rule.trigger = trigger;
    
    switch (trigger) {
        case InvalidationTrigger::BinaryLoaded:
            // Full reset - all stages affected
            for (uint32_t i = 0; i < static_cast<uint32_t>(ir::AnalysisStageDependency::MaxStages); ++i) {
                rule.affected_stages.add(static_cast<ir::AnalysisStageDependency>(i));
            }
            rule.cascade_to_dependents = true;
            rule.requires_full_reanalysis = true;
            break;
            
        case InvalidationTrigger::BinaryPatched:
            // Targeted - disassembly and downstream
            rule.affected_stages.add(ir::AnalysisStageDependency::Disassemble);
            rule.affected_stages.add(ir::AnalysisStageDependency::BuildBasicBlocks);
            rule.affected_stages.add(ir::AnalysisStageDependency::BuildCFG);
            rule.affected_stages.add(ir::AnalysisStageDependency::AnalyzeXRefs);
            rule.cascade_to_dependents = true;
            rule.requires_full_reanalysis = false;
            break;
            
        case InvalidationTrigger::BinaryRebased:
            // No structural changes - addresses are space-qualified
            rule.cascade_to_dependents = false;
            rule.requires_full_reanalysis = false;
            break;
            
        case InvalidationTrigger::SectionAdded:
        case InvalidationTrigger::SectionRemoved:
            // Major structural change
            rule.affected_stages.add(ir::AnalysisStageDependency::MapSections);
            rule.affected_stages.add(ir::AnalysisStageDependency::ScanFunctions);
            rule.cascade_to_dependents = true;
            rule.requires_full_reanalysis = true;
            break;
            
        case InvalidationTrigger::DisassemblyConfigChanged:
            rule.affected_stages.add(ir::AnalysisStageDependency::Disassemble);
            rule.affected_stages.add(ir::AnalysisStageDependency::BuildBasicBlocks);
            rule.affected_stages.add(ir::AnalysisStageDependency::BuildCFG);
            rule.affected_stages.add(ir::AnalysisStageDependency::AnalyzeXRefs);
            rule.cascade_to_dependents = true;
            rule.requires_full_reanalysis = true;
            break;
            
        case InvalidationTrigger::HeuristicTuningChanged:
            rule.affected_stages.add(ir::AnalysisStageDependency::ScanFunctions);
            rule.cascade_to_dependents = true;
            rule.requires_full_reanalysis = false;
            break;
            
        case InvalidationTrigger::TypeDatabaseUpdated:
            rule.affected_stages.add(ir::AnalysisStageDependency::TypeInference);
            rule.cascade_to_dependents = false;
            rule.requires_full_reanalysis = false;
            break;
            
        case InvalidationTrigger::ManualFunctionBoundaries:
            // Targeted - just that function
            rule.affected_stages.add(ir::AnalysisStageDependency::Disassemble);
            rule.affected_stages.add(ir::AnalysisStageDependency::BuildBasicBlocks);
            rule.affected_stages.add(ir::AnalysisStageDependency::BuildCFG);
            rule.affected_stages.add(ir::AnalysisStageDependency::AnalyzeXRefs);
            rule.cascade_to_dependents = false;
            rule.requires_full_reanalysis = false;
            break;
            
        case InvalidationTrigger::SymbolRenamed:
        case InvalidationTrigger::TypeAnnotationAdded:
            // Cosmetic - no structural changes
            rule.cascade_to_dependents = false;
            rule.requires_full_reanalysis = false;
            break;
            
        case InvalidationTrigger::DebugSymbolsLoaded:
        case InvalidationTrigger::ImportTableReconstructed:
            // Merge mode - augment existing
            rule.affected_stages.add(ir::AnalysisStageDependency::ScanFunctions);
            rule.affected_stages.add(ir::AnalysisStageDependency::TypeInference);
            rule.cascade_to_dependents = true;
            rule.requires_full_reanalysis = false;
            break;
    }
    
    return rule;
}

// InvalidationEngine implementation
struct InvalidationEngine::Impl {
    ir::Binary* binary = nullptr;
    std::unordered_set<ir::FunctionId> dirty_functions;
    std::unordered_set<ir::BasicBlockId> dirty_blocks;
    std::unordered_set<ir::InstructionId> dirty_instructions;
    Stats stats;
};

InvalidationEngine::InvalidationEngine() : impl_(std::make_unique<Impl>()) {}
InvalidationEngine::~InvalidationEngine() = default;

void InvalidationEngine::set_binary(ir::Binary* binary) {
    impl_->binary = binary;
    impl_->dirty_functions.clear();
    impl_->dirty_blocks.clear();
    impl_->dirty_instructions.clear();
    reset_stats();
}

void InvalidationEngine::invalidate(InvalidationTrigger trigger) {
    auto rule = get_invalidation_rule(trigger);
    
    if (rule.requires_full_reanalysis) {
        // Mark everything as needing rebuild
        if (impl_->binary) {
            for (const auto& fn : impl_->binary->functions()) {
                impl_->dirty_functions.insert(fn->id);
            }
        }
        impl_->stats.nodes_rebuilt++;
    } else if (!rule.affected_stages.is_empty()) {
        // Mark based on dependencies
        if (impl_->binary) {
            for (const auto& fn : impl_->binary->functions()) {
                if (fn->identity.depends_on(rule.affected_stages)) {
                    impl_->dirty_functions.insert(fn->id);
                    impl_->stats.nodes_invalidated++;
                }
            }
        }
    }
    
    if (rule.cascade_to_dependents) {
        cascade_invalidation();
    }
}

void InvalidationEngine::invalidate(InvalidationTrigger trigger, ir::AddressRange range) {
    if (!impl_->binary) return;
    
    // Find affected functions
    auto affected = find_affected_functions(*impl_->binary, range);
    for (auto fn_id : affected) {
        impl_->dirty_functions.insert(fn_id);
    }
    
    // Also apply general trigger rules
    auto rule = get_invalidation_rule(trigger);
    if (rule.requires_full_reanalysis && !rule.affected_stages.is_empty()) {
        for (const auto& fn : impl_->binary->functions()) {
            if (fn->identity.depends_on(rule.affected_stages)) {
                impl_->dirty_functions.insert(fn->id);
            }
        }
    }
    
    impl_->stats.nodes_invalidated += affected.size();
}

void InvalidationEngine::invalidate(InvalidationTrigger trigger, ir::FunctionId specific_function) {
    impl_->dirty_functions.insert(specific_function);
    impl_->stats.nodes_invalidated++;
    
    // Also apply cascade from this function
    if (impl_->binary) {
        const ir::Function* fn = impl_->binary->get_function(specific_function);
        if (fn) {
            for (ir::BasicBlockId bb_id : fn->basic_blocks) {
                impl_->dirty_blocks.insert(bb_id);
            }
        }
    }
}

std::vector<ir::FunctionId> InvalidationEngine::get_dirty_functions() const {
    return std::vector<ir::FunctionId>(
        impl_->dirty_functions.begin(), 
        impl_->dirty_functions.end()
    );
}

std::vector<ir::BasicBlockId> InvalidationEngine::get_dirty_blocks() const {
    return std::vector<ir::BasicBlockId>(
        impl_->dirty_blocks.begin(),
        impl_->dirty_blocks.end()
    );
}

std::vector<ir::InstructionId> InvalidationEngine::get_dirty_instructions() const {
    return std::vector<ir::InstructionId>(
        impl_->dirty_instructions.begin(),
        impl_->dirty_instructions.end()
    );
}

bool InvalidationEngine::is_dirty(ir::FunctionId fn) const {
    return impl_->dirty_functions.count(fn) > 0;
}

bool InvalidationEngine::is_dirty(ir::BasicBlockId bb) const {
    return impl_->dirty_blocks.count(bb) > 0;
}

bool InvalidationEngine::is_dirty(ir::InstructionId insn) const {
    return impl_->dirty_instructions.count(insn) > 0;
}

void InvalidationEngine::cascade_invalidation() {
    if (!impl_->binary) return;
    
    // Cascade from dirty functions to their BBs
    for (ir::FunctionId fn_id : impl_->dirty_functions) {
        const ir::Function* fn = impl_->binary->get_function(fn_id);
        if (fn) {
            for (ir::BasicBlockId bb_id : fn->basic_blocks) {
                impl_->dirty_blocks.insert(bb_id);
            }
        }
    }
    
    // Cascade from dirty BBs to their instructions
    for (ir::BasicBlockId bb_id : impl_->dirty_blocks) {
        const ir::BasicBlock* bb = impl_->binary->get_basic_block(bb_id);
        if (bb) {
            for (ir::InstructionId insn_id : bb->instructions) {
                impl_->dirty_instructions.insert(insn_id);
            }
        }
    }
    
    impl_->stats.cascade_steps++;
}

void InvalidationEngine::mark_clean(ir::FunctionId fn) {
    impl_->dirty_functions.erase(fn);
}

void InvalidationEngine::mark_clean(ir::BasicBlockId bb) {
    impl_->dirty_blocks.erase(bb);
}

void InvalidationEngine::mark_all_clean() {
    impl_->dirty_functions.clear();
    impl_->dirty_blocks.clear();
    impl_->dirty_instructions.clear();
}

InvalidationEngine::Stats InvalidationEngine::get_stats() const {
    return impl_->stats;
}

void InvalidationEngine::reset_stats() {
    impl_->stats = Stats{};
}

// Node resolution
NodeResolution resolve_address(const ir::Binary& binary, ir::QualifiedAddress addr) {
    NodeResolution res;
    
    // Find section
    for (const auto& sec : binary.sections()) {
        // Simple containment check - in full version use proper address translation
        if (addr.offset >= sec->virtual_addr.offset && 
            addr.offset < sec->virtual_addr.offset + sec->virtual_size) {
            res.section = sec->id;
            break;
        }
    }
    
    // Find function
    const ir::Function* fn = binary.find_function_at({addr.offset, ir::Address::Space::Virtual});
    if (fn) {
        res.function = fn->id;
        
        // Find basic block within function
        for (ir::BasicBlockId bb_id : fn->basic_blocks) {
            const ir::BasicBlock* bb = binary.get_basic_block(bb_id);
            if (bb && addr.offset >= bb->start_address.offset && 
                addr.offset < bb->end_address.offset) {
                res.block = bb_id;
                
                // Find instruction
                for (ir::InstructionId insn_id : bb->instructions) {
                    const ir::Instruction* insn = binary.get_instruction(insn_id);
                    if (insn && addr.offset >= insn->address.offset &&
                        addr.offset < insn->address.offset + insn->length) {
                        res.instruction = insn_id;
                        break;
                    }
                }
                break;
            }
        }
    }
    
    return res;
}

std::vector<ir::FunctionId> find_affected_functions(
    const ir::Binary& binary,
    ir::AddressRange range
) {
    std::vector<ir::FunctionId> result;
    
    for (const auto& fn : binary.functions()) {
        // Check if function intersects with range
        if (fn->start_address.offset < range.end.offset &&
            fn->end_address.offset > range.start.offset) {
            result.push_back(fn->id);
        }
    }
    
    return result;
}

// IncrementalState
void IncrementalState::clear() {
    dirty_stages.clear();
    dirty_functions.clear();
    dirty_blocks.clear();
    patched_regions.clear();
    can_incremental = true;
}

} // namespace atlus::analysis
