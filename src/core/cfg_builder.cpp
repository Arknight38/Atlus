#include "core/ir.h"
#include "core/ir_governance.h"
#include <queue>
#include <unordered_set>

namespace atlus::analysis {

// Control Flow Graph Builder
class CFGBuilder {
public:
    void build(ir::Function& fn, ir::Binary& binary) {
        if (fn.basic_blocks.empty()) return;
        
        // Get entry block
        ir::BasicBlockId entry = fn.entry_block;
        if (entry == ir::BasicBlockId::Invalid && !fn.basic_blocks.empty()) {
            entry = fn.basic_blocks[0];
            fn.entry_block = entry;
        }
        
        // Build successor/predecessor relationships
        for (ir::BasicBlockId bb_id : fn.basic_blocks) {
            ir::BasicBlock* bb = const_cast<ir::BasicBlock*>(binary.get_basic_block(bb_id));
            if (!bb) continue;
            
            // Clear existing edges (rebuild)
            bb->successors.clear();
            bb->predecessors.clear();
            
            if (bb->instructions.empty()) continue;
            
            // Get last instruction
            ir::InstructionId last_insn_id = bb->instructions.back();
            const ir::Instruction* last_insn = binary.get_instruction(last_insn_id);
            if (!last_insn) continue;
            
            // Determine successors based on instruction type
            if (last_insn->is_return) {
                // No successors - function exit
                bb->is_exit = true;
            } else if (last_insn->is_call) {
                // Call returns to next block (fall-through)
                add_fallthrough_successor(fn, bb, bb_id, binary);
            } else if (last_insn->is_branch) {
                // Branch - conditional or unconditional
                if (last_insn->is_conditional) {
                    // Conditional: target + fallthrough
                    add_branch_target(fn, bb, last_insn, binary);
                    add_fallthrough_successor(fn, bb, bb_id, binary);
                } else {
                    // Unconditional: only target
                    add_branch_target(fn, bb, last_insn, binary);
                }
            } else {
                // Regular instruction - fall through to next block
                add_fallthrough_successor(fn, bb, bb_id, binary);
            }
        }
        
        // Build predecessor edges from successors
        for (ir::BasicBlockId bb_id : fn.basic_blocks) {
            ir::BasicBlock* bb = const_cast<ir::BasicBlock*>(binary.get_basic_block(bb_id));
            if (!bb) continue;
            
            for (ir::BasicBlockId succ_id : bb->successors) {
                ir::BasicBlock* succ = const_cast<ir::BasicBlock*>(binary.get_basic_block(succ_id));
                if (succ) {
                    // Add this block as predecessor if not already present
                    if (std::find(succ->predecessors.begin(), succ->predecessors.end(), bb_id) 
                        == succ->predecessors.end()) {
                        succ->predecessors.push_back(bb_id);
                    }
                }
            }
        }
        
        // Mark entry block
        if (entry != ir::BasicBlockId::Invalid) {
            ir::BasicBlock* entry_bb = const_cast<ir::BasicBlock*>(binary.get_basic_block(entry));
            if (entry_bb) {
                entry_bb->is_entry = true;
            }
        }
    }

private:
    void add_fallthrough_successor(const ir::Function& fn, ir::BasicBlock* bb, 
                                    ir::BasicBlockId current_id, ir::Binary& binary) {
        // Find next block in address order
        uint64_t current_end = bb->end_address.offset;
        
        ir::BasicBlockId next_bb = ir::BasicBlockId::Invalid;
        uint64_t next_addr = UINT64_MAX;
        
        for (ir::BasicBlockId other_id : fn.basic_blocks) {
            if (other_id == current_id) continue;
            
            const ir::BasicBlock* other = binary.get_basic_block(other_id);
            if (!other) continue;
            
            if (other->start_address.offset >= current_end && other->start_address.offset < next_addr) {
                next_addr = other->start_address.offset;
                next_bb = other_id;
            }
        }
        
        if (next_bb != ir::BasicBlockId::Invalid) {
            bb->successors.push_back(next_bb);
        }
    }
    
    void add_branch_target(const ir::Function& fn, ir::BasicBlock* bb,
                           const ir::Instruction* branch_insn, ir::Binary& binary) {
        // Extract target from operands
        for (const auto& operand : branch_insn->operands) {
            if (operand.is_address()) {
                const ir::Address& target_addr = std::get<ir::Address>(operand.data);
                
                // Find block containing this address
                for (ir::BasicBlockId other_id : fn.basic_blocks) {
                    const ir::BasicBlock* other = binary.get_basic_block(other_id);
                    if (!other) continue;
                    
                    if (target_addr.offset >= other->start_address.offset &&
                        target_addr.offset < other->end_address.offset) {
                        bb->successors.push_back(other_id);
                        break;
                    }
                }
            }
        }
    }
};

// Dominator analysis
class DominatorAnalysis {
public:
    struct DomTree {
        std::unordered_map<ir::BasicBlockId, std::vector<ir::BasicBlockId>> children;
        std::unordered_map<ir::BasicBlockId, ir::BasicBlockId> immediate_dominator;
    };
    
    DomTree compute(const ir::Function& fn, const ir::Binary& binary) {
        DomTree tree;
        
        if (fn.basic_blocks.empty()) return tree;
        
        // Initialize: entry block dominates itself
        ir::BasicBlockId entry = fn.entry_block;
        if (entry == ir::BasicBlockId::Invalid) {
            entry = fn.basic_blocks[0];
        }
        
        std::unordered_map<ir::BasicBlockId, std::unordered_set<ir::BasicBlockId>> dominators;
        
        // All blocks dominated by all blocks initially (except entry)
        for (ir::BasicBlockId bb_id : fn.basic_blocks) {
            if (bb_id == entry) {
                dominators[bb_id].insert(entry);
            } else {
                for (ir::BasicBlockId other : fn.basic_blocks) {
                    dominators[bb_id].insert(other);
                }
            }
        }
        
        // Iterative fixed-point
        bool changed = true;
        while (changed) {
            changed = false;
            
            for (ir::BasicBlockId bb_id : fn.basic_blocks) {
                if (bb_id == entry) continue;
                
                const ir::BasicBlock* bb = binary.get_basic_block(bb_id);
                if (!bb || bb->predecessors.empty()) continue;
                
                // New dominator set = intersection of all predecessors' dominator sets
                std::unordered_set<ir::BasicBlockId> new_dom = dominators[bb->predecessors[0]];
                for (size_t i = 1; i < bb->predecessors.size(); ++i) {
                    std::unordered_set<ir::BasicBlockId> intersection;
                    const auto& pred_dom = dominators[bb->predecessors[i]];
                    for (auto& d : new_dom) {
                        if (pred_dom.count(d)) intersection.insert(d);
                    }
                    new_dom = std::move(intersection);
                }
                
                // Add self
                new_dom.insert(bb_id);
                
                if (new_dom != dominators[bb_id]) {
                    dominators[bb_id] = std::move(new_dom);
                    changed = true;
                }
            }
        }
        
        // Build immediate dominator tree
        for (ir::BasicBlockId bb_id : fn.basic_blocks) {
            if (bb_id == entry) continue;
            
            // Find immediate dominator: strict dominator with no strict dominators in between
            const auto& dom_set = dominators[bb_id];
            
            for (ir::BasicBlockId candidate : dom_set) {
                if (candidate == bb_id) continue;
                
                bool is_idom = true;
                for (ir::BasicBlockId other : dom_set) {
                    if (other == bb_id || other == candidate) continue;
                    if (dominators[candidate].count(other)) {
                        is_idom = false;
                        break;
                    }
                }
                
                if (is_idom) {
                    tree.immediate_dominator[bb_id] = candidate;
                    tree.children[candidate].push_back(bb_id);
                    break;
                }
            }
        }
        
        return tree;
    }
};

// Loop detection
class LoopDetection {
public:
    struct Loop {
        ir::BasicBlockId header;
        std::vector<ir::BasicBlockId> blocks;
        std::vector<ir::BasicBlockId> back_edges;
    };
    
    std::vector<Loop> detect(const ir::Function& fn, const ir::Binary& binary) {
        std::vector<Loop> loops;
        
        DominatorAnalysis dom_analysis;
        auto dom_tree = dom_analysis.compute(fn, binary);
        
        // Find back edges: edge from A to B where B dominates A
        for (ir::BasicBlockId bb_id : fn.basic_blocks) {
            const ir::BasicBlock* bb = binary.get_basic_block(bb_id);
            if (!bb) continue;
            
            for (ir::BasicBlockId succ_id : bb->successors) {
                // Check if succ dominates bb (back edge)
                if (dom_tree.immediate_dominator.count(bb_id)) {
                    // Walk up dominator tree to see if succ is a dominator
                    ir::BasicBlockId current = bb_id;
                    while (current != ir::BasicBlockId::Invalid) {
                        if (current == succ_id) {
                            // Found back edge
                            Loop loop;
                            loop.header = succ_id;
                            loop.back_edges.push_back(bb_id);
                            
                            // Find all blocks in loop
                            find_loop_blocks(loop, fn, binary);
                            
                            loops.push_back(std::move(loop));
                            break;
                        }
                        
                        auto it = dom_tree.immediate_dominator.find(current);
                        if (it == dom_tree.immediate_dominator.end()) break;
                        current = it->second;
                    }
                }
            }
        }
        
        return loops;
    }
    
private:
    void find_loop_blocks(Loop& loop, const ir::Function& fn, const ir::Binary& binary) {
        // Natural loop: header + all blocks that can reach the back edge without going through header
        std::unordered_set<ir::BasicBlockId> visited;
        std::queue<ir::BasicBlockId> worklist;
        
        loop.blocks.push_back(loop.header);
        visited.insert(loop.header);
        
        // Start from back edge sources
        for (ir::BasicBlockId back_edge_src : loop.back_edges) {
            if (!visited.count(back_edge_src)) {
                worklist.push(back_edge_src);
                visited.insert(back_edge_src);
            }
        }
        
        // BFS backwards (through predecessors)
        while (!worklist.empty()) {
            ir::BasicBlockId current = worklist.front();
            worklist.pop();
            
            loop.blocks.push_back(current);
            
            const ir::BasicBlock* bb = binary.get_basic_block(current);
            if (!bb) continue;
            
            for (ir::BasicBlockId pred : bb->predecessors) {
                if (!visited.count(pred) && pred != loop.header) {
                    visited.insert(pred);
                    worklist.push(pred);
                }
            }
        }
    }
};

// Public API functions
void build_cfg(ir::Function& fn, ir::Binary& binary) {
    CFGBuilder builder;
    builder.build(fn, binary);
}

std::vector<ir::BasicBlockId> compute_dominators(
    ir::BasicBlockId block,
    const ir::Function& fn,
    const ir::Binary& binary
) {
    DominatorAnalysis analysis;
    auto tree = analysis.compute(fn, binary);
    
    std::vector<ir::BasicBlockId> result;
    
    // Walk up immediate dominator tree
    ir::BasicBlockId current = block;
    while (current != ir::BasicBlockId::Invalid) {
        result.push_back(current);
        
        auto it = tree.immediate_dominator.find(current);
        if (it == tree.immediate_dominator.end()) break;
        current = it->second;
    }
    
    return result;
}

ir::BasicBlockId get_immediate_dominator(
    ir::BasicBlockId block,
    const ir::Function& fn,
    const ir::Binary& binary
) {
    DominatorAnalysis analysis;
    auto tree = analysis.compute(fn, binary);
    
    auto it = tree.immediate_dominator.find(block);
    if (it == tree.immediate_dominator.end()) return ir::BasicBlockId::Invalid;
    return it->second;
}

} // namespace atlus::analysis
