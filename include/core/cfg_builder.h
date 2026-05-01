#pragma once
#include "ir.h"
#include "disassembler.h"
#include <vector>
#include <unordered_set>
#include <unordered_map>

namespace atlus {

// ── Control Flow Graph Builder ───────────────────────────────────────────────
// Builds basic blocks and CFG edges by analyzing branch instructions.
// Uses iterative disassembly + leader identification algorithm.

struct CFGBuildResult {
    bool success = false;
    std::string error_message;
    size_t basic_block_count = 0;
    size_t edge_count = 0;
};

class CFGBuilder {
public:
    CFGBuilder(Disassembler* disasm);
    
    // Build CFG for a single function
    // Disassembles instructions, identifies leaders, creates basic blocks,
    // and establishes successor/predecessor edges
    CFGBuildResult build(Function& func, const std::vector<uint8_t>& code, uint64_t base_addr);
    
    // Build CFGs for all functions in a section
    void build_all(std::vector<Function>& functions, const std::vector<uint8_t>& code, uint64_t base_addr);

private:
    Disassembler* disasm_;
    
    // Phase 1: Disassemble all instructions in function range
    struct DecodedInsn {
        uint64_t address;
        uint32_t length;
        bool is_branch;
        bool is_conditional;
        bool is_call;
        bool is_return;
        bool is_jump;
        int64_t branch_target;  // -1 if indirect or unknown
    };
    
    std::vector<DecodedInsn> disassemble_range(
        const std::vector<uint8_t>& code, 
        uint64_t base_addr,
        uint64_t start_offset,
        uint64_t end_offset
    );
    
    // Phase 2: Identify basic block leaders
    // Leaders are:
    // - First instruction of function
    // - Target of any branch
    // - Instruction after a conditional branch
    // - Instruction after a call (if fallthrough)
    std::unordered_set<uint64_t> find_leaders(const std::vector<DecodedInsn>& insns);
    
    // Phase 3: Create basic blocks from leaders
    std::vector<BasicBlock> create_basic_blocks(
        const std::vector<DecodedInsn>& insns,
        const std::unordered_set<uint64_t>& leaders,
        Function& func
    );
    
    // Phase 4: Connect edges between blocks
    void connect_edges(
        std::vector<BasicBlock>& blocks,
        const std::vector<DecodedInsn>& insns,
        const std::unordered_map<uint64_t, BasicBlockId>& addr_to_block
    );
    
    // Get address of next sequential instruction
    uint64_t get_next_address(const DecodedInsn& insn) const;
};

// ── Utility Functions ────────────────────────────────────────────────────────

// Check if instruction is a branch/jump
bool is_branch_instruction(const Disassembler::Instruction& insn);
bool is_conditional_branch(const Disassembler::Instruction& insn);
bool is_unconditional_jump(const Disassembler::Instruction& insn);
bool is_call_instruction(const Disassembler::Instruction& insn);
bool is_return_instruction(const Disassembler::Instruction& insn);

// Extract branch target from instruction
// Returns -1 if indirect/unknown
int64_t get_branch_target(const Disassembler::Instruction& insn, uint64_t insn_addr, uint32_t insn_length);

// Check if instruction falls through to next
bool has_fallthrough(const Disassembler::Instruction& insn);

} // namespace atlus
