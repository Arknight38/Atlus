#pragma once
#include "core/ir.h"
#include "core/disassembler.h"
#include <vector>
#include <optional>

namespace atlus {

// ── Switch Table Analyzer ───────────────────────────────────────────────────
// Analyzes indirect jumps to recover switch table targets.
// Detects common jump table patterns for switch/case statements.

enum class SwitchTableType {
    Unknown,
    SimpleArray,        // jmp [table + index*4]
    ComputedOffset,     // jmp [base + index * scale + offset]
    X64Relative,        // RIP-relative addressing in x64
    PackedBitmap        // Sparse switch using bitmap lookup
};

struct SwitchTableCase {
    uint64_t value;           // Case value (0, 1, 2... or sparse values)
    uint64_t target_address;  // Code address for this case
};

struct SwitchTable {
    uint64_t jump_instruction_addr;  // Address of the indirect jump
    uint64_t table_address;          // Address of the jump table in memory
    SwitchTableType type;
    size_t case_count;
    uint64_t min_value;              // Minimum case value
    uint64_t max_value;              // Maximum case value
    std::vector<SwitchTableCase> cases;
    
    // For analysis
    bool is_contiguous;              // Cases are 0,1,2...N
    bool has_default;                // Has a default case target
    uint64_t default_target;         // Default case address
};

struct SwitchAnalysisResult {
    bool success = false;
    size_t table_count = 0;
    std::vector<SwitchTable> tables;
};

class SwitchAnalyzer {
public:
    SwitchAnalyzer(Disassembler* disasm);
    
    // Analyze function for switch tables
    SwitchAnalysisResult analyze_function(
        const ir::Function& func,
        const std::vector<uint8_t>& code,
        uint64_t base_addr,
        const ir::Binary& binary
    );
    
    // Try to parse a switch table at given address
    std::optional<SwitchTable> parse_switch_table(
        uint64_t table_addr,
        size_t max_cases,
        const ir::Binary& binary
    );

private:
    Disassembler* disasm_;
    
    // Pattern detection for indirect jumps
    struct IndirectJumpInfo {
        uint64_t address;
        uint64_t table_base;
        uint64_t index_reg;
        uint32_t scale;
        uint64_t offset;
        SwitchTableType type = SwitchTableType::Unknown;
    };
    
    // Detect indirect jump patterns
    std::optional<IndirectJumpInfo> detect_indirect_jump(
        const ir::Instruction& insn,
        uint64_t insn_addr
    );
    
    // Common patterns:
    // x86: jmp dword ptr [eax*4 + table]
    // x64: jmp qword ptr [rip + offset]  (RIP-relative)
    
    bool is_indirect_jump(const ir::Instruction& insn);
    bool is_jump_table_pattern(const ir::Instruction& insn, uint64_t addr);
    
    // Read table entries
    std::vector<uint64_t> read_table_entries(
        uint64_t table_addr,
        size_t count,
        size_t entry_size,
        const ir::Binary& binary
    );
    
    // Validate that target addresses are within code section
    bool is_valid_code_target(uint64_t addr, const ir::Binary& binary);
    
    // Build switch table from parsed data
    SwitchTable build_switch_table(
        const IndirectJumpInfo& jump_info,
        const ir::Binary& binary
    );
};

// ── Utility Functions ─────────────────────────────────────────────────────

const char* switch_type_name(SwitchTableType type);

} // namespace atlus
