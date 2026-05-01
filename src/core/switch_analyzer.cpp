#include "core/switch_analyzer.h"
#include <cstring>
#include <algorithm>

namespace atlus {

// ── Constructor ──────────────────────────────────────────────────────────────

SwitchAnalyzer::SwitchAnalyzer(Disassembler* disasm) : disasm_(disasm) {}

// ── Pattern Detection ──────────────────────────────────────────────────────

bool SwitchAnalyzer::is_indirect_jump(const ir::Instruction& insn) {
    // Check if instruction is an indirect jump (jmp with memory operand)
    return insn.mnemonic.find("jmp") == 0 && 
           insn.operands_text.find("ptr") != std::string::npos;
}

bool SwitchAnalyzer::is_jump_table_pattern(const ir::Instruction& insn, uint64_t addr) {
    if (!is_indirect_jump(insn)) return false;
    
    // Look for memory access patterns like [reg*scale+offset] or [rip+offset]
    const std::string& ops = insn.operands_text;
    
    // RIP-relative addressing (x64)
    if (ops.find("rip") != std::string::npos) {
        return true;
    }
    
    // Scaled index addressing (x86/x64)
    // Pattern: [reg*scale+displacement]
    if (ops.find("[") != std::string::npos && 
        (ops.find("*") != std::string::npos || ops.find("+") != std::string::npos)) {
        return true;
    }
    
    return false;
}

std::optional<SwitchAnalyzer::IndirectJumpInfo> SwitchAnalyzer::detect_indirect_jump(
    const ir::Instruction& insn,
    uint64_t insn_addr
) {
    if (!is_jump_table_pattern(insn, insn_addr)) {
        return std::nullopt;
    }
    
    IndirectJumpInfo info;
    info.address = insn_addr;
    info.scale = 4;  // Default scale (32-bit pointers)
    info.offset = 0;
    
    // Parse the operand to extract table address
    // x64: jmp qword ptr [rip + 0x1234]
    // The table address is RIP + instruction length + offset
    
    const std::string& ops = insn.operands_text;
    
    // Try to extract hex offset from operand
    size_t hex_pos = ops.find("0x");
    if (hex_pos != std::string::npos) {
        int64_t offset = std::strtoll(ops.c_str() + hex_pos, nullptr, 16);
        
        // RIP-relative: table = current instruction + length + offset
        info.table_base = insn_addr + insn.length + offset;
        info.type = SwitchTableType::X64Relative;
    }
    else {
        // x86: jmp dword ptr [eax*4 + 0x12345678]
        // Extract the base address from the displacement
        hex_pos = ops.rfind("0x");  // Look for last hex number
        if (hex_pos != std::string::npos) {
            info.table_base = std::strtoull(ops.c_str() + hex_pos + 2, nullptr, 16);
            info.type = SwitchTableType::SimpleArray;
        }
    }
    
    return info;
}

// ── Table Reading ──────────────────────────────────────────────────────────

std::vector<uint64_t> SwitchAnalyzer::read_table_entries(
    uint64_t table_addr,
    size_t count,
    size_t entry_size,
    const ir::Binary& binary
) {
    std::vector<uint64_t> entries;
    
    // Find section containing the table
    for (const auto& section : binary.sections()) {
        uint64_t sec_start = section->virtual_addr.offset;
        uint64_t sec_end = sec_start + section->virtual_size;
        
        if (table_addr >= sec_start && table_addr < sec_end) {
            size_t offset = static_cast<size_t>(table_addr - sec_start);
            
            // Note: Need section data from BinaryFile/PEInfo for actual implementation
            for (size_t i = 0; i < count && offset + entry_size <= section->virtual_size; ++i) {
                uint64_t value = 0;
                
                if (entry_size == 4) {
                    // 32-bit pointer - placeholder, needs actual section data
                    // value = *reinterpret_cast<const uint32_t*>(section_data + offset);
                    // If image base is known, add it for RVAs
                    if (value < 0x10000 && binary.image_base() > 0) {
                        value += binary.image_base();
                    }
                } else if (entry_size == 8) {
                    // 64-bit pointer - placeholder, needs actual section data
                    // value = *reinterpret_cast<const uint64_t*>(section_data + offset);
                }
                
                entries.push_back(value);
                offset += entry_size;
            }
            break;
        }
    }
    
    return entries;
}

bool SwitchAnalyzer::is_valid_code_target(uint64_t addr, const ir::Binary& binary) {
    for (const auto& section : binary.sections()) {
        if (section->is_executable) {
            uint64_t sec_start = section->virtual_addr.offset;
            uint64_t sec_end = sec_start + section->virtual_size;
            if (addr >= sec_start && addr < sec_end) {
                return true;
            }
        }
    }
    return false;
}

// ── Table Building ─────────────────────────────────────────────────────────

SwitchTable SwitchAnalyzer::build_switch_table(
    const IndirectJumpInfo& jump_info,
    const ir::Binary& binary
) {
    SwitchTable table;
    table.jump_instruction_addr = jump_info.address;
    table.table_address = jump_info.table_base;
    table.type = jump_info.type;
    table.has_default = false;
    table.is_contiguous = true;
    
    // Try different table sizes to find valid entries
    // Start with common sizes and validate
    size_t entry_size = binary.is_64bit() ? 8 : 4;
    std::vector<size_t> try_counts = {8, 16, 32, 64, 128, 256};
    
    for (size_t try_count : try_counts) {
        auto entries = read_table_entries(jump_info.table_base, try_count, entry_size, binary);
        
        // Validate entries - count valid code targets
        size_t valid_count = 0;
        for (const auto& entry : entries) {
            if (is_valid_code_target(entry, binary)) {
                valid_count++;
            } else {
                break;  // Stop at first invalid entry
            }
        }
        
        if (valid_count > 0 && valid_count < entries.size()) {
            // Found table with valid entries followed by invalid
            table.case_count = valid_count;
            table.cases.reserve(valid_count);
            
            for (size_t i = 0; i < valid_count; ++i) {
                SwitchTableCase case_info;
                case_info.value = i;  // Contiguous case values 0, 1, 2...
                case_info.target_address = entries[i];
                table.cases.push_back(case_info);
            }
            
            table.min_value = 0;
            table.max_value = valid_count - 1;
            table.is_contiguous = true;
            
            return table;
        }
    }
    
    return table;  // Empty if no valid table found
}

std::optional<SwitchTable> SwitchAnalyzer::parse_switch_table(
    uint64_t table_addr,
    size_t max_cases,
    const ir::Binary& binary
) {
    IndirectJumpInfo dummy_info;
    dummy_info.table_base = table_addr;
    dummy_info.type = SwitchTableType::SimpleArray;
    
    auto table = build_switch_table(dummy_info, binary);
    
    if (table.case_count > 0) {
        return table;
    }
    return std::nullopt;
}

// ── Main Analysis ──────────────────────────────────────────────────────────

SwitchAnalysisResult SwitchAnalyzer::analyze_function(
    const ir::Function& func,
    const std::vector<uint8_t>& code,
    uint64_t base_addr,
    const ir::Binary& binary
) {
    SwitchAnalysisResult result;
    (void)func;
    (void)code;
    (void)base_addr;
    (void)binary;
    
    // Note: This function needs to be reworked to either:
    // 1. Use atlus::Instruction for decoding and map to ir::Instruction for analysis
    // 2. Work with pre-built IR from the binary instead of decoding raw bytes
    // For now, stubbed out since it mixes Disassembler::Instruction with ir::Instruction
    
    result.success = false;
    result.table_count = 0;
    return result;
}

// ── Utility Functions ────────────────────────────────────────────────────

const char* switch_type_name(SwitchTableType type) {
    switch (type) {
        case SwitchTableType::SimpleArray: return "Simple Array";
        case SwitchTableType::ComputedOffset: return "Computed Offset";
        case SwitchTableType::X64Relative: return "x64 RIP-relative";
        case SwitchTableType::PackedBitmap: return "Packed Bitmap";
        default: return "Unknown";
    }
}

} // namespace atlus
