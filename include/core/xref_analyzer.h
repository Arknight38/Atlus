#pragma once
#include <cstdint>
#include <vector>
#include <unordered_map>
#include "core/ir.h"
#include "core/disassembler.h"

namespace atlus {

// ── Cross-Reference Analyzer ─────────────────────────────────────────────────
// Analyzes instructions to detect cross-references (calls, jumps, data refs).
// Builds an index for fast xref queries in both directions.

struct XRefAnalysisResult {
    bool success = false;
    size_t xref_count = 0;
    std::vector<ir::XRef> xrefs;
    
    // Index: address -> xrefs from that address
    std::unordered_map<ir::Address, std::vector<ir::XRef>> outgoing;
    // Index: address -> xrefs to that address
    std::unordered_map<ir::Address, std::vector<ir::XRef>> incoming;
};

class XRefAnalyzer {
public:
    XRefAnalyzer(Disassembler* disasm);
    
    // Analyze all code sections for xrefs
    XRefAnalysisResult analyze(const ir::Binary& binary);
    
    // Analyze a single function
    XRefAnalysisResult analyze_function(const ir::Function& func, 
                                        const std::vector<uint8_t>& code,
                                        uint64_t base_addr);
    
    // Analyze a single section
    std::vector<ir::XRef> analyze_section(const ir::Section& section, const ir::Binary& binary);
    
    // Find all xrefs to a specific address (incoming)
    std::vector<ir::XRef> find_refs_to(ir::Address target, const XRefAnalysisResult& result);
    
    // Find all xrefs from a specific address (outgoing)
    std::vector<ir::XRef> find_refs_from(ir::Address source, const XRefAnalysisResult& result);
    
    // Find string references
    std::vector<ir::XRef> find_string_refs(const ir::Binary& binary, 
                                        const XRefAnalysisResult& code_refs);

private:
    Disassembler* disasm_;
    
    // Analyze single instruction for xrefs
    std::vector<ir::XRef> analyze_instruction(const ir::Instruction& insn,
                                           uint64_t insn_addr,
                                           const ir::Binary& binary);
    
    // Check if an immediate value is a valid code/data address
    bool is_valid_address(uint64_t addr, const ir::Binary& binary);
    
    // Extract immediate operands from instruction
    std::vector<uint64_t> get_immediate_operands(const ir::Instruction& insn);
    
    // Build bidirectional indexes
    void build_indexes(XRefAnalysisResult& result);
};

// ── XRef Query Utilities ─────────────────────────────────────────────────────

// Get human-readable description of xref type
const char* xref_type_name(ir::XRef::Type type);

// Check if xref is a call
bool is_call_xref(const ir::XRef& xref);

// Check if xref is a jump
bool is_jump_xref(const ir::XRef& xref);

// Check if xref is data reference
bool is_data_xref(const ir::XRef& xref);

} // namespace atlus
