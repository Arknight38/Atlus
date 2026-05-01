#include "core/xref_analyzer.h"
#include <algorithm>
#include <cstring>

namespace atlus {

// ── Constructor ─────────────────────────────────────────────────────────────

XRefAnalyzer::XRefAnalyzer(Disassembler* disasm) : disasm_(disasm) {}

// ── Analysis Methods ────────────────────────────────────────────────────────

XRefAnalysisResult XRefAnalyzer::analyze(const ir::Binary& binary) {
    XRefAnalysisResult result;
    
    for (const auto& section : binary.sections()) {
        if (!section->is_executable) continue;
        
        auto section_refs = analyze_section(*section, binary);
        (void)section_refs;
        result.xrefs.insert(result.xrefs.end(), 
                           section_refs.begin(), section_refs.end());
    }
    
    build_indexes(result);
    result.success = true;
    result.xref_count = result.xrefs.size();
    
    return result;
}

XRefAnalysisResult XRefAnalyzer::analyze_function(const ir::Function& func,
                                                   const std::vector<uint8_t>& code,
                                                   uint64_t base_addr) {
    XRefAnalysisResult result;
    
    // Note: This function needs to be reworked to use IR instructions
    // instead of decoding raw bytes. The ir::Function contains instruction
    // IDs that should be looked up in the binary.
    
    // TODO: Implement using func.basic_blocks and binary.get_instruction()
    
    build_indexes(result);
    result.success = true;
    result.xref_count = result.xrefs.size();
    
    return result;
}

std::vector<ir::XRef> XRefAnalyzer::analyze_section(const ir::Section& section, const ir::Binary& binary) {
    // TODO: Implement section analysis by iterating through functions in the section
    // and analyzing their instructions
    (void)section;
    (void)binary;
    return {};
}

std::vector<ir::XRef> XRefAnalyzer::analyze_instruction(const ir::Instruction& insn,
                                                       uint64_t insn_addr,
                                                       const ir::Binary& binary) {
    std::vector<ir::XRef> refs;
    
    // Check mnemonic for branch types
    bool is_call = insn.is_call;
    bool is_jump = insn.is_branch && !insn.is_call;
    bool is_ret = insn.is_return;
    
    if (is_ret) return refs;  // Returns don't have xrefs
    
    // For calls and jumps, try to extract target from operands
    if (is_call || is_jump) {
        // Check operands for address references
        for (const auto& op : insn.operands) {
            if (op.is_address()) {
                auto addr = std::get<ir::Address>(op.data);
                ir::XRef xref;
                xref.from_address = insn.address;
                xref.to_address = addr;
                xref.type = is_call ? ir::XRef::Type::Call : ir::XRef::Type::Jump;
                refs.push_back(xref);
            }
        }
    }
    
    // Check for data references in operands
    auto imms = get_immediate_operands(insn);
    for (uint64_t imm : imms) {
        // Skip if already recorded as code xref
        bool already_recorded = false;
        for (const auto& ref : refs) {
            if (ref.to_address.offset == imm) {
                already_recorded = true;
                break;
            }
        }
        if (already_recorded) continue;
        
        // If it looks like a data address, record it
        ir::XRef xref;
        xref.from_address = insn.address;
        xref.to_address = ir::Address::virtual_addr(imm);
        xref.type = ir::XRef::Type::DataRead;
        refs.push_back(xref);
    }
    
    return refs;
}

std::vector<uint64_t> XRefAnalyzer::get_immediate_operands(const ir::Instruction& insn) {
    std::vector<uint64_t> imms;
    
    // Extract immediate values from operands
    for (const auto& op : insn.operands) {
        if (op.is_immediate()) {
            imms.push_back(std::get<uint64_t>(op.data));
        }
    }
    
    return imms;
}

// ── Index Building ──────────────────────────────────────────────────────────

void XRefAnalyzer::build_indexes(XRefAnalysisResult& result) {
    result.outgoing.clear();
    result.incoming.clear();
    
    for (const auto& xref : result.xrefs) {
        result.outgoing[xref.from_address].push_back(xref);
        result.incoming[xref.to_address].push_back(xref);
    }
}

std::vector<ir::XRef> XRefAnalyzer::find_refs_to(ir::Address target, 
                                               const XRefAnalysisResult& result) {
    auto it = result.incoming.find(target);
    if (it != result.incoming.end()) {
        return it->second;
    }
    return {};
}

std::vector<ir::XRef> XRefAnalyzer::find_refs_from(ir::Address source,
                                                const XRefAnalysisResult& result) {
    auto it = result.outgoing.find(source);
    if (it != result.outgoing.end()) {
        return it->second;
    }
    return {};
}

// ── Utility Functions ───────────────────────────────────────────────────────

const char* xref_type_name(ir::XRef::Type type) {
    switch (type) {
        case ir::XRef::Type::Call: return "Call";
        case ir::XRef::Type::Jump: return "Jump";
        case ir::XRef::Type::DataRead: return "Data Read";
        case ir::XRef::Type::DataWrite: return "Data Write";
        case ir::XRef::Type::Pointer: return "Pointer";
        default: return "Unknown";
    }
}

bool is_call_xref(const ir::XRef& xref) {
    return xref.type == ir::XRef::Type::Call;
}

bool is_jump_xref(const ir::XRef& xref) {
    return xref.type == ir::XRef::Type::Jump;
}

bool is_data_xref(const ir::XRef& xref) {
    return xref.type == ir::XRef::Type::DataRead || xref.type == ir::XRef::Type::DataWrite;
}

} // namespace atlus
