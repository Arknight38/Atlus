#include "core/ir.h"
#include "core/address_space.h"
#include <unordered_set>

namespace atlus::analysis {

// Cross-reference analyzer
class XRefAnalyzer {
public:
    void analyze_function(ir::Function& fn, ir::Binary& binary) {
        fn.calls_in.clear();
        fn.calls_out.clear();
        
        for (ir::BasicBlockId bb_id : fn.basic_blocks) {
            const ir::BasicBlock* bb = binary.get_basic_block(bb_id);
            if (!bb) continue;
            
            for (ir::InstructionId insn_id : bb->instructions) {
                const ir::Instruction* insn = binary.get_instruction(insn_id);
                if (!insn) continue;
                
                // Check for cross-references in operands
                for (const auto& operand : insn->operands) {
                    if (operand.is_address()) {
                        const ir::Address& addr = std::get<ir::Address>(operand.data);
                        
                        ir::XRef xref;
                        xref.from_address = insn->address;
                        xref.from_instruction = insn_id;
                        xref.to_address = {addr.offset, ir::Address::Space::Virtual};
                        
                        if (insn->is_call) {
                            xref.type = ir::XRef::Type::Call;
                            
                            // Find target function
                            const ir::Function* target = binary.find_function_at(xref.to_address);
                            if (target) {
                                xref.target = target->id;
                                fn.calls_out.push_back(xref);
                                
                                // Add to target's incoming calls
                                ir::XRef incoming = xref;
                                const_cast<ir::Function*>(target)->calls_in.push_back(incoming);
                            }
                        } else if (insn->is_branch) {
                            xref.type = ir::XRef::Type::Jump;
                        } else {
                            xref.type = ir::XRef::Type::DataRead;
                        }
                    }
                }
            }
        }
    }
    
    void analyze_data_refs(ir::Binary& binary) {
        // Find data references from code to data sections
        for (const auto& fn : binary.functions()) {
            for (ir::BasicBlockId bb_id : fn->basic_blocks) {
                const ir::BasicBlock* bb = binary.get_basic_block(bb_id);
                if (!bb) continue;
                
                for (ir::InstructionId insn_id : bb->instructions) {
                    const ir::Instruction* insn = binary.get_instruction(insn_id);
                    if (!insn) continue;
                    
                    // Look for memory operands that reference data
                    for (const auto& operand : insn->operands) {
                        if (operand.type == ir::Operand::Type::Memory) {
                            // Check if displacement points to data section
                            auto& mem = std::get<3>(operand.data);
                            
                            ir::Address data_addr{static_cast<uint64_t>(mem.displacement), 
                                                   ir::Address::Space::Virtual};
                            
                            const ir::Section* sec = binary.find_section_at(data_addr);
                            if (sec && !sec->is_executable) {
                                // Data reference
                                ir::XRef xref;
                                xref.type = ir::XRef::Type::DataRead;
                                xref.from_address = insn->address;
                                xref.from_instruction = insn_id;
                                xref.to_address = data_addr;
                                
                                // Check if there's a symbol at this address
                                const ir::Symbol* sym = binary.find_symbol_at(data_addr);
                                if (sym) {
                                    xref.target = sym->id;
                                }
                                
                                binary.register_xref(xref);
                            }
                        }
                    }
                }
            }
        }
    }
};

// String finder
class StringFinder {
public:
    struct StringMatch {
        uint64_t address;
        std::string content;
        bool is_unicode;
        size_t length;
    };
    
    std::vector<StringMatch> find_strings(const BinaryFile& file, 
                                          const ir::Binary& binary,
                                          size_t min_length = 4) {
        std::vector<StringMatch> results;
        
        const uint8_t* data = file.bytes();
        size_t size = file.size();
        
        // Scan each section for strings
        for (const auto& sec : binary.sections()) {
            if (sec->is_executable) continue;  // Skip code sections
            
            uint64_t file_off = sec->file_offset.offset;
            uint64_t sec_size = sec->raw_size;
            
            if (file_off + sec_size > size) continue;
            
            // Scan for ASCII strings
            scan_ascii(data + file_off, sec_size, file_off, 
                      sec->virtual_addr.offset, min_length, results);
            
            // Scan for Unicode strings
            scan_unicode(data + file_off, sec_size, file_off,
                        sec->virtual_addr.offset, min_length, results);
        }
        
        return results;
    }
    
private:
    void scan_ascii(const uint8_t* data, size_t size,
                   uint64_t file_offset, uint64_t virtual_base,
                   size_t min_length, std::vector<StringMatch>& results) {
        size_t i = 0;
        while (i < size) {
            // Find start of printable string
            if (is_printable_ascii(data[i])) {
                size_t start = i;
                while (i < size && is_printable_ascii(data[i])) {
                    ++i;
                }
                
                size_t len = i - start;
                if (len >= min_length) {
                    StringMatch match;
                    match.address = virtual_base + (file_offset + start - file_offset);
                    match.content = std::string(reinterpret_cast<const char*>(data + start), len);
                    match.is_unicode = false;
                    match.length = len;
                    results.push_back(match);
                }
            } else {
                ++i;
            }
        }
    }
    
    void scan_unicode(const uint8_t* data, size_t size,
                     uint64_t file_offset, uint64_t virtual_base,
                     size_t min_length, std::vector<StringMatch>& results) {
        size_t i = 0;
        while (i + 1 < size) {
            // UTF-16LE: printable ASCII followed by null byte
            if (is_printable_ascii(data[i]) && data[i + 1] == 0) {
                size_t start = i;
                std::string content;
                
                while (i + 1 < size && is_printable_ascii(data[i]) && data[i + 1] == 0) {
                    content += static_cast<char>(data[i]);
                    i += 2;
                }
                
                if (content.length() >= min_length) {
                    StringMatch match;
                    match.address = virtual_base + (file_offset + start - file_offset);
                    match.content = content;
                    match.is_unicode = true;
                    match.length = content.length();
                    results.push_back(match);
                }
            } else {
                i += 2;
            }
        }
    }
    
    bool is_printable_ascii(uint8_t c) {
        return c >= 0x20 && c < 0x7F;
    }
};

// Switch table recovery
class SwitchTableRecovery {
public:
    struct SwitchTable {
        uint64_t base_address;
        std::vector<uint64_t> targets;
        size_t entry_size;  // 4 or 8 bytes
    };
    
    std::optional<SwitchTable> recover(
        ir::InstructionId jmp_insn_id,
        const ir::Binary& binary,
        const BinaryFile& file
    ) {
        const ir::Instruction* insn = binary.get_instruction(jmp_insn_id);
        if (!insn || insn->mnemonic != "jmp") return std::nullopt;
        
        // Look for jmp [reg*scale+displacement] pattern
        // This indicates a jump table
        for (const auto& operand : insn->operands) {
            if (operand.type == ir::Operand::Type::Memory) {
                auto& mem = std::get<3>(operand.data);
                
                if (mem.base_reg != 0 || mem.index_reg != 0) {
                    // Potential jump table - need to find base and bounds
                    SwitchTable table;
                    table.base_address = static_cast<uint64_t>(mem.displacement);
                    table.entry_size = binary.is_64bit() ? 8 : 4;
                    
                    // Scan for consecutive valid targets
                    scan_table_entries(table, binary, file);
                    
                    if (!table.targets.empty()) {
                        return table;
                    }
                }
            }
        }
        
        return std::nullopt;
    }
    
private:
    void scan_table_entries(SwitchTable& table, const ir::Binary& binary,
                           const BinaryFile& file) {
        // Read entries from file
        auto file_addr = binary.virtual_to_file({table.base_address, ir::Address::Space::Virtual});
        if (!file_addr.has_value()) return;
        
        size_t max_entries = 256;  // Safety limit
        
        for (size_t i = 0; i < max_entries; ++i) {
            uint64_t entry_addr = file_addr->offset + i * table.entry_size;
            if (entry_addr + table.entry_size > file.size()) break;
            
            uint64_t target;
            if (table.entry_size == 8) {
                target = *reinterpret_cast<const uint64_t*>(file.bytes() + entry_addr);
            } else {
                target = *reinterpret_cast<const uint32_t*>(file.bytes() + entry_addr);
                if (binary.is_64bit()) {
                    // Sign extend for 32-bit RVA in 64-bit binary
                    target = table.base_address + (target - table.base_address);
                }
            }
            
            // Validate target is in code section
            const ir::Section* sec = binary.find_section_at({target, ir::Address::Space::Virtual});
            if (sec && sec->is_executable) {
                table.targets.push_back(target);
            } else {
                // Invalid target - assume end of table
                break;
            }
        }
    }
};

// Public API
void analyze_xrefs(ir::Function& fn, ir::Binary& binary) {
    XRefAnalyzer analyzer;
    analyzer.analyze_function(fn, binary);
}

void analyze_all_xrefs(ir::Binary& binary) {
    XRefAnalyzer analyzer;
    analyzer.analyze_data_refs(binary);
}

std::vector<std::string> find_strings(const BinaryFile& file,
                                      const ir::Binary& binary,
                                      size_t min_length) {
    StringFinder finder;
    auto matches = finder.find_strings(file, binary, min_length);
    
    std::vector<std::string> results;
    for (const auto& match : matches) {
        results.push_back(match.content);
    }
    
    return results;
}

void register_string_symbols(const BinaryFile& file,
                             ir::Binary& binary,
                             size_t min_length) {
    StringFinder finder;
    auto matches = finder.find_strings(file, binary, min_length);
    
    for (const auto& match : matches) {
        // Check if symbol already exists
        if (binary.find_symbol_at({match.address, ir::Address::Space::Virtual})) {
            continue;
        }
        
        // Create symbol for string
        ir::Symbol sym;
        sym.name = "str_" + std::to_string(match.address);
        sym.address = {match.address, ir::Address::Space::Virtual};
        sym.type = ir::Symbol::Type::String;
        
        binary.create_symbol(sym);
    }
}

} // namespace atlus::analysis
