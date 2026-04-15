#include "core/ir.h"
#include <algorithm>
#include <cstring>

namespace atlus::ir {

// Binary implementation
Binary::Binary(std::string path, uint64_t image_base, bool is_64bit)
    : id_(static_cast<BinaryId>(1))
    , path_(std::move(path))
    , image_base_(image_base)
    , is_64bit_(is_64bit) {
}

// Entity access by ID
const Section* Binary::get_section(SectionId id) const {
    uint32_t idx = static_cast<uint32_t>(id);
    if (idx >= sections_.size()) return nullptr;
    return sections_[idx].get();
}

const Function* Binary::get_function(FunctionId id) const {
    uint32_t idx = static_cast<uint32_t>(id);
    if (idx >= functions_.size()) return nullptr;
    return functions_[idx].get();
}

const BasicBlock* Binary::get_basic_block(BasicBlockId id) const {
    uint32_t idx = static_cast<uint32_t>(id);
    if (idx >= basic_blocks_.size()) return nullptr;
    return basic_blocks_[idx].get();
}

const Instruction* Binary::get_instruction(InstructionId id) const {
    uint32_t idx = static_cast<uint32_t>(id);
    if (idx >= instructions_.size()) return nullptr;
    return instructions_[idx].get();
}

const Symbol* Binary::get_symbol(SymbolId id) const {
    uint32_t idx = static_cast<uint32_t>(id);
    if (idx >= symbols_.size()) return nullptr;
    return symbols_[idx].get();
}

const TypeInfo* Binary::get_type(TypeId id) const {
    uint32_t idx = static_cast<uint32_t>(id);
    if (idx >= types_.size()) return nullptr;
    return types_[idx].get();
}

// Lookup by address
const Section* Binary::find_section_at(Address addr) const {
    auto it = section_by_rva_.find(addr.value);
    if (it == section_by_rva_.end()) return nullptr;
    return get_section(it->second);
}

const Function* Binary::find_function_at(Address addr) const {
    auto it = function_by_va_.find(addr.value);
    if (it == function_by_va_.end()) return nullptr;
    return get_function(it->second);
}

const Symbol* Binary::find_symbol_at(Address addr) const {
    auto it = symbol_by_va_.find(addr.value);
    if (it == symbol_by_va_.end()) return nullptr;
    return get_symbol(it->second);
}

std::vector<const XRef*> Binary::find_xrefs_to(Address addr) const {
    std::vector<const XRef*> result;
    auto it = xrefs_to_.find(addr.value);
    if (it != xrefs_to_.end()) {
        for (const auto& xref : it->second) {
            result.push_back(const_cast<XRef*>(&xref));
        }
    }
    return result;
}

std::vector<const XRef*> Binary::find_xrefs_from(Address addr) const {
    std::vector<const XRef*> result;
    auto it = xrefs_from_.find(addr.value);
    if (it != xrefs_from_.end()) {
        for (const auto& xref : it->second) {
            result.push_back(const_cast<XRef*>(&xref));
        }
    }
    return result;
}

// Global search
std::vector<const Symbol*> Binary::find_symbols_by_name(const std::string& pattern) const {
    std::vector<const Symbol*> result;
    
    // Simple substring search - could be optimized with trie/index
    for (const auto& sym : symbols_) {
        if (sym->name.find(pattern) != std::string::npos ||
            sym->demangled_name.find(pattern) != std::string::npos) {
            result.push_back(sym.get());
        }
    }
    
    return result;
}

std::vector<const Function*> Binary::find_functions_by_name(const std::string& pattern) const {
    std::vector<const Function*> result;
    
    // Search via symbols
    for (const auto& sym : symbols_) {
        if (sym->type == Symbol::Type::Function) {
            if (sym->name.find(pattern) != std::string::npos ||
                sym->demangled_name.find(pattern) != std::string::npos) {
                if (auto* fn = get_function(sym->type)) {
                    result.push_back(fn);
                }
            }
        }
    }
    
    return result;
}

// Entity creation
SectionId Binary::create_section(const Section& sec) {
    auto new_sec = std::make_unique<Section>(sec);
    SectionId id = static_cast<SectionId>(next_section_id_++);
    new_sec->id = id;
    
    // Update index
    section_by_rva_[new_sec->rva.offset] = id;
    
    sections_.push_back(std::move(new_sec));
    return id;
}

FunctionId Binary::create_function(const Function& fn) {
    auto new_fn = std::make_unique<Function>(fn);
    FunctionId id = static_cast<FunctionId>(next_function_id_++);
    new_fn->id = id;
    
    // Update index
    function_by_va_[new_fn->start_address.offset] = id;
    
    functions_.push_back(std::move(new_fn));
    return id;
}

BasicBlockId Binary::create_basic_block(const BasicBlock& bb) {
    auto new_bb = std::make_unique<BasicBlock>(bb);
    BasicBlockId id = static_cast<BasicBlockId>(next_bb_id_++);
    new_bb->id = id;
    
    basic_blocks_.push_back(std::move(new_bb));
    return id;
}

InstructionId Binary::create_instruction(const Instruction& insn) {
    auto new_insn = std::make_unique<Instruction>(insn);
    InstructionId id = static_cast<InstructionId>(next_insn_id_++);
    new_insn->id = id;
    
    instructions_.push_back(std::move(new_insn));
    return id;
}

SymbolId Binary::create_symbol(const Symbol& sym) {
    auto new_sym = std::make_unique<Symbol>(sym);
    SymbolId id = static_cast<SymbolId>(next_symbol_id_++);
    new_sym->id = id;
    
    // Update indexes
    symbol_by_va_[new_sym->address.offset] = id;
    if (!new_sym->name.empty()) {
        symbol_by_name_[new_sym->name] = id;
    }
    
    symbols_.push_back(std::move(new_sym));
    return id;
}

TypeId Binary::create_type(const TypeInfo& type) {
    auto new_type = std::make_unique<TypeInfo>(type);
    TypeId id = static_cast<TypeId>(next_type_id_++);
    new_type->id = id;
    
    types_.push_back(std::move(new_type));
    return id;
}

// Cross-reference registration
void Binary::register_xref(const XRef& xref) {
    xrefs_to_[xref.to_address.offset].push_back(xref);
    xrefs_from_[xref.from_address.offset].push_back(xref);
}

// Address conversion utilities
std::optional<Address> Binary::file_to_virtual(Address file_offset) const {
    // Find section containing this file offset
    for (const auto& sec : sections_) {
        if (file_offset.offset >= sec->file_offset.offset &&
            file_offset.offset < sec->file_offset.offset + sec->raw_size) {
            uint64_t section_offset = file_offset.offset - sec->file_offset.offset;
            return Address::virtual_addr(image_base_ + sec->rva.offset + section_offset);
        }
    }
    return std::nullopt;
}

std::optional<Address> Binary::virtual_to_file(Address va) const {
    // Convert VA to RVA first
    if (va.offset < image_base_) return std::nullopt;
    uint64_t rva = va.offset - image_base_;
    
    // Find section containing this RVA
    for (const auto& sec : sections_) {
        if (rva >= sec->rva.offset && rva < sec->rva.offset + sec->raw_size) {
            uint64_t section_offset = rva - sec->rva.offset;
            return Address::file_offset(sec->file_offset.offset + section_offset);
        }
    }
    return std::nullopt;
}

std::optional<Address> Binary::rva_to_virtual(Address rva) const {
    return Address::virtual_addr(image_base_ + rva.offset);
}

// Function helper methods
bool Function::has_name() const {
    return symbol != SymbolId::Invalid;
}

std::string Function::get_display_name() const {
    // This requires access to the Binary to look up the symbol
    // For now, return a placeholder
    return "func_" + std::to_string(static_cast<uint32_t>(id));
}

} // namespace atlus::ir
