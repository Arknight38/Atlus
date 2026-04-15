#include "core/query.h"
#include <queue>

namespace atlus::query {

// QueryFilter implementations
bool AddressFilter::matches(const ir::Binary& binary, ir::FunctionId fn) const {
    if (!fn) return false;
    const ir::Function* func = binary.get_function(fn);
    if (!func) return false;
    
    if (range && range->start.valid() && func->start_address.offset < range->start.offset) return false;
    if (range && range->end.valid() && func->start_address.offset >= range->end.offset) return false;
    return true;
}

bool AddressFilter::matches(const ir::Binary& binary, ir::SymbolId sym) const {
    if (!sym) return false;
    const ir::Symbol* symbol = binary.get_symbol(sym);
    if (!symbol) return false;
    
    if (range && range->start.valid() && symbol->address.offset < range->start.offset) return false;
    if (range && range->end.valid() && symbol->address.offset >= range->end.offset) return false;
    return true;
}

bool SymbolFilter::matches(const ir::Binary& binary, ir::SymbolId sym) const {
    if (!sym) return false;
    const ir::Symbol* symbol = binary.get_symbol(sym);
    if (!symbol) return false;
    
    if (name_pattern && !name_pattern->empty()) {
        if (symbol->name.find(*name_pattern) == std::string::npos &&
            symbol->demangled_name.find(*name_pattern) == std::string::npos) {
            return false;
        }
    }
    
    if (dll_name) {
        if (symbol->source_dll.find(*dll_name) == std::string::npos) {
            return false;
        }
    }
    
    if (type && symbol->type != *type) {
        return false;
    }
    
    // Check type filters
    if (symbol->type == ir::Symbol::Type::Import && !include_imports) return false;
    if (symbol->type == ir::Symbol::Type::Export && !include_exports) return false;
    
    return true;
}

bool FunctionFilter::matches(const ir::Binary& binary, ir::FunctionId fn) const {
    if (!fn) return false;
    const ir::Function* func = binary.get_function(fn);
    if (!func) return false;
    
    if (name_pattern && func->get_display_name().find(*name_pattern) == std::string::npos) {
        return false;
    }
    
    if (type && func->type != *type) return false;
    
    if (min_size && func->size_bytes < *min_size) return false;
    if (max_size && func->size_bytes > *max_size) return false;
    
    if (has_xrefs_in && func->calls_in.empty() != !*has_xrefs_in) return false;
    if (has_xrefs_out && func->calls_out.empty() != !*has_xrefs_out) return false;
    
    if (is_leaf_function && (func->calls_out.empty() != *is_leaf_function)) return false;
    
    return true;
}

bool XRefFilter::matches(const ir::Binary& binary, const ir::XRef& xref) const {
    if (include_calls && xref.is_call()) return true;
    if (include_jumps && xref.is_jump()) return true;
    if (include_data && xref.is_data()) return true;
    return false;
}

// QueryBuilder implementation - using where() methods defined in header

QueryBuilder& QueryBuilder::with_address_range(ir::Address start, ir::Address end) {
    AddressFilter f;
    f.range = ir::AddressRange{ir::QualifiedAddress(start), ir::QualifiedAddress(end)};
    return where(f);
}

QueryBuilder& QueryBuilder::limit(size_t max_results) {
    limit_ = max_results;
    return *this;
}

QueryContext::QueryContext(const ir::Binary& binary, const index::GlobalIndex& index)
    : binary_(binary), index_(index) {
}

std::vector<ir::SymbolId> QueryContext::find_symbols(const QueryBuilder& builder) {
    std::vector<ir::SymbolId> results;
    
    // Get candidate set from index
    bool has_name_filter = false;
    for (const auto& filter : builder.filters_) {
        if (std::holds_alternative<SymbolFilter>(filter)) {
            const auto& sf = std::get<SymbolFilter>(filter);
            if (!sf.name_pattern.empty()) {
                has_name_filter = true;
                results = index_.find_symbols_by_substring(sf.name_pattern);
                break;
            }
        }
    }
    
    // If no name filter, get all symbols
    if (!has_name_filter) {
        for (const auto& sym : binary_.symbols()) {
            results.push_back(sym->id);
        }
    }
    
    // Apply filters
    std::vector<ir::SymbolId> filtered;
    for (auto sym_id : results) {
        bool matches = true;
        for (const auto& filter : builder.filters_) {
            if (std::holds_alternative<AddressFilter>(filter)) {
                if (!std::get<AddressFilter>(filter).matches(binary_, sym_id)) {
                    matches = false;
                    break;
                }
            } else if (std::holds_alternative<SymbolFilter>(filter)) {
                if (!std::get<SymbolFilter>(filter).matches(binary_, sym_id)) {
                    matches = false;
                    break;
                }
            }
        }
        if (matches) {
            filtered.push_back(sym_id);
            if (filtered.size() >= builder.limit_) break;
        }
    }
    
    return filtered;
}

std::vector<ir::FunctionId> QueryContext::find_functions(const QueryBuilder& builder) {
    std::vector<ir::FunctionId> results;
    
    // Get all functions
    for (const auto& fn : binary_.functions()) {
        results.push_back(fn->id);
    }
    
    // Apply filters
    std::vector<ir::FunctionId> filtered;
    for (auto fn_id : results) {
        bool matches = true;
        for (const auto& filter : builder.filters_) {
            if (std::holds_alternative<AddressFilter>(filter)) {
                if (!std::get<AddressFilter>(filter).matches(binary_, fn_id)) {
                    matches = false;
                    break;
                }
            } else if (std::holds_alternative<FunctionFilter>(filter)) {
                if (!std::get<FunctionFilter>(filter).matches(binary_, fn_id)) {
                    matches = false;
                    break;
                }
            }
        }
        if (matches) {
            filtered.push_back(fn_id);
            if (filtered.size() >= builder.limit_) break;
        }
    }
    
    return filtered;
}

std::vector<ir::FunctionId> QueryContext::find_callers(ir::FunctionId target) {
    std::vector<ir::FunctionId> results;
    
    const ir::Function* fn = binary_.get_function(target);
    if (!fn) return results;
    
    for (const auto& xref : fn->calls_in) {
        // Find the calling function
        for (const auto& caller_fn : binary_.functions()) {
            for (const auto& out_xref : caller_fn->calls_out) {
                if (out_xref.to_address.offset == fn->start_address.offset) {
                    results.push_back(caller_fn->id);
                    break;
                }
            }
        }
    }
    
    // Remove duplicates
    std::sort(results.begin(), results.end());
    results.erase(std::unique(results.begin(), results.end()), results.end());
    
    return results;
}

std::vector<ir::FunctionId> QueryContext::find_callees(ir::FunctionId source) {
    std::vector<ir::FunctionId> results;
    
    const ir::Function* fn = binary_.get_function(source);
    if (!fn) return results;
    
    for (const auto& xref : fn->calls_out) {
        if (std::holds_alternative<ir::FunctionId>(xref.target)) {
            results.push_back(std::get<ir::FunctionId>(xref.target));
        }
    }
    
    return results;
}

std::optional<ir::FunctionId> QueryContext::function_containing(ir::Address addr) {
    return index_.find_function_at(addr);
}

std::optional<ir::BasicBlockId> QueryContext::block_containing(ir::Address addr) {
    auto fn_id = index_.find_function_at(addr);
    if (!fn_id) return std::nullopt;
    
    const ir::Function* fn = binary_.get_function(*fn_id);
    if (!fn) return std::nullopt;
    
    for (auto bb_id : fn->basic_blocks) {
        const ir::BasicBlock* bb = binary_.get_basic_block(bb_id);
        if (bb && addr.offset >= bb->start_address.offset && 
            addr.offset < bb->end_address.offset) {
            return bb_id;
        }
    }
    
    return std::nullopt;
}

std::optional<ir::InstructionId> QueryContext::instruction_at(ir::Address addr) {
    return index_.find_instruction_at(addr);
}

// Predefined queries
PredefinedQueries::PredefinedQueries(QueryContext& ctx) : ctx_(ctx) {}

std::vector<ir::FunctionId> PredefinedQueries::find_entry_points() {
    // Entry points have no incoming xrefs
    std::vector<ir::FunctionId> results;
    
    for (const auto& fn : ctx_.binary().functions()) {
        if (fn->calls_in.empty()) {
            results.push_back(fn->id);
        }
    }
    
    return results;
}

std::vector<ir::FunctionId> PredefinedQueries::find_leaf_functions() {
    // Leaf functions have no outgoing calls
    std::vector<ir::FunctionId> results;
    
    for (const auto& fn : ctx_.binary().functions()) {
        if (fn->calls_out.empty()) {
            results.push_back(fn->id);
        }
    }
    
    return results;
}

std::vector<ir::FunctionId> PredefinedQueries::find_recursive_functions() {
    // Functions that call themselves
    std::vector<ir::FunctionId> results;
    
    for (const auto& fn : ctx_.binary().functions()) {
        for (const auto& xref : fn->calls_out) {
            if (std::holds_alternative<ir::FunctionId>(xref.target)) {
                if (std::get<ir::FunctionId>(xref.target) == fn->id) {
                    results.push_back(fn->id);
                    break;
                }
            }
        }
    }
    
    return results;
}

std::vector<ir::FunctionId> PredefinedQueries::find_api_functions(const std::vector<std::string>& dll_names) {
    // Functions that call imported APIs
    std::vector<ir::FunctionId> results;
    
    for (const auto& fn : ctx_.binary().functions()) {
        for (const auto& xref : fn->calls_out) {
            if (std::holds_alternative<ir::SymbolId>(xref.target)) {
                ir::SymbolId sym_id = std::get<ir::SymbolId>(xref.target);
                const ir::Symbol* sym = ctx_.binary().get_symbol(sym_id);
                if (sym && sym->type == ir::Symbol::Type::Import) {
                    if (dll_names.empty() || 
                        std::find(dll_names.begin(), dll_names.end(), sym->source_dll) != dll_names.end()) {
                        results.push_back(fn->id);
                        break;
                    }
                }
            }
        }
    }
    
    return results;
}

std::vector<ir::SymbolId> PredefinedQueries::find_imported_apis(const std::string& dll_pattern) {
    std::vector<ir::SymbolId> results;
    
    for (const auto& sym : ctx_.binary().symbols()) {
        if (sym->type == ir::Symbol::Type::Import) {
            if (dll_pattern.empty() || sym->source_dll.find(dll_pattern) != std::string::npos) {
                results.push_back(sym->id);
            }
        }
    }
    
    return results;
}

std::vector<ir::SymbolId> PredefinedQueries::find_string_references(const std::string& pattern) {
    return ctx_.index().find_strings_by_content(pattern);
}

} // namespace atlus::query
