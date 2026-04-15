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

QueryContext::QueryContext(const ir::Binary& binary)
    : binary_(binary) {
}

void QueryContext::set_index(const index::GlobalIndex& index) {
    index_ = &index;
}

std::vector<QueryResult> QueryContext::execute(const QueryBuilder& builder) {
    // Delegate to builder's execute method
    if (index_) {
        return builder.execute(binary_, *index_);
    }
    return builder.execute(binary_);
}

} // namespace atlus::query
