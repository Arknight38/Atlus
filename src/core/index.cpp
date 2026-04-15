#include "core/index.h"
#include <algorithm>
#include <map>
#include <unordered_set>

namespace atlus::index {

// GlobalIndex implementation
struct GlobalIndex::Impl {
    // Index storage
    std::unordered_map<std::string, std::vector<ir::SymbolId>> symbol_by_name;
    std::unordered_map<std::string, std::vector<ir::SymbolId>> symbol_by_prefix;
    std::map<uint64_t, ir::SymbolId> symbol_by_address;
    std::map<uint64_t, ir::FunctionId> function_by_address;
    std::map<uint64_t, ir::InstructionId> instruction_by_address;
    std::unordered_map<uint64_t, std::vector<ir::XRef>> xrefs_incoming;
    std::unordered_map<uint64_t, std::vector<ir::XRef>> xrefs_outgoing;
    
    // String literals
    std::unordered_map<std::string, std::vector<ir::SymbolId>> string_by_content;
    
    // Track which indexes are built
    std::unordered_set<IndexType> built_indexes;
};

GlobalIndex::GlobalIndex() : impl_(std::make_unique<Impl>()) {}
GlobalIndex::~GlobalIndex() = default;

void GlobalIndex::build(const ir::Binary& binary) {
    clear();
    
    // Build all indexes
    for (uint32_t i = 0; i < static_cast<uint32_t>(IndexType::Count); ++i) {
        build_index(static_cast<IndexType>(i), binary);
    }
}

void GlobalIndex::build_index(IndexType type, const ir::Binary& binary) {
    switch (type) {
        case IndexType::SymbolByName:
        case IndexType::SymbolByAddress:
            for (const auto& sym : binary.symbols()) {
                if (!sym->name.empty()) {
                    impl_->symbol_by_name[sym->name].push_back(sym->id);
                    // Build prefix index
                    for (size_t i = 1; i <= sym->name.size(); ++i) {
                        impl_->symbol_by_prefix[sym->name.substr(0, i)].push_back(sym->id);
                    }
                }
                impl_->symbol_by_address[sym->address.offset] = sym->id;
            }
            break;
            
        case IndexType::FunctionByAddress:
            for (const auto& fn : binary.functions()) {
                impl_->function_by_address[fn->start_address.offset] = fn->id;
            }
            break;
            
        case IndexType::InstructionByAddress:
            for (const auto& fn : binary.functions()) {
                for (const auto& bb_id : fn->basic_blocks) {
                    const ir::BasicBlock* bb = binary.get_basic_block(bb_id);
                    if (!bb) continue;
                    for (const auto& insn : bb->instructions) {
                        const ir::Instruction* i = binary.get_instruction(insn);
                        if (i) {
                            impl_->instruction_by_address[i->address.offset] = insn;
                        }
                    }
                }
            }
            break;
            
        case IndexType::XRefIncoming:
        case IndexType::XRefOutgoing:
            // XRefs are built as they're added to binary
            for (const auto& fn : binary.functions()) {
                for (const auto& xref : fn->calls_in) {
                    impl_->xrefs_incoming[xref.to_address.offset].push_back(xref);
                    impl_->xrefs_outgoing[xref.from_address.offset].push_back(xref);
                }
                for (const auto& xref : fn->calls_out) {
                    impl_->xrefs_incoming[xref.to_address.offset].push_back(xref);
                    impl_->xrefs_outgoing[xref.from_address.offset].push_back(xref);
                }
            }
            break;
            
        case IndexType::StringLiteral:
            for (const auto& sym : binary.symbols()) {
                if (sym->type == ir::Symbol::Type::String && !sym->name.empty()) {
                    impl_->string_by_content[sym->name].push_back(sym->id);
                }
            }
            break;
            
        default:
            break;
    }
    
    impl_->built_indexes.insert(type);
}

void GlobalIndex::clear() {
    impl_->symbol_by_name.clear();
    impl_->symbol_by_prefix.clear();
    impl_->symbol_by_address.clear();
    impl_->function_by_address.clear();
    impl_->instruction_by_address.clear();
    impl_->xrefs_incoming.clear();
    impl_->xrefs_outgoing.clear();
    impl_->string_by_content.clear();
    impl_->built_indexes.clear();
}

void GlobalIndex::clear_index(IndexType type) {
    impl_->built_indexes.erase(type);
    // Note: Actual data clearing would require separate storage per index
}

std::vector<SearchResult> GlobalIndex::search(const SearchQuery& query) const {
    std::vector<SearchResult> results;
    
    switch (query.type) {
        case SearchQuery::Type::Exact: {
            auto symbols = find_symbols_by_name(query.text);
            for (auto id : symbols) {
                SearchResult r;
                r.entity_type = SearchResult::EntityType::Symbol;
                r.id.symbol = id;
                r.relevance = 1.0f;
                results.push_back(r);
            }
            break;
        }
        
        case SearchQuery::Type::Prefix: {
            auto symbols = find_symbols_by_prefix(query.text);
            for (auto id : symbols) {
                SearchResult r;
                r.entity_type = SearchResult::EntityType::Symbol;
                r.id.symbol = id;
                r.relevance = 0.9f;
                results.push_back(r);
            }
            break;
        }
        
        case SearchQuery::Type::Substring: {
            auto symbols = find_symbols_by_substring(query.text);
            for (auto id : symbols) {
                SearchResult r;
                r.entity_type = SearchResult::EntityType::Symbol;
                r.id.symbol = id;
                r.relevance = 0.7f;
                results.push_back(r);
            }
            break;
        }
        
        default:
            break;
    }
    
    // Limit results
    if (results.size() > query.max_results) {
        results.resize(query.max_results);
    }
    
    return results;
}

std::vector<ir::SymbolId> GlobalIndex::find_symbols_by_name(const std::string& name) const {
    auto it = impl_->symbol_by_name.find(name);
    if (it == impl_->symbol_by_name.end()) return {};
    return it->second;
}

std::vector<ir::SymbolId> GlobalIndex::find_symbols_by_prefix(const std::string& prefix) const {
    auto it = impl_->symbol_by_prefix.find(prefix);
    if (it == impl_->symbol_by_prefix.end()) return {};
    return it->second;
}

std::vector<ir::SymbolId> GlobalIndex::find_symbols_by_substring(const std::string& pattern) const {
    std::vector<ir::SymbolId> results;
    
    for (const auto& [name, ids] : impl_->symbol_by_name) {
        if (name.find(pattern) != std::string::npos) {
            results.insert(results.end(), ids.begin(), ids.end());
        }
    }
    
    return results;
}

std::optional<ir::SymbolId> GlobalIndex::find_symbol_at(ir::Address addr) const {
    auto it = impl_->symbol_by_address.find(addr.offset);
    if (it == impl_->symbol_by_address.end()) return std::nullopt;
    return it->second;
}

std::optional<ir::FunctionId> GlobalIndex::find_function_at(ir::Address addr) const {
    auto it = impl_->function_by_address.find(addr.offset);
    if (it == impl_->function_by_address.end()) return std::nullopt;
    return it->second;
}

std::optional<ir::InstructionId> GlobalIndex::find_instruction_at(ir::Address addr) const {
    auto it = impl_->instruction_by_address.find(addr.offset);
    if (it == impl_->instruction_by_address.end()) return std::nullopt;
    return it->second;
}

std::vector<ir::SymbolId> GlobalIndex::find_strings_by_content(const std::string& content) const {
    auto it = impl_->string_by_content.find(content);
    if (it == impl_->string_by_content.end()) return {};
    return it->second;
}

std::vector<ir::XRef> GlobalIndex::find_xrefs_to(ir::Address addr) const {
    auto it = impl_->xrefs_incoming.find(addr.offset);
    if (it == impl_->xrefs_incoming.end()) return {};
    return it->second;
}

std::vector<ir::XRef> GlobalIndex::find_xrefs_from(ir::Address addr) const {
    auto it = impl_->xrefs_outgoing.find(addr.offset);
    if (it == impl_->xrefs_outgoing.end()) return {};
    return it->second;
}

std::vector<ir::XRef> GlobalIndex::find_xrefs_to_function(ir::FunctionId fn) const {
    // Would need access to binary to get function address, then lookup
    return {};
}

std::optional<ir::Address> GlobalIndex::get_next_symbol(ir::Address current) const {
    auto it = impl_->symbol_by_address.upper_bound(current.offset);
    if (it == impl_->symbol_by_address.end()) return std::nullopt;
    return ir::Address::virtual_addr(it->first);
}

std::optional<ir::Address> GlobalIndex::get_prev_symbol(ir::Address current) const {
    auto it = impl_->symbol_by_address.lower_bound(current.offset);
    if (it == impl_->symbol_by_address.begin()) return std::nullopt;
    --it;
    return ir::Address::virtual_addr(it->first);
}

std::optional<ir::Address> GlobalIndex::get_next_function(ir::Address current) const {
    auto it = impl_->function_by_address.upper_bound(current.offset);
    if (it == impl_->function_by_address.end()) return std::nullopt;
    return ir::Address::virtual_addr(it->first);
}

std::optional<ir::Address> GlobalIndex::get_prev_function(ir::Address current) const {
    auto it = impl_->function_by_address.lower_bound(current.offset);
    if (it == impl_->function_by_address.begin()) return std::nullopt;
    --it;
    return ir::Address::virtual_addr(it->first);
}

size_t GlobalIndex::index_size(IndexType type) const {
    switch (type) {
        case IndexType::SymbolByName: return impl_->symbol_by_name.size();
        case IndexType::SymbolByAddress: return impl_->symbol_by_address.size();
        case IndexType::FunctionByAddress: return impl_->function_by_address.size();
        case IndexType::InstructionByAddress: return impl_->instruction_by_address.size();
        case IndexType::XRefIncoming: return impl_->xrefs_incoming.size();
        case IndexType::XRefOutgoing: return impl_->xrefs_outgoing.size();
        case IndexType::StringLiteral: return impl_->string_by_content.size();
        default: return 0;
    }
}

bool GlobalIndex::has_index(IndexType type) const {
    return impl_->built_indexes.count(type) > 0;
}

// PersistentIndex stub implementation
struct PersistentIndex::Impl {
    std::string db_path;
    bool is_open = false;
};

PersistentIndex::PersistentIndex() : impl_(std::make_unique<Impl>()) {}
PersistentIndex::~PersistentIndex() = default;

bool PersistentIndex::open(const std::string& db_path) {
    impl_->db_path = db_path;
    impl_->is_open = true;
    return true;
}

void PersistentIndex::close() {
    impl_->is_open = false;
}

bool PersistentIndex::is_open() const {
    return impl_->is_open;
}

void PersistentIndex::build_from(const ir::Binary& binary) {
    // Stub - would build SQLite database
}

std::vector<SearchResult> PersistentIndex::search(const SearchQuery& query) const {
    return {};
}

std::vector<ir::SymbolId> PersistentIndex::find_symbols_by_name(const std::string& name) const {
    return {};
}

std::optional<ir::SymbolId> PersistentIndex::find_symbol_at(ir::Address addr) const {
    return std::nullopt;
}

std::vector<ir::XRef> PersistentIndex::find_xrefs_to(ir::Address addr) const {
    return {};
}

void PersistentIndex::begin_transaction() {}
void PersistentIndex::commit_transaction() {}
void PersistentIndex::rollback() {}

// Advanced search
std::vector<SearchResult> advanced_search(
    const GlobalIndex& index,
    const AdvancedSearch& criteria
) {
    std::vector<SearchResult> results;
    
    // Build query from criteria
    if (criteria.name_pattern.has_value()) {
        SearchQuery query;
        query.text = criteria.name_pattern.value();
        query.type = SearchQuery::Type::Substring;
        results = index.search(query);
    }
    
    // TODO: Apply other filters (address range, symbol type, etc.)
    
    return results;
}

} // namespace atlus::index
