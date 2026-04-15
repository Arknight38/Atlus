#include "core/ir.h"
#include <fstream>
#include <sstream>

namespace atlus::integration {

// IDA Pro database import/export
namespace ida {

// IDC script generation for applying names/comments
class IDCGenerator {
public:
    std::string generate(const ir::Binary& binary) {
        std::ostringstream oss;
        
        oss << "// Atlus-generated IDC script\n";
        oss << "// Generated for: " << binary.path() << "\n\n";
        
        // Function names
        for (const auto& fn : binary.functions()) {
            if (fn->has_name()) {
                const ir::Symbol* sym = binary.get_symbol(fn->symbol);
                if (sym) {
                    oss << "MakeName(0x" << std::hex << fn->start_address.offset 
                        << std::dec << ", \"" << escape_string(sym->name) << "\");\n";
                }
            }
        }
        
        oss << "\n// Analysis complete\n";
        return oss.str();
    }
    
private:
    std::string escape_string(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                default: result += c;
            }
        }
        return result;
    }
};

// Simple .idb/.i64 parser stub (full implementation would use IDA SDK)
class IDBParser {
public:
    struct IDBInfo {
        std::vector<std::pair<uint64_t, std::string>> names;
        std::vector<std::pair<uint64_t, std::string>> comments;
        std::vector<std::pair<uint64_t, uint64_t>> functions;
    };
    
    std::optional<IDBInfo> parse(const std::string& path) {
        // IDA database format is proprietary and complex
        // This is a stub - real implementation would need IDA SDK or reverse engineering
        return std::nullopt;
    }
    
    bool apply_to_ir(const IDBInfo& info, ir::Binary& binary) {
        // Apply names
        for (const auto& [addr, name] : info.names) {
            if (auto* sym = const_cast<ir::Symbol*>(binary.find_symbol_at({addr, ir::Address::Space::Virtual}))) {
                const_cast<ir::Symbol*>(sym)->name = name;
            } else {
                ir::Symbol new_sym;
                new_sym.name = name;
                new_sym.address = {addr, ir::Address::Space::Virtual};
                new_sym.type = ir::Symbol::Type::Unknown;
                binary.create_symbol(new_sym);
            }
        }
        
        return true;
    }
};

} // namespace ida

// x64dbg integration
namespace x64dbg {

// x64dbg database format (simple JSON-based)
class X64DbgDb {
public:
    struct Entry {
        uint64_t address;
        std::string label;
        std::string comment;
        std::string type;  // function, data, etc.
    };
    
    std::vector<Entry> entries;
    
    std::string to_json() const {
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"labels\": [\n";
        
        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& e = entries[i];
            oss << "    {\n";
            oss << "      \"address\": \"0x" << std::hex << e.address << std::dec << "\",\n";
            oss << "      \"text\": \"" << escape_json(e.label) << "\"\n";
            oss << "    }";
            if (i < entries.size() - 1) oss << ",";
            oss << "\n";
        }
        
        oss << "  ],\n";
        oss << "  \"comments\": [\n";
        
        // Comments
        bool first = true;
        for (const auto& e : entries) {
            if (e.comment.empty()) continue;
            if (!first) oss << ",\n";
            first = false;
            
            oss << "    {\n";
            oss << "      \"address\": \"0x" << std::hex << e.address << std::dec << "\",\n";
            oss << "      \"text\": \"" << escape_json(e.comment) << "\"\n";
            oss << "    }";
        }
        
        oss << "\n  ]\n";
        oss << "}\n";
        
        return oss.str();
    }
    
    bool from_json(const std::string& json) {
        // Simple parsing - full implementation would use proper JSON library
        return false;
    }
    
    static X64DbgDb from_ir(const ir::Binary& binary) {
        X64DbgDb db;
        
        for (const auto& fn : binary.functions()) {
            Entry e;
            e.address = fn->start_address.offset;
            e.type = "function";
            
            if (fn->has_name()) {
                const ir::Symbol* sym = binary.get_symbol(fn->symbol);
                if (sym) e.label = sym->name;
            }
            
            db.entries.push_back(e);
        }
        
        for (const auto& sym : binary.symbols()) {
            if (sym->type == ir::Symbol::Type::Import || 
                sym->type == ir::Symbol::Type::Export) {
                Entry e;
                e.address = sym->address.offset;
                e.label = sym->name;
                e.type = (sym->type == ir::Symbol::Type::Import) ? "import" : "export";
                db.entries.push_back(e);
            }
        }
        
        return db;
    }
    
private:
    std::string escape_json(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c;
            }
        }
        return result;
    }
};

} // namespace x64dbg

// Ghidra integration (we already have decompiler integration, this adds export/import)
namespace ghidra {

// Ghidra XML program export format
class GhidraXMLExporter {
public:
    std::string generate(const ir::Binary& binary) {
        std::ostringstream oss;
        
        oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        oss << "<PROGRAM>\n";
        
        // Image base
        oss << "  <INFO_SOURCE>\n";
        oss << "    <IMAGE_BASE value=\"0x" << std::hex << binary.image_base() 
            << std::dec << "\"/>\n";
        oss << "  </INFO_SOURCE>\n";
        
        // Functions
        oss << "  <FUNCTIONS>\n";
        for (const auto& fn : binary.functions()) {
            oss << "    <FUNCTION>\n";
            oss << "      <ADDRESS>\n";
            oss << "        <ADDR value=\"0x" << std::hex << fn->start_address.offset 
                << std::dec << "\"/>\n";
            oss << "      </ADDRESS>\n";
            
            if (fn->has_name()) {
                const ir::Symbol* sym = binary.get_symbol(fn->symbol);
                if (sym) {
                    oss << "      <SYMBOL>" << sym->name << "</SYMBOL>\n";
                }
            }
            
            oss << "    </FUNCTION>\n";
        }
        oss << "  </FUNCTIONS>\n";
        
        // Symbols
        oss << "  <SYMBOL_TABLE>\n";
        for (const auto& sym : binary.symbols()) {
            oss << "    <SYMBOL>\n";
            oss << "      <ADDRESS>\n";
            oss << "        <ADDR value=\"0x" << std::hex << sym->address.offset 
                << std::dec << "\"/>\n";
            oss << "      </ADDRESS>\n";
            oss << "      <NAME>" << sym->name << "</NAME>\n";
            oss << "    </SYMBOL>\n";
        }
        oss << "  </SYMBOL_TABLE>\n";
        
        oss << "</PROGRAM>\n";
        
        return oss.str();
    }
};

} // namespace ghidra

// JSON API for external tools
namespace json_api {

// Export analysis results as JSON
std::string export_analysis(const ir::Binary& binary) {
    std::ostringstream oss;
    
    oss << "{\n";
    oss << "  \"binary\": {\n";
    oss << "    \"path\": \"" << binary.path() << "\",\n";
    oss << "    \"image_base\": \"0x" << std::hex << binary.image_base() << std::dec << "\",\n";
    oss << "    \"is_64bit\": " << (binary.is_64bit() ? "true" : "false") << "\n";
    oss << "  },\n";
    
    oss << "  \"functions\": [\n";
    bool first = true;
    for (const auto& fn : binary.functions()) {
        if (!first) oss << ",\n";
        first = false;
        
        oss << "    {\n";
        oss << "      \"address\": \"0x" << std::hex << fn->start_address.offset << std::dec << "\",\n";
        oss << "      \"size\": " << fn->size_bytes << ",\n";
        oss << "      \"type\": \"" << (fn->has_name() ? "named" : "unnamed") << "\"\n";
        oss << "    }";
    }
    oss << "\n  ],\n";
    
    oss << "  \"symbols\": [\n";
    first = true;
    for (const auto& sym : binary.symbols()) {
        if (!first) oss << ",\n";
        first = false;
        
        oss << "    {\n";
        oss << "      \"name\": \"" << sym->name << "\",\n";
        oss << "      \"address\": \"0x" << std::hex << sym->address.offset << std::dec << "\"\n";
        oss << "    }";
    }
    oss << "\n  ]\n";
    
    oss << "}\n";
    
    return oss.str();
}

} // namespace json_api

// Plugin SDK stub
namespace plugin_sdk {

// Plugin interface
class IPlugin {
public:
    virtual ~IPlugin() = default;
    virtual const char* get_name() const = 0;
    virtual const char* get_version() const = 0;
    virtual bool initialize() = 0;
    virtual void shutdown() = 0;
    virtual void on_binary_loaded(ir::Binary& binary) = 0;
    virtual void on_analysis_complete(ir::Binary& binary) = 0;
};

// Plugin manager
class PluginManager {
public:
    void register_plugin(IPlugin* plugin) {
        plugins_.push_back(plugin);
    }
    
    void initialize_all() {
        for (auto* plugin : plugins_) {
            plugin->initialize();
        }
    }
    
    void shutdown_all() {
        for (auto* plugin : plugins_) {
            plugin->shutdown();
        }
    }
    
    void notify_binary_loaded(ir::Binary& binary) {
        for (auto* plugin : plugins_) {
            plugin->on_binary_loaded(binary);
        }
    }
    
    void notify_analysis_complete(ir::Binary& binary) {
        for (auto* plugin : plugins_) {
            plugin->on_analysis_complete(binary);
        }
    }
    
private:
    std::vector<IPlugin*> plugins_;
};

} // namespace plugin_sdk

} // namespace atlus::integration
