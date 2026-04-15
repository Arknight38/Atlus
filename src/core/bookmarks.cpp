#include "core/ir.h"
#include "core/ir_identity.h"
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <chrono>

namespace atlus::annotations {

// Types of user annotations
enum class AnnotationType {
    Bookmark,       // Quick navigation marker
    Comment,        // Text comment at address
    Label,          // Custom name for address
    TypeInfo,       // Type annotation for data
    FunctionBoundary, // User-defined function start/end
    Color           // Highlight color
};

// Single annotation entry
struct Annotation {
    uint64_t id = 0;
    uint64_t address = 0;
    AnnotationType type = AnnotationType::Comment;
    std::string text;
    uint32_t color = 0xFFFFFF;  // RGB for color annotations
    uint64_t timestamp = 0;      // When created
    bool is_persistent = true;   // Save to session file
};

// Annotation database for a binary
class AnnotationDatabase {
public:
    // Add bookmark at address
    uint64_t add_bookmark(uint64_t address, const std::string& name = "");
    
    // Add comment at address
    uint64_t add_comment(uint64_t address, const std::string& text);
    
    // Set custom label
    uint64_t set_label(uint64_t address, const std::string& name);
    
    // Set type info for address
    uint64_t set_type(uint64_t address, const std::string& type_name);
    
    // Set highlight color
    uint64_t set_color(uint64_t address, uint32_t rgb);
    
    // Remove annotation
    bool remove(uint64_t id);
    
    // Get annotation by ID
    std::optional<Annotation> get(uint64_t id) const;
    
    // Get all annotations at address
    std::vector<Annotation> get_at_address(uint64_t address) const;
    
    // Get comment at address (if any)
    std::optional<std::string> get_comment(uint64_t address) const;
    
    // Get label at address (if any)
    std::optional<std::string> get_label(uint64_t address) const;
    
    // Get color at address (default if none)
    uint32_t get_color(uint64_t address) const;
    
    // Get all bookmarks
    std::vector<Annotation> get_all_bookmarks() const;
    
    // Get all annotations
    std::vector<Annotation> get_all() const;
    
    // Clear all annotations
    void clear();
    
    // Persist to file
    bool save(const std::string& path) const;
    
    // Load from file
    bool load(const std::string& path);
    
    // Export as CSV
    std::string export_csv() const;
    
    // Import from CSV
    bool import_csv(const std::string& csv);
    
    // Get next bookmark from address
    std::optional<uint64_t> next_bookmark(uint64_t from) const;
    
    // Get previous bookmark from address
    std::optional<uint64_t> prev_bookmark(uint64_t from) const;
    
private:
    std::unordered_map<uint64_t, Annotation> annotations_;
    uint64_t next_id_ = 1;
    
    uint64_t generate_id() { return next_id_++; }
};

uint64_t AnnotationDatabase::add_bookmark(uint64_t address, const std::string& name) {
    Annotation ann;
    ann.id = generate_id();
    ann.address = address;
    ann.type = AnnotationType::Bookmark;
    ann.text = name.empty() ? "Bookmark_" + std::to_string(ann.id) : name;
    ann.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    
    annotations_[ann.id] = ann;
    return ann.id;
}

uint64_t AnnotationDatabase::add_comment(uint64_t address, const std::string& text) {
    // Check if there's already a comment at this address
    for (auto& [id, ann] : annotations_) {
        if (ann.address == address && ann.type == AnnotationType::Comment) {
            ann.text = text;  // Update existing
            return id;
        }
    }
    
    Annotation ann;
    ann.id = generate_id();
    ann.address = address;
    ann.type = AnnotationType::Comment;
    ann.text = text;
    ann.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    
    annotations_[ann.id] = ann;
    return ann.id;
}

uint64_t AnnotationDatabase::set_label(uint64_t address, const std::string& name) {
    // Remove any existing label at this address
    for (auto it = annotations_.begin(); it != annotations_.end(); ) {
        if (it->second.address == address && it->second.type == AnnotationType::Label) {
            it = annotations_.erase(it);
        } else {
            ++it;
        }
    }
    
    Annotation ann;
    ann.id = generate_id();
    ann.address = address;
    ann.type = AnnotationType::Label;
    ann.text = name;
    ann.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    
    annotations_[ann.id] = ann;
    return ann.id;
}

uint64_t AnnotationDatabase::set_type(uint64_t address, const std::string& type_name) {
    Annotation ann;
    ann.id = generate_id();
    ann.address = address;
    ann.type = AnnotationType::TypeInfo;
    ann.text = type_name;
    ann.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    
    annotations_[ann.id] = ann;
    return ann.id;
}

uint64_t AnnotationDatabase::set_color(uint64_t address, uint32_t rgb) {
    // Remove any existing color at this address
    for (auto it = annotations_.begin(); it != annotations_.end(); ) {
        if (it->second.address == address && it->second.type == AnnotationType::Color) {
            it = annotations_.erase(it);
        } else {
            ++it;
        }
    }
    
    Annotation ann;
    ann.id = generate_id();
    ann.address = address;
    ann.type = AnnotationType::Color;
    ann.color = rgb;
    ann.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    
    annotations_[ann.id] = ann;
    return ann.id;
}

bool AnnotationDatabase::remove(uint64_t id) {
    return annotations_.erase(id) > 0;
}

std::optional<Annotation> AnnotationDatabase::get(uint64_t id) const {
    auto it = annotations_.find(id);
    if (it == annotations_.end()) return std::nullopt;
    return it->second;
}

std::vector<Annotation> AnnotationDatabase::get_at_address(uint64_t address) const {
    std::vector<Annotation> result;
    for (const auto& [id, ann] : annotations_) {
        if (ann.address == address) {
            result.push_back(ann);
        }
    }
    return result;
}

std::optional<std::string> AnnotationDatabase::get_comment(uint64_t address) const {
    for (const auto& [id, ann] : annotations_) {
        if (ann.address == address && ann.type == AnnotationType::Comment) {
            return ann.text;
        }
    }
    return std::nullopt;
}

std::optional<std::string> AnnotationDatabase::get_label(uint64_t address) const {
    for (const auto& [id, ann] : annotations_) {
        if (ann.address == address && ann.type == AnnotationType::Label) {
            return ann.text;
        }
    }
    return std::nullopt;
}

uint32_t AnnotationDatabase::get_color(uint64_t address) const {
    for (const auto& [id, ann] : annotations_) {
        if (ann.address == address && ann.type == AnnotationType::Color) {
            return ann.color;
        }
    }
    return 0xFFFFFF;  // Default white
}

std::vector<Annotation> AnnotationDatabase::get_all_bookmarks() const {
    std::vector<Annotation> result;
    for (const auto& [id, ann] : annotations_) {
        if (ann.type == AnnotationType::Bookmark) {
            result.push_back(ann);
        }
    }
    // Sort by address
    std::sort(result.begin(), result.end(), 
        [](const Annotation& a, const Annotation& b) { return a.address < b.address; });
    return result;
}

std::vector<Annotation> AnnotationDatabase::get_all() const {
    std::vector<Annotation> result;
    for (const auto& [id, ann] : annotations_) {
        result.push_back(ann);
    }
    return result;
}

void AnnotationDatabase::clear() {
    annotations_.clear();
    next_id_ = 1;
}

bool AnnotationDatabase::save(const std::string& path) const {
    std::ofstream file(path);
    if (!file) return false;
    
    // Simple INI-style format
    for (const auto& [id, ann] : annotations_) {
        file << "[" << id << "]\n";
        file << "address=0x" << std::hex << ann.address << std::dec << "\n";
        file << "type=" << static_cast<int>(ann.type) << "\n";
        file << "text=" << ann.text << "\n";
        file << "color=" << ann.color << "\n";
        file << "timestamp=" << ann.timestamp << "\n";
        file << "\n";
    }
    
    return true;
}

bool AnnotationDatabase::load(const std::string& path) {
    clear();
    
    std::ifstream file(path);
    if (!file) return false;
    
    // Simple INI parsing
    std::string line;
    Annotation current;
    bool in_entry = false;
    
    while (std::getline(file, line)) {
        if (line.empty()) {
            if (in_entry) {
                annotations_[current.id] = current;
                in_entry = false;
            }
            continue;
        }
        
        if (line[0] == '[' && line.back() == ']') {
            if (in_entry) {
                annotations_[current.id] = current;
            }
            current = Annotation{};
            current.id = std::stoull(line.substr(1, line.size() - 2));
            in_entry = true;
            next_id_ = std::max(next_id_, current.id + 1);
        } else if (line.find("address=") == 0) {
            std::string addr_str = line.substr(8);
            if (addr_str.find("0x") == 0) {
                current.address = std::stoull(addr_str.substr(2), nullptr, 16);
            } else {
                current.address = std::stoull(addr_str);
            }
        } else if (line.find("type=") == 0) {
            current.type = static_cast<AnnotationType>(std::stoi(line.substr(5)));
        } else if (line.find("text=") == 0) {
            current.text = line.substr(5);
        } else if (line.find("color=") == 0) {
            current.color = std::stoul(line.substr(6));
        } else if (line.find("timestamp=") == 0) {
            current.timestamp = std::stoull(line.substr(10));
        }
    }
    
    if (in_entry) {
        annotations_[current.id] = current;
    }
    
    return true;
}

std::string AnnotationDatabase::export_csv() const {
    std::ostringstream oss;
    oss << "id,address,type,text,color,timestamp\n";
    
    for (const auto& [id, ann] : annotations_) {
        oss << id << ",";
        oss << std::hex << "0x" << ann.address << std::dec << ",";
        oss << static_cast<int>(ann.type) << ",";
        oss << "\"" << ann.text << "\",";
        oss << ann.color << ",";
        oss << ann.timestamp << "\n";
    }
    
    return oss.str();
}

bool AnnotationDatabase::import_csv(const std::string& csv) {
    clear();
    
    std::istringstream iss(csv);
    std::string line;
    
    // Skip header
    std::getline(iss, line);
    
    while (std::getline(iss, line)) {
        // Simple CSV parsing (doesn't handle quoted commas properly)
        std::vector<std::string> fields;
        std::string field;
        std::istringstream line_iss(line);
        
        while (std::getline(line_iss, field, ',')) {
            fields.push_back(field);
        }
        
        if (fields.size() >= 6) {
            Annotation ann;
            ann.id = std::stoull(fields[0]);
            
            std::string addr_str = fields[1];
            if (addr_str.find("0x") == 0) {
                ann.address = std::stoull(addr_str.substr(2), nullptr, 16);
            } else {
                ann.address = std::stoull(addr_str);
            }
            
            ann.type = static_cast<AnnotationType>(std::stoi(fields[2]));
            ann.text = fields[3];
            // Remove quotes
            if (ann.text.size() >= 2 && ann.text.front() == '"' && ann.text.back() == '"') {
                ann.text = ann.text.substr(1, ann.text.size() - 2);
            }
            
            ann.color = std::stoul(fields[4]);
            ann.timestamp = std::stoull(fields[5]);
            
            annotations_[ann.id] = ann;
            next_id_ = std::max(next_id_, ann.id + 1);
        }
    }
    
    return true;
}

std::optional<uint64_t> AnnotationDatabase::next_bookmark(uint64_t from) const {
    std::optional<uint64_t> result;
    uint64_t min_diff = UINT64_MAX;
    
    for (const auto& [id, ann] : annotations_) {
        if (ann.type == AnnotationType::Bookmark && ann.address > from) {
            uint64_t diff = ann.address - from;
            if (diff < min_diff) {
                min_diff = diff;
                result = ann.address;
            }
        }
    }
    
    return result;
}

std::optional<uint64_t> AnnotationDatabase::prev_bookmark(uint64_t from) const {
    std::optional<uint64_t> result;
    uint64_t min_diff = UINT64_MAX;
    
    for (const auto& [id, ann] : annotations_) {
        if (ann.type == AnnotationType::Bookmark && ann.address < from) {
            uint64_t diff = from - ann.address;
            if (diff < min_diff) {
                min_diff = diff;
                result = ann.address;
            }
        }
    }
    
    return result;
}

// Session integration - annotations saved with session
class AnnotatedSession {
public:
    struct SessionData {
        std::string binary_path;
        ir::ContentHash binary_hash;  // To verify matching binary
        AnnotationDatabase annotations;
        // Could include other UI state
    };
    
    bool save(const std::string& path, const SessionData& data);
    std::optional<SessionData> load(const std::string& path);
};

bool AnnotatedSession::save(const std::string& path, const SessionData& data) {
    std::ofstream file(path);
    if (!file) return false;
    
    file << "[SESSION]\n";
    file << "binary=" << data.binary_path << "\n";
    file << "hash=" << data.binary_hash.to_string() << "\n";
    file << "\n";
    
    // Save annotations inline
    for (const auto& ann : data.annotations.get_all()) {
        file << "[ANNOTATION]\n";
        file << "id=" << ann.id << "\n";
        file << "address=0x" << std::hex << ann.address << std::dec << "\n";
        file << "type=" << static_cast<int>(ann.type) << "\n";
        file << "text=" << ann.text << "\n";
        file << "\n";
    }
    
    return true;
}

std::optional<AnnotatedSession::SessionData> AnnotatedSession::load(const std::string& path) {
    std::ifstream file(path);
    if (!file) return std::nullopt;
    
    SessionData data;
    std::string line;
    
    while (std::getline(file, line)) {
        if (line.find("binary=") == 0) {
            data.binary_path = line.substr(7);
        } else if (line.find("hash=") == 0) {
            // Parse hash
        }
        // ... more parsing
    }
    
    return data;
}

} // namespace atlus::annotations
