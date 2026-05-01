#include "core/string_analyzer.h"
#include <cstring>
#include <cctype>
#include <algorithm>

namespace atlus {

// ── String Scanning ─────────────────────────────────────────────────────────

bool StringAnalyzer::is_ascii_start(uint8_t b) {
    // Printable ASCII or common whitespace
    return (b >= 0x20 && b < 0x7F) || b == '\t' || b == '\n' || b == '\r';
}

bool StringAnalyzer::is_printable_ascii(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = data[i];
        // Allow printable, tab, newline, carriage return
        if (!((b >= 0x20 && b < 0x7F) || b == '\t' || b == '\n' || b == '\r')) {
            return false;
        }
    }
    return true;
}

bool StringAnalyzer::is_utf16_lead(uint8_t b1, uint8_t b2) {
    // Basic Latin in UTF-16LE: printable ASCII followed by null
    return (b1 >= 0x20 && b1 < 0x7F) && b2 == 0;
}

StringReference StringAnalyzer::decode_string(
    const uint8_t* data,
    size_t offset,
    size_t max_len,
    StringEncoding encoding
) {
    StringReference ref;
    ref.address = ir::Address::file_offset(offset);
    ref.encoding = encoding;
    ref.is_unicode = (encoding != StringEncoding::Ascii);
    
    if (encoding == StringEncoding::Ascii || encoding == StringEncoding::Utf8) {
        size_t len = 0;
        const uint8_t* ptr = data + offset;
        
        while (len < max_len && ptr[len] != 0 && is_ascii_start(ptr[len])) {
            ref.text += static_cast<char>(ptr[len]);
            len++;
        }
        
        ref.length = len;
    }
    else if (encoding == StringEncoding::Utf16LE) {
        size_t len = 0;
        const uint8_t* ptr = data + offset;
        
        while (len < max_len - 1) {
            uint8_t b1 = ptr[len];
            uint8_t b2 = ptr[len + 1];
            
            // Null terminator
            if (b1 == 0 && b2 == 0) break;
            
            // Basic Latin: ASCII byte followed by null
            if (b2 == 0 && b1 >= 0x20 && b1 < 0x7F) {
                ref.text += static_cast<char>(b1);
                len += 2;
            } else {
                break;  // Non-Basic Latin or control char
            }
        }
        
        ref.length = len / 2;
    }
    // UTF-16BE not implemented for simplicity
    
    return ref;
}

void StringAnalyzer::scan_for_ascii(const ir::Section& section, std::vector<StringReference>& out, size_t min_len) {
    // Note: Raw section data requires BinaryFile/PEInfo
    // This is a placeholder implementation
    const uint8_t* data = nullptr; // section.data.data();
    size_t size = section.virtual_size; // section.data.size();
    
    size_t i = 0;
    while (i < size) {
        // Skip non-printable
        if (!is_ascii_start(data[i])) {
            i++;
            continue;
        }
        
        // Try to decode string
        size_t max_scan = std::min(size - i, static_cast<size_t>(256));
        auto ref = decode_string(data, i, max_scan, StringEncoding::Ascii);
        
        if (ref.length >= min_len) {
            ref.address = ir::Address::virtual_addr(section.virtual_addr.offset + i);
            out.push_back(ref);
            i += ref.length + 1;  // Skip string + null terminator
        } else {
            i++;
        }
    }
}

void StringAnalyzer::scan_for_utf16(const ir::Section& section, std::vector<StringReference>& out, size_t min_len) {
    // Note: Raw section data requires BinaryFile/PEInfo
    // This is a placeholder implementation
    const uint8_t* data = nullptr; // section.data.data();
    size_t size = section.virtual_size; // section.data.size();
    
    size_t i = 0;
    while (i + 1 < size) {
        // Check for UTF-16LE Basic Latin pattern
        if (!is_utf16_lead(data[i], data[i+1])) {
            i++;
            continue;
        }
        
        size_t max_scan = std::min(size - i, static_cast<size_t>(512));
        auto ref = decode_string(data, i, max_scan, StringEncoding::Utf16LE);
        
        if (ref.length >= min_len) {
            ref.address = ir::Address::virtual_addr(section.virtual_addr.offset + i);
            out.push_back(ref);
            i += (ref.length * 2) + 2;  // Skip string + null terminator
        } else {
            i++;
        }
    }
}

// ── Public Interface ─────────────────────────────────────────────────────────

std::vector<StringReference> StringAnalyzer::find_strings_in_section(
    const ir::Section& section,
    size_t min_length
) {
    std::vector<StringReference> results;
    
    if (section.virtual_size == 0) return results;  // No data available in IR section
    
    // Scan for ASCII/UTF-8 strings
    scan_for_ascii(section, results, min_length);
    
    // Scan for UTF-16LE strings (common in Windows binaries)
    scan_for_utf16(section, results, min_length);
    
    // Sort by address
    std::sort(results.begin(), results.end(),
              [](const auto& a, const auto& b) { return a.address < b.address; });
    
    return results;
}

StringAnalysisResult StringAnalyzer::analyze(const ir::Binary& binary) {
    StringAnalysisResult result;
    
    for (const auto& section : binary.sections()) {
        // Scan data sections and read-only sections
        if (section->is_writable && !section->is_executable) {
            // Likely .data section - might have strings
            auto strings = find_strings_in_section(*section, 4);
            result.strings.insert(result.strings.end(), strings.begin(), strings.end());
        }
        else if (!section->is_writable && !section->is_executable) {
            // Likely .rdata - definitely scan for strings
            auto strings = find_strings_in_section(*section, 4);
            result.strings.insert(result.strings.end(), strings.begin(), strings.end());
        }
    }
    
    // Build address index
    for (size_t i = 0; i < result.strings.size(); ++i) {
        result.addr_to_index[result.strings[i].address] = i;
    }
    
    result.success = true;
    result.string_count = result.strings.size();
    
    return result;
}

void StringAnalyzer::resolve_code_refs(StringAnalysisResult& result, const XRefAnalysisResult& xrefs) {
    for (auto& str : result.strings) {
        str.code_refs.clear();
        
        // Find all data references that point to this string
        for (const auto& xref : xrefs.xrefs) {
            if ((xref.type == ir::XRef::Type::DataRead || xref.type == ir::XRef::Type::DataWrite) && xref.to_address == str.address) {
                str.code_refs.push_back(xref);
            }
        }
    }
}

const StringReference* StringAnalyzer::get_string_at(ir::Address addr, const StringAnalysisResult& result) {
    auto it = result.addr_to_index.find(addr);
    if (it != result.addr_to_index.end()) {
        return &result.strings[it->second];
    }
    return nullptr;
}

std::vector<const StringReference*> StringAnalyzer::search_strings(
    const StringAnalysisResult& result,
    const std::string& pattern,
    bool case_sensitive
) {
    std::vector<const StringReference*> matches;
    
    std::string search_pattern = pattern;
    if (!case_sensitive) {
        std::transform(search_pattern.begin(), search_pattern.end(), search_pattern.begin(), ::tolower);
    }
    
    for (const auto& str : result.strings) {
        std::string text = str.text;
        if (!case_sensitive) {
            std::transform(text.begin(), text.end(), text.begin(), ::tolower);
        }
        
        if (text.find(search_pattern) != std::string::npos) {
            matches.push_back(&str);
        }
    }
    
    return matches;
}

// ── Display Helpers ─────────────────────────────────────────────────────────

const char* encoding_name(StringEncoding enc) {
    switch (enc) {
        case StringEncoding::Ascii: return "ASCII";
        case StringEncoding::Utf8: return "UTF-8";
        case StringEncoding::Utf16LE: return "UTF-16LE";
        case StringEncoding::Utf16BE: return "UTF-16BE";
        default: return "Unknown";
    }
}

std::string escape_string(const std::string& s, size_t max_len) {
    std::string result;
    result.reserve(std::min(s.length(), max_len) + 10);
    
    for (size_t i = 0; i < std::min(s.length(), max_len); ++i) {
        char c = s[i];
        switch (c) {
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            case '\\': result += "\\\\"; break;
            case '"': result += "\\\""; break;
            default:
                if (c >= 0x20 && c < 0x7F) {
                    result += c;
                } else {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\x%02X", static_cast<unsigned char>(c));
                    result += buf;
                }
        }
    }
    
    if (s.length() > max_len) {
        result += "...";
    }
    
    return result;
}

} // namespace atlus
