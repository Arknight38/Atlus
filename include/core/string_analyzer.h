#pragma once
#include "core/ir.h"
#include "core/xref_analyzer.h"
#include <vector>
#include <string>
#include <unordered_map>

namespace atlus {

// ── String Analyzer ──────────────────────────────────────────────────────────
// Scans binary for string literals and detects code references to them.
// Supports ASCII, UTF-8, UTF-16LE/BE encoded strings.

enum class StringEncoding {
    Ascii,
    Utf8,
    Utf16LE,
    Utf16BE
};

struct StringReference {
    ir::Address address;           // Address of string in memory
    size_t length;             // Length in characters
    std::string text;          // Decoded text (UTF-8 for display)
    StringEncoding encoding;
    bool is_unicode;
    
    // References to this string
    std::vector<ir::XRef> code_refs;  // Instructions referencing this string
};

struct StringAnalysisResult {
    bool success = false;
    size_t string_count = 0;
    std::vector<StringReference> strings;
    
    // Index by address for fast lookup
    std::unordered_map<ir::Address, size_t> addr_to_index;
};

class StringAnalyzer {
public:
    StringAnalyzer() = default;
    
    // Analyze all sections for strings
    StringAnalysisResult analyze(const ir::Binary& binary);
    
    // Find strings in a specific data section
    std::vector<StringReference> find_strings_in_section(
        const ir::Section& section,
        size_t min_length = 4
    );
    
    // Match code references to discovered strings
    void resolve_code_refs(StringAnalysisResult& result, const struct XRefAnalysisResult& xrefs);
    
    // Get string at address if known
    const StringReference* get_string_at(ir::Address addr, const StringAnalysisResult& result);
    
    // Search strings by pattern
    std::vector<const StringReference*> search_strings(
        const StringAnalysisResult& result,
        const std::string& pattern,
        bool case_sensitive = false
    );

private:
    // Detect encoding and decode string
    StringReference decode_string(
        const uint8_t* data,
        size_t offset,
        size_t max_len,
        StringEncoding encoding
    );
    
    // Check if byte sequence is valid ASCII string start
    bool is_ascii_start(uint8_t b);
    bool is_utf16_lead(uint8_t b1, uint8_t b2);
    
    // Scan for strings of specific encoding
    void scan_for_ascii(const ir::Section& section, std::vector<StringReference>& out, size_t min_len);
    void scan_for_utf16(const ir::Section& section, std::vector<StringReference>& out, size_t min_len);
    
    // Heuristic: is this a printable string?
    bool is_printable_ascii(const uint8_t* data, size_t len);
};

// ── String Display Helpers ───────────────────────────────────────────────────

const char* encoding_name(StringEncoding enc);
std::string escape_string(const std::string& s, size_t max_len = 64);

} // namespace atlus
