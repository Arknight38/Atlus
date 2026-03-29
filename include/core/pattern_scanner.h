#pragma once
#include "diff_engine.h"
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace atlus {

// A single byte in an AOB pattern: either a concrete byte or a wildcard.
struct PatternByte {
    bool    wildcard = false;
    uint8_t value    = 0x00;
};

using Pattern = std::vector<PatternByte>;

struct AobSignature {
    size_t         offset;      // File offset the pattern originates from
    Pattern        old_pattern; // Pattern of the old bytes
    Pattern        new_pattern; // Pattern of the new bytes
    std::string    ida_style;   // "55 8B EC 83 EC ?? 00"  (IDA/x64dbg format)
    std::string    ce_style;    // "55 8B EC 83 EC * 00"    (Cheat Engine format)
};

class PatternScanner {
public:
    // Generate AOB signatures from diff chunks.
    // Wildcards are inserted where only certain bytes changed within a chunk.
    static std::vector<AobSignature> generate_signatures(
        const std::vector<DiffChunk>& chunks,
        size_t context_bytes = 4  // bytes of unchanged context to include
    );

    // Format a pattern as IDA-style string:  "55 8B EC ?? ?? 00"
    static std::string to_ida(const Pattern& pattern);

    // Format a pattern as Cheat Engine wildcard string: "55 8B EC * * 00"
    static std::string to_ce(const Pattern& pattern);

    // Scan a binary for a pattern; returns all matching offsets.
    static std::vector<size_t> scan(
        const std::vector<uint8_t>& data,
        const Pattern&              pattern
    );

    // Parse an IDA-style string back into a Pattern.
    // Returns nullopt if the string is malformed.
    static std::optional<Pattern> parse_ida(const std::string& ida_string);
};

} // namespace atlus
