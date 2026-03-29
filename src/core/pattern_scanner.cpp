#include "core/pattern_scanner.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace atlus {

std::vector<AobSignature> PatternScanner::generate_signatures(
    const std::vector<DiffChunk>& chunks,
    size_t context_bytes
) {
    std::vector<AobSignature> sigs;

    for (const auto& chunk : chunks) {
        AobSignature sig;
        sig.offset = chunk.offset;

        const size_t len = std::max(chunk.old_bytes.size(), chunk.new_bytes.size());

        // Build old and new patterns with wildcards where bytes are identical
        for (size_t i = 0; i < len; ++i) {
            bool have_old = i < chunk.old_bytes.size();
            bool have_new = i < chunk.new_bytes.size();

            PatternByte old_pb, new_pb;

            if (have_old && have_new && chunk.old_bytes[i] == chunk.new_bytes[i]) {
                // Same byte in both — wildcard it in both patterns
                old_pb.wildcard = true;
                new_pb.wildcard = true;
            } else {
                if (have_old) { old_pb.wildcard = false; old_pb.value = chunk.old_bytes[i]; }
                else            old_pb.wildcard = true;

                if (have_new) { new_pb.wildcard = false; new_pb.value = chunk.new_bytes[i]; }
                else            new_pb.wildcard = true;
            }

            sig.old_pattern.push_back(old_pb);
            sig.new_pattern.push_back(new_pb);
        }

        (void)context_bytes; // TODO: prepend/append context bytes from binary

        sig.ida_style = to_ida(sig.new_pattern);
        sig.ce_style  = to_ce(sig.new_pattern);
        sigs.push_back(std::move(sig));
    }

    return sigs;
}

std::string PatternScanner::to_ida(const Pattern& pattern) {
    std::ostringstream oss;
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (i > 0) oss << ' ';
        if (pattern[i].wildcard)
            oss << "??";
        else
            oss << std::uppercase << std::hex
                << std::setw(2) << std::setfill('0')
                << static_cast<int>(pattern[i].value);
    }
    return oss.str();
}

std::string PatternScanner::to_ce(const Pattern& pattern) {
    std::ostringstream oss;
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (i > 0) oss << ' ';
        if (pattern[i].wildcard)
            oss << '*';
        else
            oss << std::uppercase << std::hex
                << std::setw(2) << std::setfill('0')
                << static_cast<int>(pattern[i].value);
    }
    return oss.str();
}

std::vector<size_t> PatternScanner::scan(
    const std::vector<uint8_t>& data,
    const Pattern&              pattern
) {
    std::vector<size_t> hits;
    if (pattern.empty() || data.size() < pattern.size()) return hits;

    for (size_t i = 0; i <= data.size() - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].wildcard && data[i + j] != pattern[j].value) {
                match = false;
                break;
            }
        }
        if (match) hits.push_back(i);
    }
    return hits;
}

std::optional<Pattern> PatternScanner::parse_ida(const std::string& ida_string) {
    Pattern pattern;
    std::istringstream iss(ida_string);
    std::string token;

    while (iss >> token) {
        PatternByte pb;
        if (token == "??" || token == "?") {
            pb.wildcard = true;
        } else if (token.size() == 2) {
            try {
                pb.value = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
            } catch (...) {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
        pattern.push_back(pb);
    }

    return pattern.empty() ? std::nullopt : std::make_optional(pattern);
}

} // namespace atlus
