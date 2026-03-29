#pragma once
#include "diff_engine.h"
#include "pattern_scanner.h"
#include <string>
#include <ostream>

namespace atlus {

enum class ColorMode { Auto, Always, Never };

struct FormatOptions {
    ColorMode color         = ColorMode::Auto;
    bool      show_context  = true;   // print unchanged bytes around diffs
    size_t    context_lines = 2;
    bool      compact       = false;  // one-line-per-diff mode
};

class Formatter {
public:
    explicit Formatter(FormatOptions opts = {});

    // Level 1: print byte diffs
    void print_byte_diffs(
        std::ostream&                  out,
        const std::vector<ByteDiff>&   diffs
    ) const;

    // Level 2: print section summary
    void print_section_diffs(
        std::ostream&                      out,
        const std::vector<SectionDiff>&    diffs
    ) const;

    // Level 3: print function diff summary
    void print_function_diffs(
        std::ostream&                       out,
        const std::vector<FunctionDiff>&    diffs
    ) const;

    // Level 4: print AOB signatures
    void print_signatures(
        std::ostream&                       out,
        const std::vector<AobSignature>&    sigs
    ) const;

    // Print a full DiffResult (calls the above in order)
    void print_full(std::ostream& out, const DiffResult& result) const;

    // ANSI helpers (no-ops when color is disabled)
    static const char* RED;
    static const char* GREEN;
    static const char* YELLOW;
    static const char* CYAN;
    static const char* RESET;

private:
    FormatOptions opts_;
    bool          use_color_ = false;

    void detect_color(std::ostream& out);
    std::string colorize(const char* color, const std::string& text) const;
};

} // namespace atlus
