#include "core/formatter.h"
#include <iomanip>
#include <sstream>

namespace atlus {

// ANSI codes (empty strings when color is off, set dynamically)
const char* Formatter::RED    = "\033[31m";
const char* Formatter::GREEN  = "\033[32m";
const char* Formatter::YELLOW = "\033[33m";
const char* Formatter::CYAN   = "\033[36m";
const char* Formatter::RESET  = "\033[0m";

Formatter::Formatter(FormatOptions opts) : opts_(std::move(opts)) {}

std::string Formatter::colorize(const char* color, const std::string& text) const {
    if (!use_color_) return text;
    return std::string(color) + text + RESET;
}

void Formatter::print_byte_diffs(
    std::ostream& out,
    const std::vector<ByteDiff>& diffs
) const {
    if (diffs.empty()) {
        out << colorize(GREEN, "[=] No byte differences found.\n");
        return;
    }

    out << colorize(YELLOW, "[+] Byte differences: ")
        << diffs.size() << "\n\n";

    out << std::left  << std::setw(12) << "Offset"
        << std::setw(8)  << "Old"
        << std::setw(8)  << "New" << "\n";
    out << std::string(28, '-') << "\n";

    for (const auto& d : diffs) {
        std::ostringstream row;
        row << "0x" << std::uppercase << std::hex
            << std::setw(8) << std::setfill('0') << d.offset
            << std::setfill(' ') << "    "
            << std::setw(4) << std::setfill('0') << static_cast<int>(d.old_byte) << "    "
            << std::setw(4) << std::setfill('0') << static_cast<int>(d.new_byte);
        out << row.str() << "\n";
    }
}

void Formatter::print_section_diffs(
    std::ostream& out,
    const std::vector<SectionDiff>& diffs
) const {
    out << colorize(CYAN, "\n[*] Section diff:\n");

    for (const auto& sd : diffs) {
        std::string status_str;
        const char* color = RESET;

        switch (sd.status) {
            case SectionDiff::Status::Unchanged: status_str = "unchanged"; color = RESET;  break;
            case SectionDiff::Status::Modified:  status_str = "MODIFIED";  color = YELLOW; break;
            case SectionDiff::Status::Added:     status_str = "ADDED";     color = GREEN;  break;
            case SectionDiff::Status::Removed:   status_str = "REMOVED";   color = RED;    break;
        }

        out << "  " << std::left << std::setw(12) << sd.name
            << colorize(color, status_str);

        if (sd.status == SectionDiff::Status::Modified)
            out << "  (" << sd.byte_diffs.size() << " byte changes)";

        out << "\n";
    }
}

void Formatter::print_function_diffs(
    std::ostream& out,
    const std::vector<FunctionDiff>& diffs
) const {
    out << colorize(CYAN, "\n[*] Function diff:\n");

    for (const auto& fd : diffs) {
        std::string status_str;
        const char* color = RESET;

        switch (fd.status) {
            case FunctionDiff::Status::Unchanged: continue; // skip noise
            case FunctionDiff::Status::Modified:  status_str = "modified"; color = YELLOW; break;
            case FunctionDiff::Status::Added:     status_str = "added";    color = GREEN;  break;
            case FunctionDiff::Status::Removed:   status_str = "removed";  color = RED;    break;
        }

        out << "  " << colorize(color, status_str) << "  " << fd.name;
        if (fd.old_address)
            out << "  @ 0x" << std::hex << fd.old_address;
        out << "\n";
    }
}

void Formatter::print_signatures(
    std::ostream& out,
    const std::vector<AobSignature>& sigs
) const {
    out << colorize(CYAN, "\n[*] AOB signatures:\n");

    for (const auto& sig : sigs) {
        out << "  Offset 0x" << std::hex << sig.offset << ":\n";
        out << "    IDA: " << sig.ida_style << "\n";
        out << "    CE:  " << sig.ce_style  << "\n";
    }
}

void Formatter::print_full(std::ostream& out, const DiffResult& result) const {
    if (result.size_changed()) {
        out << colorize(YELLOW, "[!] File size changed: ")
            << result.old_size << " -> " << result.new_size << " bytes\n\n";
    }

    print_byte_diffs(out, result.byte_diffs);

    if (!result.section_diffs.empty())
        print_section_diffs(out, result.section_diffs);

    if (!result.function_diffs.empty())
        print_function_diffs(out, result.function_diffs);
}

} // namespace atlus
