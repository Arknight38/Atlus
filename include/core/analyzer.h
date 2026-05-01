#pragma once
#include "disassembler.h"
#include "pe_parser.h"
#include "thread_pool.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace atlus {

// ── Function model ─────────────────────────────────────────────────────────────

struct XRef {
    uint64_t from_address; // Address of the call/jmp instruction
    uint64_t to_address;   // Target address
    bool     is_call;      // true = CALL, false = JMP
};

struct Function {
    uint64_t start_address;
    uint64_t end_address;       // Estimated end (address of last instruction + len)
    size_t   size_bytes;

    std::string              name;  // Symbol name if known, else "sub_XXXXXX"
    std::vector<Instruction> instructions;
    std::vector<XRef>        calls_out; // Functions this function calls
    std::vector<XRef>        calls_in;  // Functions that call this one (backfilled)

    bool has_name() const { return !name.empty() && name[0] != 's'; }
};

// ── Analyzer ──────────────────────────────────────────────────────────────────

class Analyzer {
public:
    explicit Analyzer(Disassembler::Mode mode = Disassembler::Mode::X86_64);

    // Phase 3: detect functions in a PE section using heuristics.
    // Looks for common prologues: push rbp / mov rbp,rsp / sub rsp,N
    std::vector<Function> find_functions(
        const PESection& section,
        uint64_t         image_base
    ) const;

    // Multi-threaded function detection - significantly faster for large sections.
    // Uses thread pool to scan section in parallel chunks.
    std::vector<Function> find_functions_parallel(
        const PESection& section,
        uint64_t         image_base,
        ThreadPool&      pool,
        AnalysisProgress* progress = nullptr
    ) const;

    // Disassemble a known function starting at start_rva.
    Function disassemble_function(
        const PEInfo& pe,
        uint32_t      start_rva
    ) const;

    // Build a cross-reference map across all detected functions.
    // Populates calls_in on each Function.
    static void build_xrefs(std::vector<Function>& functions);

private:
    Disassembler disasm_;

    bool is_prologue(const uint8_t* bytes, size_t remaining) const;
};

} // namespace atlus
