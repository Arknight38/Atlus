#pragma once
#include "loader.h"
#include "pe_parser.h"
#include "disassembler.h"
#include "analyzer.h"
#include <cstdint>
#include <string>
#include <vector>

namespace atlus {

// ── Level 1: Byte diff ────────────────────────────────────────────────────────

struct ByteDiff {
    size_t  offset;
    uint8_t old_byte;
    uint8_t new_byte;
};

// Contiguous run of changed bytes (used by pattern scanner)
struct DiffChunk {
    size_t               offset;
    std::vector<uint8_t> old_bytes;
    std::vector<uint8_t> new_bytes;
};

// ── Level 2: Section diff ─────────────────────────────────────────────────────

struct SectionDiff {
    std::string name;

    enum class Status { Unchanged, Modified, Added, Removed };
    Status status = Status::Unchanged;

    std::vector<ByteDiff> byte_diffs; // Only populated when status == Modified
};

// ── Level 3: Function diff ────────────────────────────────────────────────────

struct FunctionDiff {
    enum class Status { Unchanged, Modified, Added, Removed };
    Status status;

    uint64_t old_address = 0;
    uint64_t new_address = 0;
    std::string name;

    // Instruction-level changes within the function
    std::vector<std::string> changed_instructions; // human-readable summary lines
};

// ── Top-level result ──────────────────────────────────────────────────────────

struct DiffResult {
    // Level 1
    std::vector<ByteDiff>  byte_diffs;
    std::vector<DiffChunk> chunks;

    // Level 2
    std::vector<SectionDiff> section_diffs;

    // Level 3
    std::vector<FunctionDiff> function_diffs;

    // Metadata
    size_t old_size = 0;
    size_t new_size = 0;
    bool   size_changed() const { return old_size != new_size; }
};

// ── Engine ────────────────────────────────────────────────────────────────────

class DiffEngine {
public:
    // Level 1: pure byte diff
    static std::vector<ByteDiff> byte_diff(
        const BinaryFile& old_file,
        const BinaryFile& new_file
    );

    // Group consecutive ByteDiffs into contiguous chunks
    static std::vector<DiffChunk> make_chunks(const std::vector<ByteDiff>& diffs);

    // Level 2: section-aware diff (requires parsed PE headers)
    static std::vector<SectionDiff> section_diff(
        const PEInfo& old_pe,
        const PEInfo& new_pe
    );

    // Level 3: function-level diff (requires analyzed functions)
    static std::vector<FunctionDiff> function_diff(
        const std::vector<Function>& old_fns,
        const std::vector<Function>& new_fns
    );

    // Run all levels and aggregate into a DiffResult
    static DiffResult full_diff(
        const BinaryFile& old_file,
        const BinaryFile& new_file,
        bool run_section_diff  = true,
        bool run_function_diff = false // requires Zydis; off by default
    );

private:
    // Instruction-level diff between two function bodies
    static std::vector<std::string> diff_instructions(
        const std::vector<Instruction>& old_insns,
        const std::vector<Instruction>& new_insns
    );
};

} // namespace atlus
