#include "core/analyzer.h"
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>
#include <Zydis/Zydis.h>

namespace atlus {

Analyzer::Analyzer(Disassembler::Mode mode) : disasm_(mode) {}

// ─────────────────────────────────────────────────────────────────────────────
// Prologue detection
// Covers the most common MSVC x64 release and debug prologues.
// ─────────────────────────────────────────────────────────────────────────────
bool Analyzer::is_prologue(const uint8_t* bytes, size_t remaining) const {
    if (remaining < 2) return false;

    // push rbp; mov rbp, rsp  (55 48 89 E5)
    if (remaining >= 4 &&
        bytes[0] == 0x55 && bytes[1] == 0x48 &&
        bytes[2] == 0x89 && bytes[3] == 0xE5) return true;

    // sub rsp, imm8  (48 83 EC xx)
    if (remaining >= 4 &&
        bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) return true;

    // sub rsp, imm32  (48 81 EC xx xx xx xx)
    if (remaining >= 7 &&
        bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC) return true;

    // REX push rbp  (40 55)
    if (bytes[0] == 0x40 && bytes[1] == 0x55) return true;

    // push rdi  (57) — common in MSVC leaf functions
    if (bytes[0] == 0x57) return true;

    // push rsi  (56)
    if (bytes[0] == 0x56) return true;

    // mov [rsp+8], rcx  (48 89 4C 24 08) — MSVC fastcall thunks
    if (remaining >= 5 &&
        bytes[0] == 0x48 && bytes[1] == 0x89 &&
        bytes[2] == 0x4C && bytes[3] == 0x24) return true;

    // push rbx  (53) — common in non-leaf functions
    if (bytes[0] == 0x53) return true;

    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Walk forward from a prologue until we hit a ret/retn, an unconditional jmp
// with no return, or a hard cap. Returns the number of bytes consumed.
//
// Uses Zydis directly (same decoder the Disassembler class wraps) so we don't
// allocate a full Instruction vector for every candidate — just need lengths
// and mnemonic IDs.
// ─────────────────────────────────────────────────────────────────────────────
static size_t measure_function(const uint8_t* data, size_t max_bytes) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder,
                     ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_STACK_WIDTH_64);

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];

    size_t offset      = 0;
    size_t last_ret    = 0;     // byte offset just past the last ret we saw
    int    insn_count  = 0;
    const  int MAX_INSNS = 4096; // hard cap: ~16 KB of instructions

    while (offset < max_bytes && insn_count < MAX_INSNS) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder,
                data + offset,
                max_bytes - offset,
                &insn, ops))) {
            // Decode failure — probably hit padding or data. Stop here.
            break;
        }

        offset += insn.length;
        ++insn_count;

        // ret / retn — end of function body
        if (insn.mnemonic == ZYDIS_MNEMONIC_RET) {
            last_ret = offset;

            // Look ahead: if the next byte(s) are INT3 (0xCC) padding or
            // another valid prologue, this really is the end.
            // Otherwise keep going — tail-called functions can have multiple rets.
            if (offset < max_bytes) {
                const uint8_t* next = data + offset;
                size_t remaining = max_bytes - offset;

                // INT3 padding → definitely done
                if (next[0] == 0xCC) break;

                // NOP padding (90, or 66 90, or 0F 1F ...) → done
                if (next[0] == 0x90) break;
                if (remaining >= 2 && next[0] == 0x66 && next[1] == 0x90) break;
                if (remaining >= 3 && next[0] == 0x0F &&
                    next[1] == 0x1F && next[2] == 0x00) break;

                // Another valid prologue → done (next function starts here)
                // Use a quick 2-byte check to avoid calling is_prologue on
                // every byte (it's called from the outer loop already).
                if (next[0] == 0x55 || next[0] == 0x53 ||
                    next[0] == 0x56 || next[0] == 0x57 ||
                    next[0] == 0x40 || next[0] == 0x48) break;
            } else {
                // Hit end of buffer after ret
                break;
            }

            // Otherwise, this might be a non-tail ret in the middle of a function
            // (e.g. early-exit paths). Keep walking.
        }

        // Unconditional jmp with no obvious successor → treat as function end.
        // We check this separately from ret because a jmp can be a tail call.
        if (insn.mnemonic == ZYDIS_MNEMONIC_JMP) {
            // If followed by INT3 or NOP, it's the end.
            if (offset < max_bytes) {
                if (data[offset] == 0xCC || data[offset] == 0x90) {
                    last_ret = offset;
                    break;
                }
            } else {
                last_ret = offset;
                break;
            }
        }
    }

    // If we never saw a ret, return what we walked so the caller still gets
    // a reasonable size estimate (capped at MAX_INSNS instructions worth).
    return last_ret > 0 ? last_ret : offset;
}

// ─────────────────────────────────────────────────────────────────────────────
// find_functions
// Scans the section for prologues, then measures each one to get real bounds.
// Also deduplicates: if two prologues are found within 4 bytes of each other
// (can happen with REX prefix variants), only the first is kept.
// ─────────────────────────────────────────────────────────────────────────────
std::vector<Function> Analyzer::find_functions(
    const PESection& section,
    uint64_t         image_base
) const {
    std::vector<Function> fns;
    const auto& data = section.data;

    size_t i = 0;
    while (i + 4 < data.size()) {
        if (!is_prologue(data.data() + i, data.size() - i)) {
            ++i;
            continue;
        }

        uint64_t addr = image_base + section.vaddr + i;

        // Measure the function by walking instructions
        const size_t max_scan = data.size() - i;
        size_t fn_bytes = measure_function(data.data() + i, max_scan);

        // Clamp to a sane minimum (some prologues are immediately followed
        // by padding — treat them as 1-instruction stubs rather than 0-byte)
        if (fn_bytes == 0) fn_bytes = 1;

        Function fn;
        fn.start_address = addr;
        fn.end_address   = addr + fn_bytes;
        fn.size_bytes    = fn_bytes;

        char buf[32];
        std::snprintf(buf, sizeof(buf), "%llX", (unsigned long long)addr);
        fn.name = "sub_" + std::string(buf);

        fns.push_back(fn);

        // Skip past this function to avoid finding prologues inside it
        // (e.g. prologue bytes that appear as operands of mov instructions).
        // Use max(1, fn_bytes) so we always advance.
        i += fn_bytes > 0 ? fn_bytes : 1;
    }

    return fns;
}

// ─────────────────────────────────────────────────────────────────────────────
// find_functions_parallel — multi-threaded prologue scanning
// ─────────────────────────────────────────────────────────────────────────────
std::vector<Function> Analyzer::find_functions_parallel(
    const PESection& section,
    uint64_t         image_base,
    ThreadPool&      pool,
    AnalysisProgress* progress
) const {
    // Phase 1: Parallel prologue scan - each thread finds candidates in its chunk
    const auto& data = section.data;
    const size_t num_threads = pool.size();

    if (progress) {
        progress->start("Parallel prologue scan", data.size());
    }

    // Thread-local candidate lists
    std::vector<std::vector<std::pair<size_t, size_t>>> thread_candidates(num_threads);

    // Each thread scans a chunk and finds prologues
    pool.parallel_for(size_t(0), data.size(), [&](size_t i) {
        if (i + 4 >= data.size()) return;

        // Quick prefix check before full prologue test
        uint8_t b0 = data[i];
        if (!((b0 == 0x55) || (b0 == 0x53) || (b0 == 0x56) ||
              (b0 == 0x57) || (b0 == 0x40) || (b0 == 0x48))) {
            return;
        }

        if (is_prologue(data.data() + i, data.size() - i)) {
            // Store: (offset, thread_id)
            size_t tid = std::hash<std::thread::id>{}(std::this_thread::get_id()) % num_threads;
            thread_candidates[tid].push_back({i, 0});
        }
    }, 4096);  // 4KB chunks per thread

    if (progress) {
        progress->complete();
    }

    // Phase 2: Merge and sort candidates, deduplicate overlaps
    std::vector<std::pair<size_t, size_t>> all_candidates;
    for (auto& tc : thread_candidates) {
        all_candidates.insert(all_candidates.end(), tc.begin(), tc.end());
    }

    std::sort(all_candidates.begin(), all_candidates.end());

    // Phase 3: Parallel function measurement
    // Each candidate is measured in parallel, but we need to handle overlaps
    // Simple approach: measure all, then resolve overlaps in merge phase
    struct Candidate {
        size_t offset;
        size_t size;
        uint64_t address;
    };

    std::vector<Candidate> measured;
    measured.reserve(all_candidates.size());

    if (progress) {
        progress->start("Measure functions", all_candidates.size());
    }

    std::atomic<size_t> measured_count{0};
    std::mutex measured_mutex;

    // Parallel measurement
    pool.parallel_for(size_t(0), all_candidates.size(), [&](size_t i) {
        size_t offset = all_candidates[i].first;
        size_t max_scan = data.size() - offset;
        size_t fn_bytes = measure_function(data.data() + offset, max_scan);
        if (fn_bytes == 0) fn_bytes = 1;

        Candidate c{offset, fn_bytes, image_base + section.vaddr + offset};

        {
            std::lock_guard<std::mutex> lock(measured_mutex);
            measured.push_back(c);
        }

        if (progress && (++measured_count % 64) == 0) {
            progress->update(measured_count);
        }
    }, 1);  // One candidate per work item

    if (progress) {
        progress->complete();
    }

    // Phase 4: Resolve overlaps (sequential - must be deterministic)
    // Sort by address, keep non-overlapping functions
    std::sort(measured.begin(), measured.end(),
              [](const Candidate& a, const Candidate& b) { return a.address < b.address; });

    std::vector<Function> fns;
    fns.reserve(measured.size());

    uint64_t last_end = 0;
    for (const auto& c : measured) {
        // Skip if this function overlaps with previous
        if (c.address < last_end) continue;

        Function fn;
        fn.start_address = c.address;
        fn.end_address = c.address + c.size;
        fn.size_bytes = c.size;

        char buf[32];
        std::snprintf(buf, sizeof(buf), "%llX", (unsigned long long)c.address);
        fn.name = "sub_" + std::string(buf);

        fns.push_back(fn);
        last_end = fn.end_address;
    }

    return fns;
}

// ─────────────────────────────────────────────────────────────────────────────
// disassemble_function — full implementation now that Zydis is available
// ─────────────────────────────────────────────────────────────────────────────
Function Analyzer::disassemble_function(const PEInfo& pe, uint32_t start_rva) const {
    Function fn;

    auto offset_opt = PEParser::rva_to_offset(pe, start_rva);
    if (!offset_opt) return fn;

    // We don't know the size yet — measure first
    const uint8_t* base = pe.sections[0].data.data(); // placeholder
    // Better: find which section contains this RVA
    for (const auto& sec : pe.sections) {
        if (start_rva >= sec.vaddr && start_rva < sec.vaddr + sec.vsize) {
            size_t sec_offset = start_rva - sec.vaddr;
            size_t max_bytes  = sec.data.size() - sec_offset;
            size_t fn_bytes   = measure_function(sec.data.data() + sec_offset,
                                                  max_bytes);

            fn.start_address = pe.image_base + start_rva;
            fn.end_address   = fn.start_address + fn_bytes;
            fn.size_bytes    = fn_bytes;

            char buf[32];
            std::snprintf(buf, sizeof(buf), "%llX",
                          (unsigned long long)fn.start_address);
            fn.name = "sub_" + std::string(buf);

            // Full disassembly into instruction list
            fn.instructions = disasm_.disassemble(
                sec.data.data() + sec_offset,
                fn_bytes,
                fn.start_address);

            return fn;
        }
    }

    return fn;
}

// ─────────────────────────────────────────────────────────────────────────────
// build_xrefs — unchanged, works once instructions are populated
// ─────────────────────────────────────────────────────────────────────────────
void Analyzer::build_xrefs(std::vector<Function>& functions) {
    std::unordered_map<uint64_t, size_t> addr_map;
    for (size_t i = 0; i < functions.size(); ++i)
        addr_map[functions[i].start_address] = i;

    for (auto& fn : functions) {
        for (auto& xref : fn.calls_out) {
            auto it = addr_map.find(xref.to_address);
            if (it != addr_map.end())
                functions[it->second].calls_in.push_back(xref);
        }
    }
}

} // namespace atlus