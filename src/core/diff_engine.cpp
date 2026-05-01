#include "core/diff_engine.h"
#include "core/analyzer.h"
#include <algorithm>
#include <unordered_map>
#include <thread>
#include <atomic>

namespace atlus {

// ── Level 1: byte diff ────────────────────────────────────────────────────────

std::vector<ByteDiff> DiffEngine::byte_diff(
    const BinaryFile& old_file,
    const BinaryFile& new_file
) {
    std::vector<ByteDiff> diffs;
    const size_t common = std::min(old_file.size(), new_file.size());

    for (size_t i = 0; i < common; ++i) {
        if (old_file[i] != new_file[i])
            diffs.push_back({ i, old_file[i], new_file[i] });
    }
    return diffs;
}

std::vector<DiffChunk> DiffEngine::make_chunks(const std::vector<ByteDiff>& diffs) {
    std::vector<DiffChunk> chunks;
    if (diffs.empty()) return chunks;

    DiffChunk current;
    current.offset = diffs[0].offset;
    current.old_bytes.push_back(diffs[0].old_byte);
    current.new_bytes.push_back(diffs[0].new_byte);

    for (size_t i = 1; i < diffs.size(); ++i) {
        if (diffs[i].offset == diffs[i-1].offset + 1) {
            // Contiguous: extend current chunk
            current.old_bytes.push_back(diffs[i].old_byte);
            current.new_bytes.push_back(diffs[i].new_byte);
        } else {
            chunks.push_back(std::move(current));
            current = {};
            current.offset = diffs[i].offset;
            current.old_bytes.push_back(diffs[i].old_byte);
            current.new_bytes.push_back(diffs[i].new_byte);
        }
    }
    chunks.push_back(std::move(current));
    return chunks;
}

// ── Level 2: section diff ─────────────────────────────────────────────────────

std::vector<SectionDiff> DiffEngine::section_diff(
    const PEInfo& old_pe,
    const PEInfo& new_pe
) {
    std::vector<SectionDiff> results;

    std::unordered_map<std::string, const PESection*> new_map;
    for (const auto& sec : new_pe.sections)
        new_map[sec.name] = &sec;

    // Check old sections
    for (const auto& old_sec : old_pe.sections) {
        SectionDiff sd;
        sd.name = old_sec.name;

        auto it = new_map.find(old_sec.name);
        if (it == new_map.end()) {
            sd.status = SectionDiff::Status::Removed;
        } else {
            const auto& new_sec = *it->second;
            new_map.erase(it); // mark as seen

            if (old_sec.data == new_sec.data) {
                sd.status = SectionDiff::Status::Unchanged;
            } else {
                sd.status = SectionDiff::Status::Modified;
                // Byte diff within this section
                BinaryFile old_buf, new_buf;
                old_buf.data = old_sec.data;
                new_buf.data = new_sec.data;
                sd.byte_diffs = byte_diff(old_buf, new_buf);
            }
        }
        results.push_back(std::move(sd));
    }

    // Remaining in new_map are Added sections
    for (const auto& [name, _] : new_map) {
        SectionDiff sd;
        sd.name   = name;
        sd.status = SectionDiff::Status::Added;
        results.push_back(std::move(sd));
    }

    return results;
}

// ── Level 3: function diff ────────────────────────────────────────────────────

std::vector<FunctionDiff> DiffEngine::function_diff(
    const std::vector<Function>& old_fns,
    const std::vector<Function>& new_fns
) {
    std::vector<FunctionDiff> results;

    // Match by name (stable across versions) then fall back to address
    std::unordered_map<std::string, const Function*> new_map;
    for (const auto& fn : new_fns)
        new_map[fn.name] = &fn;

    for (const auto& old_fn : old_fns) {
        FunctionDiff fd;
        fd.name        = old_fn.name;
        fd.old_address = old_fn.start_address;

        auto it = new_map.find(old_fn.name);
        if (it == new_map.end()) {
            fd.status = FunctionDiff::Status::Removed;
        } else {
            fd.new_address = it->second->start_address;
            new_map.erase(it);

            bool same_bytes = (old_fn.instructions.size() == it->second->instructions.size());
            // TODO: real instruction-level compare via diff_instructions()
            fd.status = same_bytes ? FunctionDiff::Status::Unchanged
                                   : FunctionDiff::Status::Modified;
        }
        results.push_back(std::move(fd));
    }

    for (const auto& [name, fn] : new_map) {
        FunctionDiff fd;
        fd.name        = name;
        fd.new_address = fn->start_address;
        fd.status      = FunctionDiff::Status::Added;
        results.push_back(std::move(fd));
    }

    return results;
}

std::vector<std::string> DiffEngine::diff_instructions(
    const std::vector<Instruction>& /*old_insns*/,
    const std::vector<Instruction>& /*new_insns*/
) {
    // TODO: LCS-based instruction diff
    return {};
}

// ── Parallel variants (P1 roadmap) ───────────────────────────────────────────

std::vector<ByteDiff> DiffEngine::byte_diff_parallel(
    const BinaryFile& old_file,
    const BinaryFile& new_file,
    ThreadPool& pool,
    AnalysisProgress* progress
) {
    const size_t common = std::min(old_file.size(), new_file.size());
    if (common == 0) return {};

    // Use thread-local storage for each worker
    const size_t num_threads = pool.size();
    std::vector<std::vector<ByteDiff>> thread_diffs(num_threads);

    if (progress) {
        progress->start("Parallel byte diff", common);
    }

    std::atomic<size_t> diff_count{0};

    pool.parallel_for(size_t(0), common, [&](size_t i) {
        if (old_file[i] != new_file[i]) {
            size_t tid = std::hash<std::thread::id>{}(std::this_thread::get_id()) % num_threads;
            thread_diffs[tid].push_back({ i, old_file[i], new_file[i] });

            if (progress && (++diff_count % 1024) == 0) {
                progress->update(i);
            }
        }
    }, 65536);  // 64KB chunks per thread

    // Merge thread-local results (they're already sorted by offset within each chunk)
    std::vector<ByteDiff> diffs;
    size_t total = 0;
    for (const auto& td : thread_diffs) {
        total += td.size();
    }
    diffs.reserve(total);

    for (auto& td : thread_diffs) {
        diffs.insert(diffs.end(), td.begin(), td.end());
    }

    // Sort by offset
    std::sort(diffs.begin(), diffs.end(),
              [](const ByteDiff& a, const ByteDiff& b) { return a.offset < b.offset; });

    if (progress) {
        progress->complete();
    }

    return diffs;
}

DiffResult DiffEngine::full_diff_parallel(
    const BinaryFile& old_file,
    const BinaryFile& new_file,
    ThreadPool& pool,
    AnalysisProgress* progress,
    bool run_section_diff,
    bool run_function_diff
) {
    DiffResult result;
    result.old_size = old_file.size();
    result.new_size = new_file.size();

    // Parallel byte diff
    result.byte_diffs = byte_diff_parallel(old_file, new_file, pool, progress);
    result.chunks = make_chunks(result.byte_diffs);

    if (progress) {
        progress->update(result.byte_diffs.size());
    }

    if (run_section_diff) {
        if (progress) {
            progress->start("Section diff", 1);
        }
        PEInfo old_pe = PEParser::parse(old_file);
        PEInfo new_pe = PEParser::parse(new_file);
        if (old_pe.valid && new_pe.valid)
            result.section_diffs = section_diff(old_pe, new_pe);
        if (progress) {
            progress->complete();
        }
    }

    if (run_function_diff) {
        // TODO: run Analyzer on both PEs then call function_diff()
    }

    return result;
}

// ── Full diff ─────────────────────────────────────────────────────────────────

DiffResult DiffEngine::full_diff(
    const BinaryFile& old_file,
    const BinaryFile& new_file,
    bool run_section_diff,
    bool run_function_diff
) {
    DiffResult result;
    result.old_size = old_file.size();
    result.new_size = new_file.size();

    result.byte_diffs = byte_diff(old_file, new_file);
    result.chunks     = make_chunks(result.byte_diffs);

    if (run_section_diff) {
        PEInfo old_pe = PEParser::parse(old_file);
        PEInfo new_pe = PEParser::parse(new_file);
        if (old_pe.valid && new_pe.valid)
            result.section_diffs = section_diff(old_pe, new_pe);
    }

    if (run_function_diff) {
        // TODO: run Analyzer on both PEs then call function_diff()
    }

    return result;
}

} // namespace atlus
