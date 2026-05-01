#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>

namespace atlus {

// ── Disassembly Cache ─────────────────────────────────────────────────────────
// Persistent file-based cache for disassembly results.
// Uses file hash (SHA-256) as the primary key to identify cached data.

struct Instruction;
struct DisassemblyBlock {
    uint64_t address;
    uint64_t size;
    std::vector<uint8_t> raw_bytes;
    std::vector<Instruction> instructions;
    uint64_t cache_time;  // Unix timestamp when cached
};

class DisassemblyCache {
public:
    // Default cache directory: %LOCALAPPDATA%/Atlus/cache/
    explicit DisassemblyCache(const std::string& cache_path = "");
    ~DisassemblyCache();

    // Disable copy, enable move
    DisassemblyCache(const DisassemblyCache&) = delete;
    DisassemblyCache& operator=(const DisassemblyCache&) = delete;
    DisassemblyCache(DisassemblyCache&&) noexcept;
    DisassemblyCache& operator=(DisassemblyCache&&) noexcept;

    // Initialize/open cache directory
    bool open();
    void close();
    bool is_open() const;

    // Cache key = SHA-256 of file bytes + address
    bool has_entry(const std::string& file_hash, uint64_t address) const;
    
    // Get cached disassembly for a block
    bool get_block(const std::string& file_hash, uint64_t address, 
                   DisassemblyBlock& out_block) const;
    
    // Store disassembly for a block
    bool put_block(const std::string& file_hash, uint64_t address,
                   const DisassemblyBlock& block);

    // Store multiple blocks (batch)
    bool put_blocks_batch(const std::string& file_hash,
                          const std::vector<DisassemblyBlock>& blocks);

    // Invalidate all entries for a file
    bool invalidate_file(const std::string& file_hash);

    // Get cache statistics
    struct Stats {
        uint64_t total_entries = 0;
        uint64_t total_bytes = 0;
        uint64_t oldest_entry = 0;
        uint64_t newest_entry = 0;
    };
    Stats get_stats() const;

    // Maintenance
    bool vacuum();  // Reclaim space (no-op for file-based cache)
    bool purge_older_than(uint64_t age_seconds);  // Remove old entries
    bool clear();  // Clear entire cache

    // Cache path
    std::string path() const;

private:
    std::string cache_path_;
    bool open_ = false;
    mutable std::mutex mutex_;

    // Generate cache file path from hash and address
    std::string get_entry_path(const std::string& file_hash, uint64_t address) const;
};

// ── Global Cache Instance ────────────────────────────────────────────────────

DisassemblyCache& get_disassembly_cache();

// ── Cache Helper Functions ───────────────────────────────────────────────────

// Compute SHA-256 hash of data
std::string compute_file_hash(const std::vector<uint8_t>& data);

// Get default cache directory
std::string get_default_cache_directory();

// Ensure directory exists
bool ensure_directory_exists(const std::string& path);

} // namespace atlus
