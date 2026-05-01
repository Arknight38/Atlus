#include "core/disassembly_cache.h"
#include "core/disassembler.h"
#include "core/sha256.h"
#include <fstream>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <filesystem>

namespace atlus {

// ── Instruction Serialization ───────────────────────────────────────────────
// Simple binary format for caching instructions
// Format: [count:4][instruction data...]
// Each instruction: [address:8][size:4][mnemonic_len:2][mnemonic][operands_len:2][operands]

static std::vector<uint8_t> serialize_instructions(const std::vector<Instruction>& insns) {
    std::vector<uint8_t> result;
    
    // Write count
    uint32_t count = static_cast<uint32_t>(insns.size());
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&count), 
                  reinterpret_cast<uint8_t*>(&count) + sizeof(count));
    
    for (const auto& insn : insns) {
        // Address
        result.insert(result.end(), reinterpret_cast<const uint8_t*>(&insn.address),
                      reinterpret_cast<const uint8_t*>(&insn.address) + sizeof(insn.address));
        
        // Length (using ir::Instruction::length)
        uint32_t length = insn.length;
        result.insert(result.end(), reinterpret_cast<const uint8_t*>(&length),
                      reinterpret_cast<const uint8_t*>(&length) + sizeof(length));
        
        // Mnemonic
        uint16_t mnem_len = static_cast<uint16_t>(insn.mnemonic.size());
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&mnem_len),
                      reinterpret_cast<uint8_t*>(&mnem_len) + sizeof(mnem_len));
        result.insert(result.end(), insn.mnemonic.begin(), insn.mnemonic.end());
        
        // Operands
        uint16_t op_len = static_cast<uint16_t>(insn.operands.size());
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&op_len),
                      reinterpret_cast<uint8_t*>(&op_len) + sizeof(op_len));
        result.insert(result.end(), insn.operands.begin(), insn.operands.end());
    }
    
    return result;
}

static std::vector<Instruction> deserialize_instructions(const std::vector<uint8_t>& data) {
    std::vector<Instruction> result;
    if (data.size() < 4) return result;
    
    const uint8_t* ptr = data.data();
    const uint8_t* end = data.data() + data.size();
    
    uint32_t count = *reinterpret_cast<const uint32_t*>(ptr);
    ptr += sizeof(count);
    
    result.reserve(count);
    
    for (uint32_t i = 0; i < count && ptr < end; ++i) {
        Instruction insn;
        
        // Address
        if (ptr + sizeof(insn.address) > end) break;
        insn.address = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += sizeof(insn.address);
        
        // Length
        if (ptr + sizeof(uint32_t) > end) break;
        insn.length = static_cast<uint8_t>(*reinterpret_cast<const uint32_t*>(ptr));
        ptr += sizeof(uint32_t);
        
        // Mnemonic
        if (ptr + 2 > end) break;
        uint16_t mnem_len = *reinterpret_cast<const uint16_t*>(ptr);
        ptr += 2;
        if (ptr + mnem_len > end) break;
        insn.mnemonic.assign(reinterpret_cast<const char*>(ptr), mnem_len);
        ptr += mnem_len;
        
        // Operands
        if (ptr + 2 > end) break;
        uint16_t op_len = *reinterpret_cast<const uint16_t*>(ptr);
        ptr += 2;
        if (ptr + op_len > end) break;
        insn.operands.assign(reinterpret_cast<const char*>(ptr), op_len);
        ptr += op_len;
        
        result.push_back(insn);
    }
    
    return result;
}

// ── SHA-256 Hashing ─────────────────────────────────────────────────────────

std::string compute_file_hash(const std::vector<uint8_t>& data) {
    return sha256_hex(data);
}

// ── File System Helpers ────────────────────────────────────────────────────

std::string get_default_cache_directory() {
#ifdef _WIN32
    const char* local_appdata = std::getenv("LOCALAPPDATA");
    if (local_appdata) {
        return std::string(local_appdata) + "/Atlus/cache";
    }
    const char* temp = std::getenv("TEMP");
    if (temp) return std::string(temp) + "/Atlus/cache";
#else
    const char* home = std::getenv("HOME");
    if (home) {
        return std::string(home) + "/.cache/atlus";
    }
#endif
    return "cache";
}

bool ensure_directory_exists(const std::string& path) {
    std::filesystem::create_directories(path);
    return true;
}

// ── Cache File Format ────────────────────────────────────────────────────────
// Simple binary format per cache entry:
// [magic:4] = "AC01" (Atlus Cache version 01)
// [address:8] = virtual address
// [size:8] = block size
// [raw_bytes_len:4]
// [raw_bytes: N]
// [instructions_len:4]
// [instructions: N]
// [cache_time:8] = Unix timestamp
// [checksum:4] = simple XOR checksum

static constexpr const char* CACHE_MAGIC = "AC01";
static constexpr uint32_t CACHE_VERSION = 1;

struct CacheEntryHeader {
    char magic[4];
    uint32_t version;
    uint64_t address;
    uint64_t size;
    uint32_t raw_bytes_len;
    uint32_t insns_len;
    uint64_t cache_time;
    uint32_t checksum;
};

static uint32_t compute_checksum(const uint8_t* data, size_t len) {
    uint32_t checksum = 0;
    for (size_t i = 0; i < len; ++i) {
        checksum ^= (data[i] << ((i % 4) * 8));
    }
    return checksum;
}

// ── DisassemblyCache Implementation ─────────────────────────────────────────

DisassemblyCache::DisassemblyCache(const std::string& cache_path) 
    : cache_path_(cache_path) {
    if (cache_path_.empty()) {
        cache_path_ = get_default_cache_directory();
    }
}

DisassemblyCache::~DisassemblyCache() {
    close();
}

DisassemblyCache::DisassemblyCache(DisassemblyCache&& other) noexcept
    : cache_path_(std::move(other.cache_path_)),
      open_(other.open_) {
}

DisassemblyCache& DisassemblyCache::operator=(DisassemblyCache&& other) noexcept {
    if (this != &other) {
        close();
        cache_path_ = std::move(other.cache_path_);
        open_ = other.open_;
    }
    return *this;
}

bool DisassemblyCache::open() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (open_) return true;
    
    // Ensure directory exists
    ensure_directory_exists(cache_path_);
    
    open_ = true;
    return true;
}

void DisassemblyCache::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    open_ = false;
}

bool DisassemblyCache::is_open() const {
    return open_;
}

std::string DisassemblyCache::get_entry_path(const std::string& file_hash, uint64_t address) const {
    std::ostringstream oss;
    oss << file_hash << "_" << std::hex << address << ".bin";
    return (std::filesystem::path(cache_path_) / oss.str()).string();
}

bool DisassemblyCache::has_entry(const std::string& file_hash, uint64_t address) const {
    return std::filesystem::exists(get_entry_path(file_hash, address));
}

bool DisassemblyCache::get_block(const std::string& file_hash, uint64_t address,
                                   DisassemblyBlock& out_block) const {
    std::string path = get_entry_path(file_hash, address);
    
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    
    // Read header
    CacheEntryHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    
    if (std::memcmp(header.magic, CACHE_MAGIC, 4) != 0 || header.version != CACHE_VERSION) {
        return false;
    }
    
    // Read raw bytes
    std::vector<uint8_t> raw_bytes(header.raw_bytes_len);
    if (header.raw_bytes_len > 0) {
        file.read(reinterpret_cast<char*>(raw_bytes.data()), header.raw_bytes_len);
    }
    
    // Read instructions blob
    std::vector<uint8_t> insns_blob(header.insns_len);
    if (header.insns_len > 0) {
        file.read(reinterpret_cast<char*>(insns_blob.data()), header.insns_len);
    }
    
    out_block.address = header.address;
    out_block.size = header.size;
    out_block.raw_bytes = std::move(raw_bytes);
    out_block.instructions = deserialize_instructions(insns_blob);
    out_block.cache_time = header.cache_time;
    
    return true;
}

bool DisassemblyCache::put_block(const std::string& file_hash, uint64_t address,
                                  const DisassemblyBlock& block) {
    std::string path = get_entry_path(file_hash, address);
    
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    
    auto now = std::chrono::system_clock::now();
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    
    auto insns_blob = serialize_instructions(block.instructions);
    
    CacheEntryHeader header;
    std::memcpy(header.magic, CACHE_MAGIC, 4);
    header.version = CACHE_VERSION;
    header.address = block.address;
    header.size = block.size;
    header.raw_bytes_len = static_cast<uint32_t>(block.raw_bytes.size());
    header.insns_len = static_cast<uint32_t>(insns_blob.size());
    header.cache_time = timestamp;
    
    // Compute checksum (placeholder - compute over data portion)
    header.checksum = 0;
    
    file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    
    if (!block.raw_bytes.empty()) {
        file.write(reinterpret_cast<const char*>(block.raw_bytes.data()), block.raw_bytes.size());
    }
    
    if (!insns_blob.empty()) {
        file.write(reinterpret_cast<const char*>(insns_blob.data()), insns_blob.size());
    }
    
    return file.good();
}

bool DisassemblyCache::put_blocks_batch(const std::string& file_hash,
                                         const std::vector<DisassemblyBlock>& blocks) {
    bool success = true;
    for (const auto& block : blocks) {
        if (!put_block(file_hash, block.address, block)) {
            success = false;
        }
    }
    return success;
}

bool DisassemblyCache::invalidate_file(const std::string& file_hash) {
    std::string prefix = file_hash + "_";
    if (!std::filesystem::exists(cache_path_)) return true;
    for (const auto& entry : std::filesystem::directory_iterator(cache_path_)) {
        if (!entry.is_regular_file()) continue;
        std::string name = entry.path().filename().string();
        if (name.find(prefix) == 0) {
            std::filesystem::remove(entry.path());
        }
    }
    return true;
}

DisassemblyCache::Stats DisassemblyCache::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Stats stats;
    if (!std::filesystem::exists(cache_path_)) return stats;
    
    std::filesystem::file_time_type oldest = {};
    std::filesystem::file_time_type newest = {};
    bool first = true;
    
    for (const auto& entry : std::filesystem::directory_iterator(cache_path_)) {
        if (!entry.is_regular_file()) continue;
        stats.total_entries++;
        stats.total_bytes += entry.file_size();
        
        auto lwt = entry.last_write_time();
        if (first) {
            oldest = newest = lwt;
            first = false;
        } else {
            if (lwt < oldest) oldest = lwt;
            if (lwt > newest) newest = lwt;
        }
    }
    
    if (!first) {
        auto now_sys = std::chrono::system_clock::now();
        auto now_file = std::filesystem::file_time_type::clock::now();
        auto diff = now_sys.time_since_epoch() - now_file.time_since_epoch();
        
        auto oldest_sys = std::chrono::time_point<std::chrono::system_clock>(
            oldest.time_since_epoch() + diff);
        auto newest_sys = std::chrono::time_point<std::chrono::system_clock>(
            newest.time_since_epoch() + diff);
        
        stats.oldest_entry = std::chrono::duration_cast<std::chrono::seconds>(
            oldest_sys.time_since_epoch()).count();
        stats.newest_entry = std::chrono::duration_cast<std::chrono::seconds>(
            newest_sys.time_since_epoch()).count();
    }
    return stats;
}

bool DisassemblyCache::vacuum() {
    // For file-based cache, just report success (no vacuum needed)
    return true;
}

bool DisassemblyCache::purge_older_than(uint64_t age_seconds) {
    auto now = std::chrono::system_clock::now();
    uint64_t cutoff = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count() - age_seconds;
    
    if (!std::filesystem::exists(cache_path_)) return true;
    
    auto now_sys = std::chrono::system_clock::now();
    auto now_file = std::filesystem::file_time_type::clock::now();
    auto diff = now_sys.time_since_epoch() - now_file.time_since_epoch();
    
    for (const auto& entry : std::filesystem::directory_iterator(cache_path_)) {
        if (!entry.is_regular_file()) continue;
        
        auto lwt = entry.last_write_time();
        auto sys_time = std::chrono::time_point<std::chrono::system_clock>(
            lwt.time_since_epoch() + diff);
        uint64_t unix_time = std::chrono::duration_cast<std::chrono::seconds>(
            sys_time.time_since_epoch()).count();
        
        if (unix_time < cutoff) {
            std::filesystem::remove(entry.path());
        }
    }
    return true;
}

bool DisassemblyCache::clear() {
    if (!std::filesystem::exists(cache_path_)) return true;
    for (const auto& entry : std::filesystem::directory_iterator(cache_path_)) {
        if (entry.is_regular_file()) {
            std::filesystem::remove(entry.path());
        }
    }
    return true;
}

std::string DisassemblyCache::path() const {
    return cache_path_;
}

// ── Global Instance ─────────────────────────────────────────────────────────

DisassemblyCache& get_disassembly_cache() {
    static DisassemblyCache cache;
    return cache;
}

} // namespace atlus
