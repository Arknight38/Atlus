#pragma once
#include "core/ir.h"
#include <string>
#include <optional>
#include <vector>
#include <cstdint>

namespace atlus::ir {

// ── Session File Format v1 ───────────────────────────────────────────────────
//
// Binary format for persisting IR analysis state:
//
// Header (64 bytes):
//   - Magic: "ATLUSv1" (7 bytes) + null
//   - Version: uint32_t (1)
//   - Flags: uint32_t
//   - Binary hash: 32 bytes (SHA-256)
//   - Timestamp: uint64_t
//   - Original path length: uint32_t
//   - Original path: variable
//
// Entity Sections:
//   - Section count: uint32_t
//   - For each section:
//     - Type tag: uint8_t (1=Section, 2=Function, 3=BB, 4=Insn, 5=Symbol, 6=Type, 7=XRef)
//     - Entity count: uint32_t
//     - Serialized entities (variable size)
//
// Footer:
//   - Entity section offsets: uint32_t[count]
//   - Total size: uint64_t
//   - Checksum: uint32_t (CRC32)

// ── Configuration ─────────────────────────────────────────────────────────────

constexpr char kSessionMagic[] = "ATLUSv1";
constexpr uint32_t kSessionVersion = 1;

// ── Result Types ─────────────────────────────────────────────────────────────

struct SerializationResult {
    bool success = false;
    std::string error;
    std::string file_path;
    size_t bytes_written = 0;
    
    bool ok() const { return success; }
};

struct DeserializationResult {
    bool success = false;
    std::string error;
    std::string file_path;
    size_t bytes_read = 0;
    
    // Loaded data
    std::unique_ptr<Binary> binary;
    
    // Verification info
    std::string original_binary_path;
    std::array<uint8_t, 32> original_binary_hash;
    uint64_t timestamp = 0;
    
    // Stats
    uint32_t sections_loaded = 0;
    uint32_t functions_loaded = 0;
    uint32_t basic_blocks_loaded = 0;
    uint32_t instructions_loaded = 0;
    uint32_t symbols_loaded = 0;
    uint32_t types_loaded = 0;
    uint32_t xrefs_loaded = 0;
    
    bool ok() const { return success; }
};

// ── Main API ─────────────────────────────────────────────────────────────────

/**
 * Save a Binary (IR analysis results) to a session file.
 * 
 * @param binary The IR binary to serialize
 * @param file_path Output file path
 * @return Serialization result with status and metadata
 */
SerializationResult save_session(const Binary& binary, const std::string& file_path);

/**
 * Load a Binary from a session file.
 * 
 * @param file_path Session file to load
 * @return Deserialization result with loaded binary or error
 */
DeserializationResult load_session(const std::string& file_path);

/**
 * Verify a session file without fully loading it.
 * Checks magic, version, and checksum.
 * 
 * @param file_path Session file to verify
 * @return true if file is valid and can be loaded
 */
bool verify_session_file(const std::string& file_path);

/**
 * Get session file info without loading.
 * 
 * @param file_path Session file
 * @return Optional containing metadata, or nullopt if invalid
 */
struct SessionInfo {
    uint32_t version = 0;
    uint64_t timestamp = 0;
    std::string original_binary_path;
    std::array<uint8_t, 32> original_binary_hash;
    size_t total_entities = 0;
    size_t file_size = 0;
};
std::optional<SessionInfo> get_session_info(const std::string& file_path);

// ── Binary Hash Utilities ────────────────────────────────────────────────────

/**
 * Compute SHA-256 hash of a file.
 * Used for binary integrity verification when saving/loading sessions.
 */
std::array<uint8_t, 32> compute_file_hash(const std::string& file_path);

/**
 * Compare a file's hash with expected value.
 * Used to verify the original binary hasn't changed.
 */
bool verify_binary_integrity(const std::string& file_path, const std::array<uint8_t, 32>& expected_hash);

// ── Legacy/Compatibility ───────────────────────────────────────────────────

/**
 * Check if a session file version is supported.
 */
bool is_session_version_supported(uint32_t version);

} // namespace atlus::ir
