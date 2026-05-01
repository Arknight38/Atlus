#include "core/ir_serialization.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <fstream>
#include <numeric>

#include "core/sha256.h"

namespace atlus::ir {

// ── Entity Type Tags ─────────────────────────────────────────────────────────

enum class EntityType : uint8_t {
    Section = 1,
    Function = 2,
    BasicBlock = 3,
    Instruction = 4,
    Symbol = 5,
    Type = 6,
    XRef = 7
};

// ── Binary I/O Helpers ───────────────────────────────────────────────────────

static bool write_u8(FILE* f, uint8_t v) {
    return fwrite(&v, 1, 1, f) == 1;
}

static bool write_u32(FILE* f, uint32_t v) {
    return fwrite(&v, 4, 1, f) == 1;
}

static bool write_u64(FILE* f, uint64_t v) {
    return fwrite(&v, 8, 1, f) == 1;
}

static bool write_bytes(FILE* f, const void* data, size_t len) {
    return fwrite(data, 1, len, f) == len;
}

static bool write_string(FILE* f, const std::string& s) {
    if (!write_u32(f, static_cast<uint32_t>(s.size()))) return false;
    if (s.empty()) return true;
    return write_bytes(f, s.data(), s.size());
}

static bool read_u8(FILE* f, uint8_t& v) {
    return fread(&v, 1, 1, f) == 1;
}

static bool read_u32(FILE* f, uint32_t& v) {
    return fread(&v, 4, 1, f) == 1;
}

static bool read_u64(FILE* f, uint64_t& v) {
    return fread(&v, 8, 1, f) == 1;
}

static bool read_bytes(FILE* f, void* data, size_t len) {
    return fread(data, 1, len, f) == len;
}

static bool read_string(FILE* f, std::string& s) {
    uint32_t len = 0;
    if (!read_u32(f, len)) return false;
    if (len == 0) {
        s.clear();
        return true;
    }
    s.resize(len);
    return read_bytes(f, s.data(), len);
}

// ── CRC32 Checksum ───────────────────────────────────────────────────────────

static uint32_t crc32_table[256];
static bool crc32_initialized = false;

static void init_crc32() {
    if (crc32_initialized) return;
    for (int i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
        crc32_table[i] = crc;
    }
    crc32_initialized = true;
}

static uint32_t compute_crc32(const uint8_t* data, size_t len) {
    init_crc32();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    }
    return ~crc;
}

// ── SHA-256 Implementation ─────────────────────────────────────────────────

std::array<uint8_t, 32> compute_file_hash(const std::string& file_path) {
    return sha256_file(file_path);
}

bool verify_binary_integrity(const std::string& file_path, const std::array<uint8_t, 32>& expected_hash) {
    auto actual_hash = compute_file_hash(file_path);
    return actual_hash == expected_hash;
}

// ── Entity Serialization ───────────────────────────────────────────────────

static bool serialize_address(FILE* f, const Address& addr) {
    return write_u64(f, addr.offset) &&
           write_u8(f, static_cast<uint8_t>(addr.space));
}

static bool deserialize_address(FILE* f, Address& addr) {
    uint64_t offset = 0;
    uint8_t space = 0;
    if (!read_u64(f, offset) || !read_u8(f, space)) return false;
    addr.offset = offset;
    addr.space = static_cast<Address::Space>(space);
    return true;
}

static bool serialize_id(FILE* f, uint32_t id) {
    return write_u32(f, id);
}

static bool deserialize_id(FILE* f, uint32_t& id) {
    return read_u32(f, id);
}

static bool serialize_section(FILE* f, const Section& sec) {
    return serialize_id(f, static_cast<uint32_t>(sec.id)) &&
           serialize_address(f, sec.file_offset) &&
           serialize_address(f, sec.rva) &&
           serialize_address(f, sec.virtual_addr) &&
           write_u64(f, sec.virtual_size) &&
           write_u64(f, sec.raw_size) &&
           write_u32(f, sec.characteristics) &&
           write_string(f, sec.name);
}

static bool deserialize_section(FILE* f, Section& sec) {
    uint32_t id = 0;
    if (!deserialize_id(f, id)) return false;
    sec.id = SectionId(id);
    uint64_t virtual_size = 0, raw_size = 0;
    bool ok = deserialize_address(f, sec.file_offset) &&
              deserialize_address(f, sec.rva) &&
              deserialize_address(f, sec.virtual_addr) &&
              read_u64(f, virtual_size) &&
              read_u64(f, raw_size) &&
              read_u32(f, sec.characteristics) &&
              read_string(f, sec.name);
    sec.virtual_size = static_cast<uint32_t>(virtual_size);
    sec.raw_size = static_cast<uint32_t>(raw_size);
    return ok;
}

static bool serialize_function(FILE* f, const Function& fn) {
    return serialize_id(f, static_cast<uint32_t>(fn.id)) &&
           serialize_id(f, static_cast<uint32_t>(fn.section.value)) &&
           serialize_id(f, static_cast<uint32_t>(fn.symbol.value)) &&
           serialize_address(f, fn.start_address) &&
           serialize_address(f, fn.end_address) &&
           write_u64(f, fn.size_bytes) &&
           write_u8(f, fn.type == Function::Type::Standard ? 1 : 0);
}

static bool deserialize_function(FILE* f, Function& fn) {
    uint32_t id = 0, sec_id = 0, sym_id = 0;
    if (!deserialize_id(f, id)) return false;
    fn.id = FunctionId(id);
    if (!deserialize_id(f, sec_id)) return false;
    fn.section = SectionId(sec_id);
    if (!deserialize_id(f, sym_id)) return false;
    fn.symbol = SymbolId(sym_id);
    uint64_t size_bytes = 0;
    uint8_t is_standard = 0;
    bool ok = deserialize_address(f, fn.start_address) &&
              deserialize_address(f, fn.end_address) &&
              read_u64(f, size_bytes) &&
              read_u8(f, is_standard);
    fn.size_bytes = static_cast<uint32_t>(size_bytes);
    fn.type = (is_standard != 0) ? Function::Type::Standard : Function::Type::Thunk;
    return ok;
}

static bool serialize_basic_block(FILE* f, const BasicBlock& bb) {
    return serialize_id(f, static_cast<uint32_t>(bb.id)) &&
           serialize_id(f, static_cast<uint32_t>(bb.parent_function.value)) &&
           serialize_address(f, bb.start_address) &&
           serialize_address(f, bb.end_address) &&
           write_u64(f, bb.instructions.size()) &&
           write_u64(f, bb.successors.size()) &&
           write_u64(f, bb.predecessors.size());
}

static bool deserialize_basic_block(FILE* f, BasicBlock& bb, std::vector<uint32_t>& insn_ids,
                                     std::vector<uint32_t>& succ_ids, std::vector<uint32_t>& pred_ids) {
    uint32_t id = 0, fn_id = 0;
    if (!deserialize_id(f, id)) return false;
    bb.id = BasicBlockId(id);
    if (!deserialize_id(f, fn_id)) return false;
    bb.parent_function = FunctionId(fn_id);
    uint64_t insn_count = 0, succ_count = 0, pred_count = 0;
    bool ok = deserialize_address(f, bb.start_address) &&
              deserialize_address(f, bb.end_address) &&
              read_u64(f, insn_count) &&
              read_u64(f, succ_count) &&
              read_u64(f, pred_count);
    insn_ids.resize(insn_count);
    succ_ids.resize(succ_count);
    pred_ids.resize(pred_count);
    return ok;
}

static bool serialize_instruction(FILE* f, const Instruction& insn) {
    return serialize_id(f, static_cast<uint32_t>(insn.id)) &&
           serialize_id(f, static_cast<uint32_t>(insn.parent_bb.value)) &&
           serialize_address(f, insn.address) &&
           write_u64(f, insn.length) &&
           write_u64(f, insn.bytes.size) &&
           write_bytes(f, insn.bytes.data, insn.bytes.size) &&
           write_string(f, insn.mnemonic) &&
           write_string(f, insn.operands_text);
}

static bool deserialize_instruction(FILE* f, Instruction& insn) {
    uint32_t id = 0, bb_id = 0;
    if (!deserialize_id(f, id)) return false;
    insn.id = InstructionId(id);
    if (!deserialize_id(f, bb_id)) return false;
    insn.parent_bb = BasicBlockId(bb_id);
    uint64_t length = 0, byte_count = 0;
    bool ok = deserialize_address(f, insn.address) &&
              read_u64(f, length) &&
              read_u64(f, byte_count) &&
              (byte_count <= 16);
    if (!ok) return false;
    insn.length = static_cast<uint32_t>(length);
    insn.bytes.size = static_cast<uint32_t>(byte_count);
    // Note: bytes.data is a pointer to external data - we can't read directly into it
    // For deserialization, we'd need to store the raw bytes elsewhere
    // For now, skip reading the bytes data
    std::vector<uint8_t> temp_bytes(byte_count);
    ok = read_bytes(f, temp_bytes.data(), byte_count) &&
         read_string(f, insn.mnemonic) &&
         read_string(f, insn.operands_text);
    return ok;
}

static bool serialize_symbol(FILE* f, const Symbol& sym) {
    return serialize_id(f, static_cast<uint32_t>(sym.id)) &&
           serialize_address(f, sym.address) &&
           write_u32(f, static_cast<uint32_t>(sym.type)) &&
           write_string(f, sym.name);
}

static bool deserialize_symbol(FILE* f, Symbol& sym) {
    uint32_t id = 0, type = 0;
    if (!deserialize_id(f, id)) return false;
    sym.id = SymbolId(id);
    bool ok = deserialize_address(f, sym.address) &&
              read_u32(f, type) &&
              read_string(f, sym.name);
    sym.type = static_cast<Symbol::Type>(type);
    return ok;
}

static bool serialize_type(FILE* f, const TypeInfo& type) {
    return serialize_id(f, static_cast<uint32_t>(type.id)) &&
           write_u32(f, static_cast<uint32_t>(type.kind)) &&
           write_string(f, type.name) &&
           write_u64(f, type.size_bytes);
}

static bool deserialize_type(FILE* f, TypeInfo& type) {
    uint32_t id = 0, kind = 0;
    if (!deserialize_id(f, id)) return false;
    type.id = TypeId(id);
    uint64_t size_bytes = 0;
    bool ok = read_u32(f, kind) &&
              read_string(f, type.name) &&
              read_u64(f, size_bytes);
    type.size_bytes = static_cast<uint32_t>(size_bytes);
    type.kind = static_cast<TypeInfo::Kind>(kind);
    return ok;
}

static bool serialize_xref(FILE* f, const XRef& xref) {
    return serialize_address(f, xref.from_address) &&
           serialize_address(f, xref.to_address) &&
           write_u32(f, static_cast<uint32_t>(xref.type));
}

static bool deserialize_xref(FILE* f, XRef& xref) {
    uint32_t type = 0;
    bool ok = deserialize_address(f, xref.from_address) &&
              deserialize_address(f, xref.to_address) &&
              read_u32(f, type);
    xref.type = static_cast<XRef::Type>(type);
    return ok;
}

// ── Main Save Function ───────────────────────────────────────────────────────

SerializationResult save_session(const Binary& binary, const std::string& file_path) {
    SerializationResult result;
    result.file_path = file_path;
    
    FILE* f = fopen(file_path.c_str(), "wb");
    if (!f) {
        result.error = "Failed to open file for writing: " + file_path;
        return result;
    }
    
    // Write header
    write_bytes(f, kSessionMagic, 8);  // includes null terminator
    write_u32(f, kSessionVersion);
    write_u32(f, 0);  // flags (reserved)
    
    // Binary hash and metadata
    auto hash = compute_file_hash(binary.path());
    write_bytes(f, hash.data(), 32);
    
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    write_u64(f, static_cast<uint64_t>(timestamp));
    
    write_string(f, binary.path());
    
    // Count entities
    uint32_t section_count = static_cast<uint32_t>(binary.sections().size());
    uint32_t function_count = static_cast<uint32_t>(binary.functions().size());
    
    // We need to collect counts for other entities
    // For now, we'll iterate and serialize directly
    
    // Write section table
    write_u8(f, static_cast<uint8_t>(EntityType::Section));
    write_u32(f, section_count);
    for (uint32_t i = 0; i < section_count; i++) {
        if (auto* sec = binary.get_section(SectionId(i))) {
            serialize_section(f, *sec);
        }
    }
    
    // Write function table
    write_u8(f, static_cast<uint8_t>(EntityType::Function));
    write_u32(f, function_count);
    for (uint32_t i = 0; i < function_count; i++) {
        if (auto* fn = binary.get_function(FunctionId(i))) {
            serialize_function(f, *fn);
        }
    }
    
    // Get all other entities via traversal
    std::vector<const BasicBlock*> bbs;
    std::vector<const Instruction*> insns;
    std::vector<const Symbol*> symbols;
    std::vector<const TypeInfo*> types;
    std::vector<XRef> xrefs;
    
    for (uint32_t i = 0; i < function_count; i++) {
        if (auto* fn = binary.get_function(FunctionId(i))) {
            for (auto bb_id : fn->basic_blocks) {
                if (auto* bb = binary.get_basic_block(bb_id)) {
                    bbs.push_back(bb);
                    for (auto insn_id : bb->instructions) {
                        if (auto* insn = binary.get_instruction(insn_id)) {
                            insns.push_back(insn);
                        }
                    }
                }
            }
        }
    }
    
    // Collect symbols
    // Note: We don't have a direct count, so we'll iterate
    // This is a limitation of the current API - we'd need a symbol iterator
    
    // Write basic blocks
    write_u8(f, static_cast<uint8_t>(EntityType::BasicBlock));
    write_u32(f, static_cast<uint32_t>(bbs.size()));
    for (const auto* bb : bbs) {
        serialize_basic_block(f, *bb);
        // Write instruction IDs
        for (auto insn_id : bb->instructions) {
            write_u32(f, static_cast<uint32_t>(insn_id.value));
        }
        // Write successor IDs
        for (auto succ_id : bb->successors) {
            write_u32(f, static_cast<uint32_t>(succ_id.value));
        }
        // Write predecessor IDs
        for (auto pred_id : bb->predecessors) {
            write_u32(f, static_cast<uint32_t>(pred_id.value));
        }
    }
    
    // Write instructions
    write_u8(f, static_cast<uint8_t>(EntityType::Instruction));
    write_u32(f, static_cast<uint32_t>(insns.size()));
    for (const auto* insn : insns) {
        serialize_instruction(f, *insn);
    }
    
    // TODO: Write symbols, types, xrefs
    // For now, write empty sections
    write_u8(f, static_cast<uint8_t>(EntityType::Symbol));
    write_u32(f, 0);
    
    write_u8(f, static_cast<uint8_t>(EntityType::Type));
    write_u32(f, 0);
    
    write_u8(f, static_cast<uint8_t>(EntityType::XRef));
    write_u32(f, 0);
    
    // Footer - file size
    long file_size = ftell(f);
    write_u64(f, static_cast<uint64_t>(file_size));
    
    // Compute and write checksum (from start to current position)
    // For simplicity, we'll skip the actual CRC and just write a placeholder
    // A proper implementation would rewind and compute over all data
    write_u32(f, 0xDEADBEEF);  // Placeholder checksum
    
    fclose(f);
    
    result.success = true;
    result.bytes_written = static_cast<size_t>(file_size);
    return result;
}

// ── Main Load Function ───────────────────────────────────────────────────────

DeserializationResult load_session(const std::string& file_path) {
    DeserializationResult result;
    result.file_path = file_path;
    
    FILE* f = fopen(file_path.c_str(), "rb");
    if (!f) {
        result.error = "Failed to open file: " + file_path;
        return result;
    }
    
    // Read and verify header
    char magic[8] = {};
    if (!read_bytes(f, magic, 8) || strncmp(magic, kSessionMagic, 7) != 0) {
        result.error = "Invalid session file format (bad magic)";
        fclose(f);
        return result;
    }
    
    uint32_t version = 0;
    if (!read_u32(f, version) || version != kSessionVersion) {
        result.error = "Unsupported session file version: " + std::to_string(version);
        fclose(f);
        return result;
    }
    
    uint32_t flags = 0;
    read_u32(f, flags);
    
    // Read binary hash
    read_bytes(f, result.original_binary_hash.data(), 32);
    
    // Read timestamp
    read_u64(f, result.timestamp);
    
    // Read original binary path
    read_string(f, result.original_binary_path);
    
    // Create new Binary
    auto binary = std::make_unique<Binary>("", 0, false);
    
    // Read entity sections
    bool done = false;
    while (!done && !feof(f)) {
        uint8_t type_tag = 0;
        if (!read_u8(f, type_tag)) break;
        
        uint32_t count = 0;
        if (!read_u32(f, count)) break;
        
        EntityType type = static_cast<EntityType>(type_tag);
        
        switch (type) {
            case EntityType::Section: {
                for (uint32_t i = 0; i < count; i++) {
                    Section sec;
                    if (deserialize_section(f, sec)) {
                        // Re-create with proper ID assignment
                        Section new_sec = sec;
                        binary->create_section(new_sec);
                    }
                }
                result.sections_loaded = count;
                break;
            }
            case EntityType::Function: {
                for (uint32_t i = 0; i < count; i++) {
                    Function fn;
                    if (deserialize_function(f, fn)) {
                        Function new_fn = fn;
                        binary->create_function(new_fn);
                    }
                }
                result.functions_loaded = count;
                break;
            }
            case EntityType::BasicBlock: {
                for (uint32_t i = 0; i < count; i++) {
                    BasicBlock bb;
                    std::vector<uint32_t> insn_ids, succ_ids, pred_ids;
                    if (deserialize_basic_block(f, bb, insn_ids, succ_ids, pred_ids)) {
                        // Read instruction IDs
                        for (auto id : insn_ids) {
                            bb.instructions.push_back(InstructionId(id));
                        }
                        // Read successor IDs
                        for (auto id : succ_ids) {
                            bb.successors.push_back(BasicBlockId(id));
                        }
                        // Read predecessor IDs
                        for (auto id : pred_ids) {
                            bb.predecessors.push_back(BasicBlockId(id));
                        }
                        BasicBlock new_bb = bb;
                        binary->create_basic_block(new_bb);
                    }
                }
                result.basic_blocks_loaded = count;
                break;
            }
            case EntityType::Instruction: {
                for (uint32_t i = 0; i < count; i++) {
                    Instruction insn;
                    if (deserialize_instruction(f, insn)) {
                        Instruction new_insn = insn;
                        binary->create_instruction(new_insn);
                    }
                }
                result.instructions_loaded = count;
                break;
            }
            case EntityType::Symbol: {
                for (uint32_t i = 0; i < count; i++) {
                    Symbol sym;
                    if (deserialize_symbol(f, sym)) {
                        Symbol new_sym = sym;
                        binary->create_symbol(new_sym);
                    }
                }
                result.symbols_loaded = count;
                break;
            }
            case EntityType::Type: {
                for (uint32_t i = 0; i < count; i++) {
                    TypeInfo type;
                    if (deserialize_type(f, type)) {
                        TypeInfo new_type = type;
                        binary->create_type(new_type);
                    }
                }
                result.types_loaded = count;
                break;
            }
            case EntityType::XRef: {
                for (uint32_t i = 0; i < count; i++) {
                    XRef xref;
                    if (deserialize_xref(f, xref)) {
                        binary->register_xref(xref);
                    }
                }
                result.xrefs_loaded = count;
                break;
            }
            default: {
                result.error = "Unknown entity type: " + std::to_string(type_tag);
                fclose(f);
                return result;
            }
        }
        
        // Check for footer (peek next byte)
        long pos = ftell(f);
        uint8_t peek = 0;
        if (fread(&peek, 1, 1, f) == 1) {
            // If it's not a valid entity type (0 or > 7), it might be footer
            if (peek == 0 || peek > 7) {
                fseek(f, pos, SEEK_SET);
                done = true;
            } else {
                fseek(f, pos, SEEK_SET);  // Put it back
            }
        } else {
            done = true;
        }
    }
    
    // Read footer
    uint64_t file_size = 0;
    read_u64(f, file_size);
    
    uint32_t checksum = 0;
    read_u32(f, checksum);
    
    fclose(f);
    
    result.binary = std::move(binary);
    result.success = true;
    result.bytes_read = static_cast<size_t>(file_size);
    
    return result;
}

// ── Verification ──────────────────────────────────────────────────────────────

bool verify_session_file(const std::string& file_path) {
    FILE* f = fopen(file_path.c_str(), "rb");
    if (!f) return false;
    
    char magic[8] = {};
    if (!read_bytes(f, magic, 8)) {
        fclose(f);
        return false;
    }
    
    if (strncmp(magic, kSessionMagic, 7) != 0) {
        fclose(f);
        return false;
    }
    
    uint32_t version = 0;
    if (!read_u32(f, version) || version != kSessionVersion) {
        fclose(f);
        return false;
    }
    
    fclose(f);
    return true;
}

bool is_session_version_supported(uint32_t version) {
    return version == kSessionVersion;
}

std::optional<SessionInfo> get_session_info(const std::string& file_path) {
    FILE* f = fopen(file_path.c_str(), "rb");
    if (!f) return std::nullopt;
    
    // Seek to end to get file size
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char magic[8] = {};
    if (!read_bytes(f, magic, 8) || strncmp(magic, kSessionMagic, 7) != 0) {
        fclose(f);
        return std::nullopt;
    }
    
    uint32_t version = 0;
    if (!read_u32(f, version)) {
        fclose(f);
        return std::nullopt;
    }
    
    uint32_t flags = 0;
    read_u32(f, flags);
    
    SessionInfo info;
    info.version = version;
    info.file_size = file_size;
    
    std::array<uint8_t, 32> hash;
    read_bytes(f, hash.data(), 32);
    info.original_binary_hash = hash;
    
    read_u64(f, info.timestamp);
    read_string(f, info.original_binary_path);
    
    // Count entities by scanning
    info.total_entities = 0;
    while (!feof(f)) {
        uint8_t type = 0;
        if (!read_u8(f, type)) break;
        uint32_t count = 0;
        if (!read_u32(f, count)) break;
        info.total_entities += count;
        
        // Skip entity data (rough approximation)
        // This is simplified - proper implementation would know sizes
        break;  // For now, just break after first
    }
    
    fclose(f);
    return info;
}

} // namespace atlus::ir
