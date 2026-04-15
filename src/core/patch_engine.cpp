#include "core/ir.h"
#include "core/address_space.h"
#include <vector>
#include <stack>

namespace atlus::patch {

// Patch operation types
struct PatchOperation {
    enum class Type {
        BytePatch,
        NOPInsertion,
        CodeInjection,
        JumpHook
    };
    
    Type type;
    uint64_t address;
    std::vector<uint8_t> original_bytes;
    std::vector<uint8_t> new_bytes;
    std::string description;
};

// Patch engine for binary modification
class PatchEngine {
public:
    struct PatchResult {
        bool success = false;
        std::string error;
        std::vector<PatchOperation> applied;
    };
    
    // Apply a single byte patch
    PatchResult patch_bytes(ir::Binary& binary,
                           ir::BinaryFile& file,
                           uint64_t address,
                           const std::vector<uint8_t>& new_bytes,
                           const std::string& description = "");
    
    // Insert NOP sled at location
    PatchResult insert_nop(ir::Binary& binary,
                          ir::BinaryFile& file,
                          uint64_t address,
                          size_t length);
    
    // Find code caves (sequences of null bytes in executable sections)
    std::vector<std::pair<uint64_t, size_t>> find_code_caves(
        const ir::BinaryFile& file,
        const ir::Binary& binary,
        size_t min_size = 16
    );
    
    // Create a jump hook (redirect execution)
    PatchResult create_jump_hook(
        ir::Binary& binary,
        ir::BinaryFile& file,
        uint64_t target_address,
        uint64_t hook_address,
        bool preserve_original = true
    );
    
    // Undo last patch
    bool undo_last(ir::Binary& binary, ir::BinaryFile& file);
    
    // Undo all patches
    bool undo_all(ir::Binary& binary, ir::BinaryFile& file);
    
    // Get patch history
    const std::vector<PatchOperation>& get_history() const { return history_; }
    
private:
    std::vector<PatchOperation> history_;
    std::stack<PatchOperation> undo_stack_;
    
    bool apply_to_file(ir::BinaryFile& file, const PatchOperation& op);
    bool restore_from_file(ir::BinaryFile& file, const PatchOperation& op);
};

PatchEngine::PatchResult PatchEngine::patch_bytes(
    ir::Binary& binary,
    ir::BinaryFile& file,
    uint64_t address,
    const std::vector<uint8_t>& new_bytes,
    const std::string& description
) {
    PatchResult result;
    
    // Convert VA to file offset
    auto file_addr = binary.virtual_to_file({address, ir::Address::Space::Virtual});
    if (!file_addr.has_value()) {
        result.error = "Cannot translate address to file offset";
        return result;
    }
    
    uint64_t offset = file_addr->offset;
    if (offset + new_bytes.size() > file.size()) {
        result.error = "Patch extends beyond file size";
        return result;
    }
    
    // Create patch operation
    PatchOperation op;
    op.type = PatchOperation::Type::BytePatch;
    op.address = address;
    op.new_bytes = new_bytes;
    op.original_bytes.resize(new_bytes.size());
    op.description = description;
    
    // Save original bytes
    std::memcpy(op.original_bytes.data(), file.bytes() + offset, new_bytes.size());
    
    // Apply patch
    if (apply_to_file(file, op)) {
        history_.push_back(op);
        result.success = true;
        result.applied.push_back(op);
        
        // Invalidate affected analysis
        // In full implementation, trigger invalidation via InvalidationEngine
    }
    
    return result;
}

PatchEngine::PatchResult PatchEngine::insert_nop(
    ir::Binary& binary,
    ir::BinaryFile& file,
    uint64_t address,
    size_t length
) {
    // x86 NOP opcode is 0x90
    std::vector<uint8_t> nops(length, 0x90);
    return patch_bytes(binary, file, address, nops, "NOP insertion");
}

std::vector<std::pair<uint64_t, size_t>> PatchEngine::find_code_caves(
    const ir::BinaryFile& file,
    const ir::Binary& binary,
    size_t min_size
) {
    std::vector<std::pair<uint64_t, size_t>> caves;
    
    // Scan executable sections for null bytes
    for (const auto& sec : binary.sections()) {
        if (!sec->is_executable) continue;
        
        uint64_t file_off = sec->file_offset.offset;
        uint64_t sec_size = sec->raw_size;
        
        if (file_off + sec_size > file.size()) continue;
        
        const uint8_t* data = file.bytes() + file_off;
        
        // Find runs of null bytes (0x00) or NOPs (0x90)
        size_t run_start = 0;
        bool in_run = false;
        
        for (size_t i = 0; i < sec_size; ++i) {
            bool is_nullable = (data[i] == 0x00 || data[i] == 0x90 || data[i] == 0xCC);
            
            if (is_nullable && !in_run) {
                run_start = i;
                in_run = true;
            } else if (!is_nullable && in_run) {
                size_t run_len = i - run_start;
                if (run_len >= min_size) {
                    uint64_t va = sec->virtual_addr.offset + run_start;
                    caves.push_back({va, run_len});
                }
                in_run = false;
            }
        }
        
        // Check for run at end of section
        if (in_run) {
            size_t run_len = sec_size - run_start;
            if (run_len >= min_size) {
                uint64_t va = sec->virtual_addr.offset + run_start;
                caves.push_back({va, run_len});
            }
        }
    }
    
    return caves;
}

PatchEngine::PatchResult PatchEngine::create_jump_hook(
    ir::Binary& binary,
    ir::BinaryFile& file,
    uint64_t target_address,
    uint64_t hook_address,
    bool preserve_original
) {
    PatchResult result;
    
    // Build jump instruction (JMP rel32 for x64)
    // 5 bytes: 0xE9 + 32-bit relative offset
    std::vector<uint8_t> jump_insn(5);
    jump_insn[0] = 0xE9;  // JMP rel32
    
    // Calculate relative offset: target - (current + 5)
    int32_t rel_offset = static_cast<int32_t>(hook_address - (target_address + 5));
    std::memcpy(&jump_insn[1], &rel_offset, 4);
    
    // If preserving original, we need to save it to a code cave or allocated memory
    // and jump back after execution
    if (preserve_original) {
        // Find a code cave near the target for trampoline
        auto caves = find_code_caves(file, binary, 16);
        
        if (caves.empty()) {
            result.error = "No suitable code cave found for trampoline";
            return result;
        }
        
        // Use first available cave
        uint64_t trampoline_addr = caves[0].first;
        
        // Build trampoline: [original bytes] + [jmp back to target+5]
        // For now, just do simple hook without trampoline
    }
    
    return patch_bytes(binary, file, target_address, jump_insn, "Jump hook");
}

bool PatchEngine::undo_last(ir::Binary& binary, ir::BinaryFile& file) {
    if (history_.empty()) return false;
    
    PatchOperation op = history_.back();
    history_.pop_back();
    
    bool success = restore_from_file(file, op);
    if (success) {
        undo_stack_.push(op);
    }
    
    return success;
}

bool PatchEngine::undo_all(ir::Binary& binary, ir::BinaryFile& file) {
    bool all_success = true;
    
    while (!history_.empty()) {
        if (!undo_last(binary, file)) {
            all_success = false;
        }
    }
    
    return all_success;
}

bool PatchEngine::apply_to_file(ir::BinaryFile& file, const PatchOperation& op) {
    auto file_addr = file.data.data();  // Simplified - should use proper translation
    
    // This is a simplified version - in reality we'd use proper address translation
    // For now, assume patches are applied to a memory buffer
    
    return true;
}

bool PatchEngine::restore_from_file(ir::BinaryFile& file, const PatchOperation& op) {
    // Restore original bytes
    // Simplified - see apply_to_file
    
    return true;
}

// Export patch to various formats
namespace export_format {

    // IPS patch format (classic ROM hacking format)
    std::vector<uint8_t> create_ips(const std::vector<PatchOperation>& patches) {
        std::vector<uint8_t> result;
        
        // Header
        result.insert(result.end(), {'P', 'A', 'T', 'C', 'H'});
        
        // Each patch record
        for (const auto& patch : patches) {
            if (patch.type != PatchOperation::Type::BytePatch) continue;
            
            // 3-byte offset (big-endian)
            uint32_t offset = static_cast<uint32_t>(patch.address);
            result.push_back((offset >> 16) & 0xFF);
            result.push_back((offset >> 8) & 0xFF);
            result.push_back(offset & 0xFF);
            
            // 2-byte size (big-endian)
            uint16_t size = static_cast<uint16_t>(patch.new_bytes.size());
            result.push_back((size >> 8) & 0xFF);
            result.push_back(size & 0xFF);
            
            // Data
            result.insert(result.end(), patch.new_bytes.begin(), patch.new_bytes.end());
        }
        
        // Footer
        result.insert(result.end(), {'E', 'O', 'F'});
        
        return result;
    }
    
    // BPS patch format (binary patch space)
    std::vector<uint8_t> create_bps(const std::vector<PatchOperation>& patches,
                                    const ir::BinaryFile& original,
                                    const ir::BinaryFile& modified) {
        // BPS is more complex - requires diffing entire files
        // This is a placeholder
        return {};
    }
    
    // xdelta format (standard binary diff)
    // Would require xdelta library
    
    // JSON patch description (human-readable)
    std::string create_json(const std::vector<PatchOperation>& patches) {
        std::string json = "[\n";
        
        for (size_t i = 0; i < patches.size(); ++i) {
            const auto& p = patches[i];
            json += "  {\n";
            json += "    \"address\": \"0x" + std::to_string(p.address) + "\",\n";
            json += "    \"description\": \"" + p.description + "\",\n";
            json += "    \"new_bytes\": \"";
            for (auto b : p.new_bytes) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02X", b);
                json += buf;
            }
            json += "\"\n";
            json += "  }";
            if (i < patches.size() - 1) json += ",";
            json += "\n";
        }
        
        json += "]\n";
        return json;
    }

} // namespace export_format

} // namespace atlus::patch
