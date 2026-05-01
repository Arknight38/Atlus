#include "core/structure_analyzer.h"
#include <cstring>
#include <algorithm>

namespace atlus {

// ── Memory Reading Helpers ─────────────────────────────────────────────────

uint64_t StructureAnalyzer::read_pointer(const uint8_t* data, size_t offset, bool is_64bit) {
    if (is_64bit) {
        return *reinterpret_cast<const uint64_t*>(data + offset);
    } else {
        return *reinterpret_cast<const uint32_t*>(data + offset);
    }
}

bool StructureAnalyzer::is_valid_code_pointer(uint64_t ptr, const ir::Binary& binary) {
    // Check if pointer points to executable code
    for (const auto& section : binary.sections()) {
        if (section->is_executable) {
            uint64_t start = section->virtual_addr.offset;
            uint64_t end = start + section->virtual_size;
            if (ptr >= start && ptr < end) {
                return true;
            }
        }
    }
    return false;
}

bool StructureAnalyzer::is_valid_data_pointer(uint64_t ptr, const ir::Binary& binary) {
    // Check if pointer points to data
    for (const auto& section : binary.sections()) {
        if (!section->is_executable) {
            uint64_t start = section->virtual_addr.offset;
            uint64_t end = start + section->virtual_size;
            if (ptr >= start && ptr < end) {
                return true;
            }
        }
    }
    return false;
}

// ── VTable Detection ───────────────────────────────────────────────────────

std::optional<DetectedStructure> StructureAnalyzer::analyze_potential_vtable(
    uint64_t addr,
    const ir::Binary& binary,
    int min_funcs
) {
    DetectedStructure vtable;
    vtable.type = StructureType::VTable;
    vtable.address = addr;
    vtable.element_size = binary.is_64bit() ? 8 : 4;
    
    // Try to read function pointers from this address
    std::vector<uint64_t> func_ptrs;
    
    for (const auto& section : binary.sections()) {
        if (addr < section->virtual_addr.offset || addr >= section->virtual_addr.offset + section->virtual_size) {
            continue;
        }
        
        // Note: Section raw data access requires BinaryFile/PEInfo
        // This is a placeholder - actual implementation needs section data
        size_t offset = static_cast<size_t>(addr - section->virtual_addr.offset);
        size_t max_entries = std::min(static_cast<size_t>(128), 
                                      (section->virtual_size - offset) / vtable.element_size);
        
        for (size_t i = 0; i < max_entries; ++i) {
            // Placeholder - need actual section data from BinaryFile
            uint64_t ptr = 0; // read_pointer(section_data + offset + (i * vtable.element_size), binary.is_64bit());
            
            // Check if it's a valid code pointer
            if (is_valid_code_pointer(ptr, binary)) {
                func_ptrs.push_back(ptr);
                
                StructureMember member;
                member.offset = i * vtable.element_size;
                member.size = vtable.element_size;
                member.type = "func_ptr";
                member.value = ptr;
                member.comment = "Virtual function " + std::to_string(i);
                vtable.members.push_back(member);
            } else if (ptr == 0) {
                // Null terminator - valid end of vtable
                break;
            } else {
                // Invalid pointer - probably end of vtable
                break;
            }
        }
        break;
    }
    
    if (func_ptrs.size() < static_cast<size_t>(min_funcs)) {
        return std::nullopt;
    }
    
    vtable.element_count = func_ptrs.size();
    vtable.size = vtable.element_count * vtable.element_size;
    vtable.confidence = 70;  // Base confidence
    
    // Higher confidence if RTTI pointer precedes vtable (MSVC pattern)
    // In MSVC: [RTTI ptr] [-1 offset] [vftable...]
    // So vtable at X is often preceded by pointer to type info at X-8 (x64) or X-4 (x86)
    
    char name_buf[64];
    std::snprintf(name_buf, sizeof(name_buf), "vtable_%llX", (unsigned long long)addr);
    vtable.name = name_buf;
    
    return vtable;
}

std::vector<DetectedStructure> StructureAnalyzer::find_vtables(const ir::Binary& binary) {
    std::vector<DetectedStructure> vtables;
    
    // Scan data sections for patterns that look like vtables
    for (const auto& section : binary.sections()) {
        if (section->is_executable) continue;  // Skip code sections
        
        size_t ptr_size = binary.is_64bit() ? 8 : 4;
        size_t scan_step = ptr_size;
        
        // Note: Actual implementation needs section data from BinaryFile
        for (size_t offset = 0; offset + ptr_size <= section->virtual_size; offset += scan_step) {
            uint64_t potential_vtable_addr = section->virtual_addr.offset + offset;
            
            // Try to analyze as vtable
            auto vtable = analyze_potential_vtable(potential_vtable_addr, binary, 2);
            if (vtable) {
                vtables.push_back(*vtable);
                // Skip past this vtable to avoid overlapping detections
                offset += (vtable->element_count - 1) * ptr_size;
            }
        }
    }
    
    return vtables;
}

// ── RTTI Detection (MSVC Specific) ──────────────────────────────────────

std::optional<DetectedStructure> StructureAnalyzer::parse_msvc_rtti(
    uint64_t rtti_addr,
    const ir::Binary& binary
) {
    // MSVC RTTI Complete Object Locator structure:
    // 0x00: signature (0x0 until VS2015, 0x1 from VS2015 with COH)
    // 0x04: offset (0 for single inheritance)
    // 0x08: cdOffset (0 for single inheritance)
    // 0x0C: pTypeDescriptor (rva)
    // 0x10: pClassDescriptor (rva)
    // 0x14/0x18: pSelf (rva, x86/x64)
    
    DetectedStructure rtti;
    rtti.type = StructureType::RTTIComplete;
    rtti.address = rtti_addr;
    rtti.confidence = 60;
    
    // Simplified: just detect by checking if it looks like valid RTTI
    // Full implementation would parse Type Descriptor and validate signature
    
    char name_buf[64];
    std::snprintf(name_buf, sizeof(name_buf), "RTTI_%llX", (unsigned long long)rtti_addr);
    rtti.name = name_buf;
    
    return rtti;
}

std::vector<DetectedStructure> StructureAnalyzer::find_rtti(const ir::Binary& binary) {
    std::vector<DetectedStructure> rtti_entries;
    
    // Look for RTTI in .rdata section
    // MSVC places RTTI descriptors in .rdata
    for (const auto& section : binary.sections()) {
        // Check if section name contains rdata or data
        if (section->name.find("rdata") == std::string::npos &&
            section->name.find(".data") == std::string::npos) {
            continue;
        }
        
        // Scan for RTTI signatures
        // Simplified: look for patterns that might be RTTI
        // Full implementation would parse and validate the structures
    }
    
    return rtti_entries;
}

// ── Function Table Detection ─────────────────────────────────────────────

std::vector<DetectedStructure> StructureAnalyzer::find_function_tables(const ir::Binary& binary) {
    std::vector<DetectedStructure> tables;
    
    // Similar to vtable detection but for non-virtual function pointer arrays
    // e.g., callback tables, dispatch tables
    
    return tables;
}

// ── TLS Callback Detection ────────────────────────────────────────────────

std::vector<DetectedStructure> StructureAnalyzer::find_tls_callbacks(const ir::Binary& binary) {
    std::vector<DetectedStructure> callbacks;
    
    // TLS callback table is in the TLS directory
    // It's a null-terminated array of function pointers
    
    // Note: tls_directory_addr not available in current IR - needs PEInfo
    // if (binary.tls_directory_addr == 0) return callbacks;
    
    // For PE files, TLS directory contains:
    // StartAddressOfRawData
    // EndAddressOfRawData
    // AddressOfIndex
    // AddressOfCallBacks <- Points to callback array
    // SizeOfZeroFill
    // Characteristics
    
    // Would need to parse PE header to get this
    // Simplified stub implementation
    
    return callbacks;
}

// ── Main Analysis ─────────────────────────────────────────────────────────

StructureAnalysisResult StructureAnalyzer::analyze(const ir::Binary& binary) {
    StructureAnalysisResult result;
    
    // Find all structure types
    auto vtables = find_vtables(binary);
    auto rtti = find_rtti(binary);
    auto func_tables = find_function_tables(binary);
    auto tls = find_tls_callbacks(binary);
    
    // Combine all structures
    result.structures.reserve(vtables.size() + rtti.size() + func_tables.size() + tls.size());
    result.structures.insert(result.structures.end(), vtables.begin(), vtables.end());
    result.structures.insert(result.structures.end(), rtti.begin(), rtti.end());
    result.structures.insert(result.structures.end(), func_tables.begin(), func_tables.end());
    result.structures.insert(result.structures.end(), tls.begin(), tls.end());
    
    // Build filtered lists
    for (const auto& s : result.structures) {
        switch (s.type) {
            case StructureType::VTable:
                result.vtables.push_back(&s);
                break;
            case StructureType::RTTIComplete:
            case StructureType::RTTIClassHierarchy:
                result.rtti_entries.push_back(&s);
                break;
            case StructureType::FunctionPtrArray:
                result.func_tables.push_back(&s);
                break;
            default:
                break;
        }
    }
    
    result.success = true;
    result.structure_count = result.structures.size();
    
    return result;
}

// ── Display Helpers ───────────────────────────────────────────────────────

const char* structure_type_name(StructureType type) {
    switch (type) {
        case StructureType::VTable: return "Virtual Table";
        case StructureType::RTTIComplete: return "RTTI Complete";
        case StructureType::RTTIClassHierarchy: return "RTTI Class Hierarchy";
        case StructureType::FunctionPtrArray: return "Function Pointer Array";
        case StructureType::StringTable: return "String Table";
        case StructureType::JumpTable: return "Jump Table";
        case StructureType::ImportTable: return "Import Table";
        case StructureType::ExportTable: return "Export Address Table";
        case StructureType::TLSCallbackTable: return "TLS Callback Table";
        default: return "Unknown";
    }
}

const char* structure_icon(StructureType type) {
    switch (type) {
        case StructureType::VTable: return "V";
        case StructureType::RTTIComplete:
        case StructureType::RTTIClassHierarchy: return "R";
        case StructureType::FunctionPtrArray: return "F";
        case StructureType::StringTable: return "S";
        case StructureType::JumpTable: return "J";
        case StructureType::ImportTable: return "I";
        case StructureType::ExportTable: return "E";
        case StructureType::TLSCallbackTable: return "T";
        default: return "?";
    }
}

} // namespace atlus
