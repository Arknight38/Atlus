#include "core/ir_governance.h"
#include "core/md5.h"
#include <cstring>

namespace atlus::ir {

// FunctionGovernance implementation
ContentHash FunctionGovernance::compute_identity(
    QualifiedAddress start_addr,
    const uint8_t* prologue_bytes,
    size_t prologue_len
) {
    MD5Context ctx;
    md5_init(&ctx);
    
    // Hash the start address (RVA portion, ASLR-invariant)
    uint64_t rva = start_addr.offset;
    uint8_t addr_bytes[8];
    for (int i = 0; i < 8; ++i) {
        addr_bytes[i] = (rva >> (i * 8)) & 0xFF;
    }
    md5_update(&ctx, addr_bytes, 8);
    
    // Hash the prologue bytes
    if (prologue_bytes && prologue_len > 0) {
        md5_update(&ctx, prologue_bytes, prologue_len);
    }
    
    ContentHash hash;
    md5_final(hash.bytes, &ctx);
    return hash;
}

// BasicBlockGovernance implementation  
ContentHash BasicBlockGovernance::compute_identity(
    const std::vector<InstructionId>& instructions,
    const Binary& binary
) {
    MD5Context ctx;
    md5_init(&ctx);
    
    // Hash each instruction's content
    for (InstructionId insn_id : instructions) {
        const Instruction* insn = binary.get_instruction(insn_id);
        if (insn && insn->bytes.data) {
            md5_update(&ctx, insn->bytes.data, insn->bytes.size);
        }
    }
    
    ContentHash hash;
    md5_final(hash.bytes, &ctx);
    return hash;
}

// InstructionGovernance implementation
ContentHash InstructionGovernance::compute_identity(
    QualifiedAddress addr,
    const uint8_t* bytes,
    size_t len
) {
    return ContentHash::of_instruction_sequence(bytes, len, addr.offset);
}

// SymbolGovernance implementation
ContentHash SymbolGovernance::compute_identity_by_name(const std::string& name) {
    return ContentHash::from_string(name);
}

ContentHash SymbolGovernance::compute_identity_by_address(QualifiedAddress addr) {
    uint8_t addr_bytes[8];
    for (int i = 0; i < 8; ++i) {
        addr_bytes[i] = (addr.offset >> (i * 8)) & 0xFF;
    }
    return ContentHash::from_data(addr_bytes, 8);
}

// XRefGovernance implementation
ContentHash XRefGovernance::compute_identity(
    QualifiedAddress from,
    QualifiedAddress to,
    XRef::Type type
) {
    MD5Context ctx;
    md5_init(&ctx);
    
    uint8_t data[24]; // 8 + 8 + 4 + 4 bytes
    
    // From address
    for (int i = 0; i < 8; ++i) {
        data[i] = (from.offset >> (i * 8)) & 0xFF;
    }
    // To address
    for (int i = 0; i < 8; ++i) {
        data[8 + i] = (to.offset >> (i * 8)) & 0xFF;
    }
    // Type
    uint32_t type_val = static_cast<uint32_t>(type);
    for (int i = 0; i < 4; ++i) {
        data[16 + i] = (type_val >> (i * 8)) & 0xFF;
    }
    // Space info
    data[20] = static_cast<uint8_t>(from.space);
    data[21] = static_cast<uint8_t>(to.space);
    data[22] = 0;
    data[23] = 0;
    
    md5_update(&ctx, data, 24);
    
    ContentHash hash;
    md5_final(hash.bytes, &ctx);
    return hash;
}

bool XRefGovernance::validate(
    const XRef& xref,
    const Instruction& from_insn,
    const Binary& binary
) {
    // Check that the from_address matches the instruction
    if (xref.from_address.offset != from_insn.address.offset) {
        return false;
    }
    
    // For call/jump, verify it's actually a branch
    if (xref.is_call() || xref.is_jump()) {
        if (!from_insn.is_branch && !from_insn.is_call) {
            return false;
        }
    }
    
    // TODO: Additional validation - check operands actually reference target
    return true;
}

// TypeInfoGovernance implementation
ContentHash TypeInfoGovernance::compute_identity(const TypeInfo& type) {
    std::string descriptor;
    
    // Build canonical descriptor
    switch (type.kind) {
        case TypeInfo::Kind::Void:
            descriptor = "v";
            break;
        case TypeInfo::Kind::Integer:
            descriptor = "i" + std::to_string(type.size_bytes);
            break;
        case TypeInfo::Kind::Float:
            descriptor = "f" + std::to_string(type.size_bytes);
            break;
        case TypeInfo::Kind::Pointer:
            descriptor = "p" + std::to_string(type.size_bytes);
            break;
        case TypeInfo::Kind::Array:
            descriptor = "a[" + std::to_string(type.element_count) + "]";
            break;
        case TypeInfo::Kind::Struct:
            descriptor = "s{" + std::to_string(type.fields.size()) + "}";
            for (const auto& field : type.fields) {
                descriptor += field.name + ":" + std::to_string(field.offset) + ";";
            }
            break;
        default:
            descriptor = "?";
    }
    
    // Include size in identity
    descriptor += "@" + std::to_string(type.size_bytes);
    
    return ContentHash::from_string(descriptor);
}

TypeId TypeInfoGovernance::create_forward_declaration(const std::string& name) {
    // This is a factory method that would be called by Binary::create_type
    // The actual ID assignment happens in Binary
    return TypeId::Invalid; // Placeholder - real implementation in Binary
}

bool TypeInfoGovernance::resolve_forward_declaration(TypeId id, const TypeInfo& definition) {
    // Mark the type as resolved
    // Real implementation would update the type in Binary
    return id != TypeId::Invalid;
}

// EntityGovernance implementation
bool EntityGovernance::can_modify(const Function& fn, FunctionGovernance::Mutability op) {
    // Check if function allows this mutation type
    // For now, assume FullAnalysis during initial analysis
    // After analysis, functions become Immutable
    return op != FunctionGovernance::Mutability::Immutable;
}

bool EntityGovernance::can_modify(const BasicBlock& bb, BasicBlockGovernance::Mutability op) {
    return op != BasicBlockGovernance::Mutability::Immutable;
}

bool EntityGovernance::can_modify(const Symbol& sym, SymbolGovernance::Mutability op) {
    switch (op) {
        case SymbolGovernance::Mutability::Immutable:
            return false;
        case SymbolGovernance::Mutability::NameEditable:
            return true; // User can always rename
        case SymbolGovernance::Mutability::TypeEditable:
            return true;
        case SymbolGovernance::Mutability::FullEditable:
            return true;
    }
    return false;
}

EntityLifecycle EntityGovernance::get_lifecycle(const IRNodeIdentity& identity) {
    if (identity.is_invalid()) {
        return EntityLifecycle::Invalid;
    }
    if (identity.is_dirty()) {
        return EntityLifecycle::Dirty;
    }
    if (identity.version.stage_sequence == 0 && identity.dependencies.is_empty()) {
        return EntityLifecycle::Pending;
    }
    return EntityLifecycle::Complete;
}

bool EntityGovernance::validate(const Function& fn, const Binary& binary) {
    // Check that function has valid section reference
    if (fn.section != SectionId::Invalid) {
        if (!binary.get_section(fn.section)) {
            return false;
        }
    }
    
    // Check that all basic blocks exist
    for (BasicBlockId bb_id : fn.basic_blocks) {
        if (!binary.get_basic_block(bb_id)) {
            return false;
        }
    }
    
    // Check that entry block is in the list
    if (fn.entry_block != BasicBlockId::Invalid) {
        bool found = false;
        for (BasicBlockId bb_id : fn.basic_blocks) {
            if (bb_id == fn.entry_block) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    
    return true;
}

bool EntityGovernance::validate(const BasicBlock& bb, const Binary& binary) {
    // Check that parent function exists
    if (bb.parent_function != FunctionId::Invalid) {
        if (!binary.get_function(bb.parent_function)) {
            return false;
        }
    }
    
    // Check that all instructions exist
    for (InstructionId insn_id : bb.instructions) {
        if (!binary.get_instruction(insn_id)) {
            return false;
        }
    }
    
    // Check that successor/predecessor blocks exist
    for (BasicBlockId succ_id : bb.successors) {
        if (!binary.get_basic_block(succ_id)) {
            return false;
        }
    }
    for (BasicBlockId pred_id : bb.predecessors) {
        if (!binary.get_basic_block(pred_id)) {
            return false;
        }
    }
    
    return true;
}

bool EntityGovernance::validate(const Instruction& insn, const Binary& binary) {
    // Check that parent basic block exists
    if (insn.parent_bb != BasicBlockId::Invalid) {
        if (!binary.get_basic_block(insn.parent_bb)) {
            return false;
        }
    }
    
    // Check that bytes pointer is valid
    if (insn.bytes.data == nullptr && insn.bytes.size > 0) {
        return false;
    }
    
    return true;
}

void EntityGovernance::report_violation(
    const std::string& entity_type,
    EntityId id,
    const std::string& operation,
    const std::string& reason
) {
    // Log the violation - in production, this would use a proper logging system
    // For now, we'll just store it or output to stderr
    // TODO: Integrate with logging system when available
}

} // namespace atlus::ir
