#pragma once
#include "core/ir_identity.h"
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <optional>
#include <variant>

namespace atlus::ir {

// ── Address Representation ─────────────────────────────────────────────────────

/**
 * Universal address type that abstracts file offset, RVA, and virtual address.
 * All IR entities use this for consistent addressing across the analysis pipeline.
 */
struct Address {
    uint64_t offset = 0;
    
    enum class Space { None, FileOffset, RVA, Virtual };
    Space space = Space::None;
    
    // Convenience constructors
    static Address file_offset(uint64_t off) { return {off, Space::FileOffset}; }
    static Address rva(uint64_t r)           { return {r, Space::RVA}; }
    static Address virtual_addr(uint64_t va)   { return {va, Space::Virtual}; }
    
    bool valid() const { return space != Space::None; }
    
    bool operator==(const Address& other) const { 
        return offset == other.offset && space == other.space; 
    }
    bool operator<(const Address& other) const {
        return offset < other.offset;
    }
};

// ── Core Entity IDs ──────────────────────────────────────────────────────────

/**
 * Strongly-typed IDs for IR entities to prevent accidental mixing.
 * These are used for fast lookup and index-based relationships.
 */
enum class EntityId : uint32_t { Invalid = 0xFFFFFFFF };

struct BinaryId {
    uint32_t value = 0xFFFFFFFF;
    static constexpr uint32_t Invalid = 0xFFFFFFFF;
    BinaryId() = default;
    explicit BinaryId(uint32_t v) : value(v) {}
    bool operator==(const BinaryId& other) const { return value == other.value; }
    bool operator!=(const BinaryId& other) const { return value != other.value; }
    bool operator==(uint32_t v) const { return value == v; }
    bool operator!=(uint32_t v) const { return value != v; }
    bool operator<(const BinaryId& other) const { return value < other.value; }
    explicit operator uint32_t() const { return value; }
    explicit operator bool() const { return value != Invalid; }
    bool is_valid() const { return value != Invalid; }
};

struct SectionId {
    uint32_t value = 0xFFFFFFFF;
    static constexpr uint32_t Invalid = 0xFFFFFFFF;
    SectionId() = default;
    explicit SectionId(uint32_t v) : value(v) {}
    bool operator==(const SectionId& other) const { return value == other.value; }
    bool operator!=(const SectionId& other) const { return value != other.value; }
    bool operator==(uint32_t v) const { return value == v; }
    bool operator!=(uint32_t v) const { return value != v; }
    bool operator<(const SectionId& other) const { return value < other.value; }
    explicit operator uint32_t() const { return value; }
    explicit operator bool() const { return value != Invalid; }
    bool is_valid() const { return value != Invalid; }
};

struct SymbolId {
    uint32_t value = 0xFFFFFFFF;
    static constexpr uint32_t Invalid = 0xFFFFFFFF;
    SymbolId() = default;
    explicit SymbolId(uint32_t v) : value(v) {}
    bool operator==(const SymbolId& other) const { return value == other.value; }
    bool operator!=(const SymbolId& other) const { return value != other.value; }
    bool operator==(uint32_t v) const { return value == v; }
    bool operator!=(uint32_t v) const { return value != v; }
    bool operator<(const SymbolId& other) const { return value < other.value; }
    explicit operator uint32_t() const { return value; }
    explicit operator bool() const { return value != Invalid; }
    bool is_valid() const { return value != Invalid; }
};

struct FunctionId {
    uint32_t value = 0xFFFFFFFF;
    static constexpr uint32_t Invalid = 0xFFFFFFFF;
    FunctionId() = default;
    explicit FunctionId(uint32_t v) : value(v) {}
    bool operator==(const FunctionId& other) const { return value == other.value; }
    bool operator!=(const FunctionId& other) const { return value != other.value; }
    bool operator==(uint32_t v) const { return value == v; }
    bool operator!=(uint32_t v) const { return value != v; }
    bool operator<(const FunctionId& other) const { return value < other.value; }
    explicit operator uint32_t() const { return value; }
    explicit operator bool() const { return value != Invalid; }
    bool is_valid() const { return value != Invalid; }
};

struct BasicBlockId {
    uint32_t value = 0xFFFFFFFF;
    static constexpr uint32_t Invalid = 0xFFFFFFFF;
    BasicBlockId() = default;
    explicit BasicBlockId(uint32_t v) : value(v) {}
    bool operator==(const BasicBlockId& other) const { return value == other.value; }
    bool operator!=(const BasicBlockId& other) const { return value != other.value; }
    bool operator==(uint32_t v) const { return value == v; }
    bool operator!=(uint32_t v) const { return value != v; }
    bool operator<(const BasicBlockId& other) const { return value < other.value; }
    explicit operator uint32_t() const { return value; }
    explicit operator bool() const { return value != Invalid; }
    bool is_valid() const { return value != Invalid; }
};

struct InstructionId {
    uint32_t value = 0xFFFFFFFF;
    static constexpr uint32_t Invalid = 0xFFFFFFFF;
    InstructionId() = default;
    explicit InstructionId(uint32_t v) : value(v) {}
    bool operator==(const InstructionId& other) const { return value == other.value; }
    bool operator!=(const InstructionId& other) const { return value != other.value; }
    bool operator==(uint32_t v) const { return value == v; }
    bool operator!=(uint32_t v) const { return value != v; }
    bool operator<(const InstructionId& other) const { return value < other.value; }
    explicit operator uint32_t() const { return value; }
    explicit operator bool() const { return value != Invalid; }
    bool is_valid() const { return value != Invalid; }
};

struct TypeId {
    uint32_t value = 0xFFFFFFFF;
    static constexpr uint32_t Invalid = 0xFFFFFFFF;
    TypeId() = default;
    explicit TypeId(uint32_t v) : value(v) {}
    bool operator==(const TypeId& other) const { return value == other.value; }
    bool operator!=(const TypeId& other) const { return value != other.value; }
    bool operator==(uint32_t v) const { return value == v; }
    bool operator!=(uint32_t v) const { return value != v; }
    bool operator<(const TypeId& other) const { return value < other.value; }
    explicit operator uint32_t() const { return value; }
    explicit operator bool() const { return value != Invalid; }
    bool is_valid() const { return value != Invalid; }
};

// ── Operand Types ──────────────────────────────────────────────────────────────

/**
 * Memory reference operand data.
 * Used for instructions that reference memory (e.g., [rbx+rcx*4+0x10]).
 */
struct MemoryRef {
    uint32_t base_reg = 0;
    uint32_t index_reg = 0;
    uint8_t  scale = 0;
    int64_t  displacement = 0;
};

/**
 * Represents an instruction operand with type-safe access.
 * Supports registers, immediate values, memory references, and addresses.
 */
struct Operand {
    enum class Type { None, Register, Immediate, Memory, Address };
    
    Type type = Type::None;
    
    // Variant storage for different operand types
    std::variant<
        std::monostate,           // None
        uint32_t,                 // Register (ZydisRegister enum)
        uint64_t,                 // Immediate value
        MemoryRef,                // Memory reference
        Address                   // Code/data address reference
    > data;
    
    // Convenience accessors
    bool is_register() const { return type == Type::Register; }
    bool is_immediate() const { return type == Type::Immediate; }
    bool is_memory() const { return type == Type::Memory; }
    bool is_address() const { return type == Type::Address; }
};

// ── IR Entities ──────────────────────────────────────────────────────────────

/**
 * Instruction - The fundamental code unit.
 * 
 * Relationships:
 *   - instruction -> basic_block (parent)
 *   - instruction -> xrefs (outgoing references from this instruction)
 *   - instruction -> symbol (if this address has a name)
 */
struct Instruction {
    InstructionId id{InstructionId::Invalid};
    BasicBlockId parent_bb{BasicBlockId::Invalid};
    
    // Addressing
    Address address;
    uint32_t length = 0;  // 1-15 bytes for x86/x64
    
    // Disassembly
    std::string mnemonic;
    std::string operands_text;
    std::vector<Operand> operands;
    
    // Raw bytes (view into binary data, not owned)
    struct { const uint8_t* data; uint32_t size; } bytes = {nullptr, 0};
    
    // Control flow
    bool is_branch = false;
    bool is_call = false;
    bool is_return = false;
    bool is_conditional = false;
    
    // Cross-references from this instruction (calls, jumps, data refs)
    std::vector<struct XRef> outgoing_refs;
};

/**
 * BasicBlock - A sequence of instructions with single-entry, single-exit semantics.
 * 
 * Relationships:
 *   - basic_block -> function (parent)
 *   - basic_block -> instructions[] (ordered)
 *   - basic_block -> successor_bbs[] (CFG edges)
 *   - basic_block -> predecessor_bbs[] (reverse CFG edges)
 */
struct BasicBlock {
    BasicBlockId id{BasicBlockId::Invalid};
    FunctionId parent_function{FunctionId::Invalid};
    
    // Address range
    Address start_address;
    Address end_address;  // Address after last instruction
    
    // Contents
    std::vector<InstructionId> instructions;
    
    // Control Flow Graph edges
    std::vector<BasicBlockId> successors;     // Outgoing edges
    std::vector<BasicBlockId> predecessors;   // Incoming edges
    
    // Properties
    bool is_entry = false;    // First BB of function
    bool is_exit = false;     // Returns or tail-calls
};

/**
 * Function - A callable unit with control flow graph.
 * 
 * Relationships:
 *   - function -> basic_blocks[] (the CFG)
 *   - function -> symbol (name binding)
 *   - function -> section (containing section)
 *   - function -> xrefs_in[] (callers)
 *   - function -> xrefs_out[] (callees)
 */
struct Function {
    FunctionId id{FunctionId::Invalid};
    SectionId section{SectionId::Invalid};
    SymbolId symbol{SymbolId::Invalid};
    
    // Address range
    Address start_address;
    Address end_address;
    uint32_t size_bytes = 0;
    
    // CFG
    std::vector<BasicBlockId> basic_blocks;
    BasicBlockId entry_block{BasicBlockId::Invalid};
    
    // Cross-references
    std::vector<struct XRef> calls_in;   // Functions calling this one
    std::vector<struct XRef> calls_out;  // Functions this one calls
    
    // Properties
    enum class Type { Standard, Thunk, Imported, Exported };
    Type type = Type::Standard;
    
    bool has_name() const;
    std::string get_display_name() const;
};

/**
 * Section - A contiguous memory region with common attributes.
 * 
 * Relationships:
 *   - section -> binary (parent)
 *   - section -> functions[] (contained functions)
 *   - section -> data_symbols[] (contained data references)
 */
struct Section {
    SectionId id{SectionId::Invalid};
    BinaryId parent_binary{BinaryId::Invalid};
    
    std::string name;
    
    // Addressing
    Address file_offset;   // Where in file
    Address rva;          // Relative virtual address
    Address virtual_addr; // Image base + RVA
    uint32_t virtual_size = 0;
    uint32_t raw_size = 0;
    
    // Properties
    uint32_t characteristics = 0;  // PE section flags
    bool is_executable = false;
    bool is_writable = false;
    bool is_readable = false;
    
    // Contained entities (populated by analysis)
    std::vector<FunctionId> functions;
    std::vector<SymbolId> data_symbols;
};

/**
 * Symbol - A named address (function, data, import, export).
 * 
 * Relationships:
 *   - symbol -> address (binding)
 *   - symbol -> type (optional type information)
 */
struct Symbol {
    SymbolId id{SymbolId::Invalid};
    
    std::string name;
    std::string demangled_name;  // C++ demangled version
    
    Address address;
    
    enum class Type {
        Unknown,
        Function,
        Data,
        Import,
        Export,
        String,
        VTable
    };
    Type type = Type::Unknown;
    
    TypeId type_info{TypeId::Invalid};  // Optional type association
    
    // For imports: which DLL
    std::string source_dll;
    
    // Identity for provenance tracking
    IRNodeIdentity identity;
};

/**
 * XRef - Cross-reference between addresses.
 * 
 * Represents code/data relationships like:
 *   - CALL from function A to function B
 *   - JMP from basic block A to basic block B  
 *   - Data reference (string access, vtable load, etc)
 */
struct XRef {
    enum class Type { Call, Jump, DataRead, DataWrite, Pointer };
    
    Type type = Type::Call;
    
    // Source (always an instruction)
    Address from_address;
    InstructionId from_instruction{InstructionId::Invalid};
    
    // Target (function, basic block, data address)
    Address to_address;
    std::variant<
        std::monostate,
        FunctionId,
        BasicBlockId,
        SymbolId
    > target;
    
    bool is_call() const { return type == Type::Call; }
    bool is_jump() const { return type == Type::Jump; }
    bool is_data() const { return type == Type::DataRead || type == Type::DataWrite; }
};

/**
 * TypeInfo - Type system for memory interpretation.
 * 
 * Supports primitive types, pointers, arrays, structures.
 */
struct TypeInfo {
    TypeId id{TypeId::Invalid};
    
    std::string name;
    uint32_t size_bytes = 0;
    
    enum class Kind { 
        Void, 
        Integer, 
        Float, 
        Pointer, 
        Array, 
        Struct, 
        Union,
        Function,
        Enum
    };
    Kind kind = Kind::Void;
    
    // For structs/unions
    struct Field {
        std::string name;
        TypeId type;
        uint32_t offset;
    };
    std::vector<Field> fields;
    
    // For pointers/arrays
    TypeId element_type{TypeId::Invalid};
    uint32_t element_count = 0;  // For arrays, 0 = unknown
};

// ── Binary Module (Top-level Container) ────────────────────────────────────────

/**
 * Binary - The root container for all IR entities of a loaded file.
 * 
 * This is the unified interface that all analysis passes operate on.
 * It owns all entities and provides fast lookup by ID or address.
 */
class Binary {
public:
    BinaryId id() const { return id_; }
    
    // Entity access by ID
    const Section*      get_section(SectionId id) const;
    const Function*     get_function(FunctionId id) const;
    const BasicBlock*   get_basic_block(BasicBlockId id) const;
    const Instruction*  get_instruction(InstructionId id) const;
    const Symbol*       get_symbol(SymbolId id) const;
    const TypeInfo*     get_type(TypeId id) const;
    
    // Lookup by address
    const Section*      find_section_at(Address addr) const;
    const Function*     find_function_at(Address addr) const;
    const Symbol*       find_symbol_at(Address addr) const;
    std::vector<const XRef*> find_xrefs_to(Address addr) const;
    std::vector<const XRef*> find_xrefs_from(Address addr) const;
    
    // Global search
    std::vector<const Symbol*> find_symbols_by_name(const std::string& pattern) const;
    std::vector<const Function*> find_functions_by_name(const std::string& pattern) const;
    
    // Iteration
    const std::vector<std::unique_ptr<Section>>& sections() const { return sections_; }
    const std::vector<std::unique_ptr<Function>>& functions() const { return functions_; }
    const std::vector<std::unique_ptr<Symbol>>& symbols() const { return symbols_; }
    
    // Entity creation (used by analysis passes)
    SectionId    create_section(const Section& sec);
    FunctionId   create_function(const Function& fn);
    BasicBlockId create_basic_block(const BasicBlock& bb);
    InstructionId create_instruction(const Instruction& insn);
    SymbolId     create_symbol(const Symbol& sym);
    TypeId       create_type(const TypeInfo& type);
    
    // Cross-reference registration
    void register_xref(const XRef& xref);
    
    // Address conversion utilities
    std::optional<Address> file_to_virtual(Address file_offset) const;
    std::optional<Address> virtual_to_file(Address va) const;
    std::optional<Address> rva_to_virtual(Address rva) const;
    
    // Properties
    const std::string& path() const { return path_; }
    uint64_t image_base() const { return image_base_; }
    bool is_64bit() const { return is_64bit_; }
    
    // Internal construction
    explicit Binary(std::string path, uint64_t image_base, bool is_64bit);
    
private:
    BinaryId id_;
    std::string path_;
    uint64_t image_base_;
    bool is_64bit_;
    
    // Entity storage (stable addresses for pointer validity)
    std::vector<std::unique_ptr<Section>> sections_;
    std::vector<std::unique_ptr<Function>> functions_;
    std::vector<std::unique_ptr<BasicBlock>> basic_blocks_;
    std::vector<std::unique_ptr<Instruction>> instructions_;
    std::vector<std::unique_ptr<Symbol>> symbols_;
    std::vector<std::unique_ptr<TypeInfo>> types_;
    
    // Indexes for fast lookup
    std::unordered_map<uint64_t, SectionId> section_by_rva_;
    std::unordered_map<uint64_t, FunctionId> function_by_va_;
    std::unordered_map<uint64_t, SymbolId> symbol_by_va_;
    std::unordered_map<std::string, SymbolId> symbol_by_name_;
    
    // XRef indexes
    std::unordered_map<uint64_t, std::vector<XRef>> xrefs_to_;
    std::unordered_map<uint64_t, std::vector<XRef>> xrefs_from_;
    
    // ID generators
    uint32_t next_section_id_ = 0;
    uint32_t next_function_id_ = 0;
    uint32_t next_bb_id_ = 0;
    uint32_t next_insn_id_ = 0;
    uint32_t next_symbol_id_ = 0;
    uint32_t next_type_id_ = 0;
};

// ─= Entity ID hashing ─────────────────────────────────────────────────────────

// Enable EntityId use in unordered_map/unordered_set
struct EntityIdHash {
    template<typename T>
    size_t operator()(T id) const {
        return std::hash<uint32_t>{}(static_cast<uint32_t>(id));
    }
};

} // namespace atlus::ir

// std::hash specializations for ID types (needed for unordered_map/set)
namespace std {
    template<> struct hash<atlus::ir::BinaryId> {
        size_t operator()(const atlus::ir::BinaryId& id) const {
            return hash<uint32_t>{}(id.value);
        }
    };
    template<> struct hash<atlus::ir::SectionId> {
        size_t operator()(const atlus::ir::SectionId& id) const {
            return hash<uint32_t>{}(id.value);
        }
    };
    template<> struct hash<atlus::ir::SymbolId> {
        size_t operator()(const atlus::ir::SymbolId& id) const {
            return hash<uint32_t>{}(id.value);
        }
    };
    template<> struct hash<atlus::ir::FunctionId> {
        size_t operator()(const atlus::ir::FunctionId& id) const {
            return hash<uint32_t>{}(id.value);
        }
    };
    template<> struct hash<atlus::ir::BasicBlockId> {
        size_t operator()(const atlus::ir::BasicBlockId& id) const {
            return hash<uint32_t>{}(id.value);
        }
    };
    template<> struct hash<atlus::ir::InstructionId> {
        size_t operator()(const atlus::ir::InstructionId& id) const {
            return hash<uint32_t>{}(id.value);
        }
    };
    template<> struct hash<atlus::ir::TypeId> {
        size_t operator()(const atlus::ir::TypeId& id) const {
            return hash<uint32_t>{}(id.value);
        }
    };
}
