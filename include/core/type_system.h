#pragma once
#include "core/ir.h"
#include <optional>
#include <variant>
#include <vector>
#include <string>

namespace atlus::ir {

// ── Type Lattice (Minimal v1) ──────────────────────────────────────────────────

/**
 * BaseType - Primitive types for the type propagation engine.
 * 
 * This is intentionally minimal for v1. We can expand to full
 * C++ type system later without breaking the IR contract.
 */
enum class BaseType : uint8_t {
    Unknown = 0,
    
    // Integers
    Int8, Int16, Int32, Int64,
    UInt8, UInt16, UInt32, UInt64,
    
    // Floating point
    Float32, Float64,
    
    // Pointers (with optional pointee type)
    Pointer,
    
    // Special
    Void,
    Bool,
    Char,       // Platform-dependent char
    WideChar,   // UTF-16 typically
    
    // Aggregates (referenced by TypeInfo)
    Struct,
    Array,
    FunctionPtr,
    
    // Analysis-specific
    CodeAddr,   // Known to be a code address
    DataAddr,   // Known to be a data address
    StringPtr,  // Pointer to string literal
    VTablePtr,  // Pointer to virtual function table
    
    Count
};

const char* base_type_name(BaseType type);
size_t base_type_size(BaseType type, bool is_64bit = true);

// ── Type Variable ─────────────────────────────────────────────────────────────

/**
 * TypeConstraint - Constraints on a type variable.
 */
struct TypeConstraint {
    enum class Kind {
        None,
        MustBe,           // Must be exactly this type
        MustBeBaseType,   // Must be one of base type (e.g., any int)
        PointerTo,        // Must be pointer to specific type
        SameAs,           // Must match another variable's type
    };
    
    Kind kind = Kind::None;
    BaseType base = BaseType::Unknown;
    TypeId pointee{TypeId::Invalid};  // For PointerTo
    // For SameAs: use type variable binding (see TypeEnvironment)
};

/**
 * TypeVariable - A type to be inferred or propagated.
 * 
 * Every register, stack slot, and memory location gets a type variable
 * during analysis. The constraint solver determines actual types.
 */
struct TypeVariable {
    uint32_t id = 0;
    BaseType inferred_type = BaseType::Unknown;
    std::vector<TypeConstraint> constraints;
    bool is_final = false;  // Locked after constraint resolution
    
    // Provenance: where did this variable come from?
    enum class Source {
        Register,
        StackSlot,
        GlobalAddr,
        HeapAddr,
        InstructionResult,  // Result of an instruction
        Parameter,          // Function parameter
        ReturnValue         // Function return
    };
    Source source = Source::Register;
    
    // Location info for debugging
    std::string name;           // e.g., "rax", "[rbp-8]"
    InstructionId def_site{InstructionId::Invalid};  // Where defined
};

// ── Register Type State ─────────────────────────────────────────────────────────

/**
 * RegisterState - Type state for all registers at a program point.
 * 
 * Used for:
 *   - Data flow analysis
 *   - Type propagation across basic blocks
 *   - Call convention checking
 */
struct RegisterState {
    // x86-64 general purpose registers (simplified)
    // Full version would include: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp,
    // r8-r15, xmm0-xmm15, etc.
    
    struct RegState {
        uint32_t type_var = 0;  // Index into type variable array
        bool is_defined = false;   // Has this register been written?
        bool is_volatile = false;  // Caller-saved (ABI dependent)
    };
    
    // GP registers: map register number to type variable
    std::unordered_map<uint32_t, RegState> gp_regs;
    
    // Flags
    bool zf_defined = false;
    bool cf_defined = false;
    bool sf_defined = false;
    bool of_defined = false;
};

// ── Stack Frame Model ────────────────────────────────────────────────────────────

/**
 * StackSlot - A typed location on the stack.
 */
struct StackSlot {
    int32_t offset = 0;      // Offset from RBP (positive = arg, negative = local)
    uint32_t size = 0;
    uint32_t type_var = 0;   // Type variable for this slot
    std::string name;        // Inferred name (e.g., "local_8", "arg_0")
};

/**
 * StackFrame - Model of a function's stack usage.
 */
struct StackFrame {
    uint32_t local_size = 0;    // sub rsp, N
    uint32_t padding_size = 0;  // Alignment padding
    
    std::vector<StackSlot> locals;
    std::vector<StackSlot> arguments;
    
    // Call-saved registers pushed by prologue
    std::vector<uint32_t> saved_regs;  // Register numbers
    
    // Analysis state
    bool is_frame_pointer_based = false;  // Uses RBP as frame pointer
    bool analyzed = false;
};

// ── Call Convention Model ───────────────────────────────────────────────────────

/**
 * CallingConvention - Abstract model of parameter passing.
 * 
 * Supports: SystemV AMD64 ABI, Windows x64 ABI, and custom conventions.
 */
struct CallingConvention {
    enum class Type {
        Unknown,
        SystemV_AMD64,   // Linux/ELF standard
        Windows_x64,     // Windows standard
        CDecl,           // 32-bit C calling convention
        FastCall,        // __fastcall
        ThisCall,        // __thiscall (MSVC)
        VectorCall,      // __vectorcall
        Custom
    };
    
    Type type = Type::Unknown;
    
    // Parameter locations
    struct ParamLoc {
        enum class Kind { Register, Stack };
        Kind kind = Kind::Register;
        uint32_t reg_num = 0;    // For register params
        int32_t stack_offset = 0; // For stack params (from RSP at call)
    };
    
    std::vector<uint32_t> integer_arg_regs;   // e.g., [rdi, rsi, rdx, rcx, r8, r9]
    std::vector<uint32_t> float_arg_regs;     // e.g., [xmm0-xmm7]
    uint32_t stack_arg_alignment = 8;           // Stack arg alignment in bytes
    
    // Return value
    uint32_t integer_return_reg = 0;  // Usually rax
    uint32_t float_return_reg = 0;    // Usually xmm0
    
    // Caller-saved (volatile) registers
    std::vector<uint32_t> volatile_regs;
    
    // Callee-saved (non-volatile) registers
    std::vector<uint32_t> nonvolatile_regs;
    
    // Get parameter location by index (0-based)
    ParamLoc get_param_location(size_t index, bool is_float, bool is_64bit) const;
    
    // Static constructors for known conventions
    static CallingConvention systemv_amd64();
    static CallingConvention windows_x64();
};

// ── Type Propagation Engine (Stub) ───────────────────────────────────────────────

/**
 * TypePropagation - Constraint-based type inference.
 * 
 * This is intentionally minimal for v1. Full implementation will
 * include unification, widening, and iterative fixed-point solving.
 */
class TypePropagation {
public:
    TypePropagation();
    ~TypePropagation();
    
    // Initialize with function to analyze
    void initialize(FunctionId function, Binary& binary);
    
    // Add type variable for a register at an instruction
    uint32_t add_register_var(
        uint32_t reg_num,
        InstructionId at_insn,
        TypeVariable::Source source,
        const std::string& name
    );
    
    // Add constraint to a type variable
    void add_constraint(uint32_t var_id, const TypeConstraint& constraint);
    
    // Set concrete type (e.g., from debug symbols, API prototypes)
    void set_concrete_type(uint32_t var_id, BaseType type);
    
    // Run constraint solving (simplified v1: just resolve direct constraints)
    void solve();
    
    // Query results
    BaseType get_inferred_type(uint32_t var_id) const;
    std::string get_type_description(uint32_t var_id) const;
    
    // Stack frame analysis
    void analyze_stack_frame(const Function& fn);
    const StackFrame& get_stack_frame() const { return stack_frame_; }
    
    // Results
    struct Result {
        std::unordered_map<InstructionId, RegisterState> register_states;
        StackFrame stack_frame;
        std::vector<TypeVariable> type_variables;
        bool converged = false;
    };
    Result get_result() const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    StackFrame stack_frame_;
};

// ── Type Database ───────────────────────────────────────────────────────────────

/**
 * TypeDatabase - Known type definitions.
 * 
 * Predefined types for common structures (Windows API, C stdlib, etc.)
 * plus user-defined structures.
 */
class TypeDatabase {
public:
    TypeDatabase();
    ~TypeDatabase();
    
    // Load predefined types
    void load_builtins(bool is_64bit, bool is_windows);
    
    // User-defined types
    TypeId add_struct(const std::string& name, const std::vector<TypeInfo::Field>& fields);
    TypeId add_typedef(const std::string& name, TypeId underlying);
    TypeId add_enum(const std::string& name, const std::vector<std::pair<std::string, int64_t>>& values);
    
    // Lookup
    std::optional<TypeId> find_by_name(const std::string& name) const;
    const TypeInfo* get_type(TypeId id) const;
    
    // Windows API helpers (v1 minimal set)
    TypeId get_handle_type();       // HANDLE
    TypeId get_pointer_type();      // PVOID / void*
    TypeId get_string_type();       // char* / wchar_t*
    TypeId get_size_t_type();       // platform size_t
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace atlus::ir
