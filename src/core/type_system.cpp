#include "core/type_system.h"
#include <algorithm>

namespace atlus::ir {

const char* base_type_name(BaseType type) {
    switch (type) {
        case BaseType::Unknown: return "unknown";
        case BaseType::Int8: return "int8_t";
        case BaseType::Int16: return "int16_t";
        case BaseType::Int32: return "int32_t";
        case BaseType::Int64: return "int64_t";
        case BaseType::UInt8: return "uint8_t";
        case BaseType::UInt16: return "uint16_t";
        case BaseType::UInt32: return "uint32_t";
        case BaseType::UInt64: return "uint64_t";
        case BaseType::Float32: return "float";
        case BaseType::Float64: return "double";
        case BaseType::Pointer: return "void*";
        case BaseType::Void: return "void";
        case BaseType::Bool: return "bool";
        case BaseType::Char: return "char";
        case BaseType::WideChar: return "wchar_t";
        case BaseType::Struct: return "struct";
        case BaseType::Array: return "array";
        case BaseType::FunctionPtr: return "fn_ptr";
        case BaseType::CodeAddr: return "code_addr";
        case BaseType::DataAddr: return "data_addr";
        case BaseType::StringPtr: return "string_ptr";
        case BaseType::VTablePtr: return "vtable_ptr";
        default: return "?";
    }
}

size_t base_type_size(BaseType type, bool is_64bit) {
    switch (type) {
        case BaseType::Int8: 
        case BaseType::UInt8: return 1;
        case BaseType::Int16: 
        case BaseType::UInt16: return 2;
        case BaseType::Int32: 
        case BaseType::UInt32: 
        case BaseType::Float32: return 4;
        case BaseType::Int64: 
        case BaseType::UInt64: 
        case BaseType::Float64: 
        case BaseType::Pointer:
        case BaseType::CodeAddr:
        case BaseType::DataAddr:
        case BaseType::StringPtr:
        case BaseType::VTablePtr:
            return is_64bit ? 8 : 4;
        case BaseType::Bool: return 1;
        case BaseType::Char: return 1;
        case BaseType::WideChar: return 2;
        case BaseType::Void: return 0;
        default: return is_64bit ? 8 : 4;  // Unknown = pointer size
    }
}

// CallingConvention implementation
CallingConvention::ParamLoc CallingConvention::get_param_location(
    size_t index, 
    bool is_float, 
    bool is_64bit
) const {
    ParamLoc loc;
    
    if (is_float) {
        if (index < float_arg_regs.size()) {
            loc.kind = ParamLoc::Kind::Register;
            loc.reg_num = float_arg_regs[index];
        } else {
            // Stack parameter
            loc.kind = ParamLoc::Kind::Stack;
            size_t stack_index = index - float_arg_regs.size();
            loc.stack_offset = static_cast<int32_t>(stack_index * stack_arg_alignment);
        }
    } else {
        if (index < integer_arg_regs.size()) {
            loc.kind = ParamLoc::Kind::Register;
            loc.reg_num = integer_arg_regs[index];
        } else {
            // Stack parameter
            loc.kind = ParamLoc::Kind::Stack;
            size_t stack_index = index - integer_arg_regs.size();
            loc.stack_offset = static_cast<int32_t>(stack_index * stack_arg_alignment);
        }
    }
    
    return loc;
}

CallingConvention CallingConvention::systemv_amd64() {
    CallingConvention cc;
    cc.type = Type::SystemV_AMD64;
    // Integer args: RDI, RSI, RDX, RCX, R8, R9
    cc.integer_arg_regs = {7, 6, 2, 1, 8, 9};  // Register numbers
    // Float args: XMM0-XMM7
    cc.float_arg_regs = {0, 1, 2, 3, 4, 5, 6, 7};
    cc.integer_return_reg = 0;  // RAX
    cc.float_return_reg = 0;    // XMM0
    cc.stack_arg_alignment = 8;
    // Volatile: RAX, RCX, RDX, RSI, RDI, R8-R11, XMM0-XMM15
    cc.volatile_regs = {0, 1, 2, 6, 7, 8, 9, 10, 11};
    // Nonvolatile: RBX, RBP, R12-R15
    cc.nonvolatile_regs = {3, 5, 12, 13, 14, 15};
    return cc;
}

CallingConvention CallingConvention::windows_x64() {
    CallingConvention cc;
    cc.type = Type::Windows_x64;
    // Integer args: RCX, RDX, R8, R9
    cc.integer_arg_regs = {1, 2, 8, 9};
    // Float args: XMM0-XMM3
    cc.float_arg_regs = {0, 1, 2, 3};
    cc.integer_return_reg = 0;  // RAX
    cc.float_return_reg = 0;    // XMM0
    cc.stack_arg_alignment = 8;
    // Volatile: RAX, RCX, RDX, R8-R11, XMM0-XMM5
    cc.volatile_regs = {0, 1, 2, 8, 9, 10, 11};
    // Nonvolatile: RBX, RBP, RDI, RSI, R12-R15, XMM6-XMM15
    cc.nonvolatile_regs = {3, 5, 6, 7, 12, 13, 14, 15};
    return cc;
}

// TypePropagation stub implementation
struct TypePropagation::Impl {
    std::vector<TypeVariable> variables;
    std::unordered_map<InstructionId, RegisterState> register_states;
    FunctionId current_function;
    Binary* binary = nullptr;
};

TypePropagation::TypePropagation() : impl_(std::make_unique<Impl>()) {}
TypePropagation::~TypePropagation() = default;

void TypePropagation::initialize(FunctionId function, Binary& binary) {
    impl_->current_function = function;
    impl_->binary = &binary;
    impl_->variables.clear();
    impl_->register_states.clear();
}

uint32_t TypePropagation::add_register_var(
    uint32_t reg_num,
    InstructionId at_insn,
    TypeVariable::Source source,
    const std::string& name
) {
    TypeVariable var;
    var.id = static_cast<uint32_t>(impl_->variables.size()) + 1;
    var.source = source;
    var.name = name;
    var.def_site = at_insn;
    
    impl_->variables.push_back(var);
    return var.id;
}

void TypePropagation::add_constraint(uint32_t var_id, const TypeConstraint& constraint) {
    if (var_id == 0 || var_id > impl_->variables.size()) return;
    impl_->variables[var_id - 1].constraints.push_back(constraint);
}

void TypePropagation::set_concrete_type(uint32_t var_id, BaseType type) {
    if (var_id == 0 || var_id > impl_->variables.size()) return;
    impl_->variables[var_id - 1].inferred_type = type;
    impl_->variables[var_id - 1].is_final = true;
}

void TypePropagation::solve() {
    // Simplified v1: Just resolve direct MustBe constraints
    for (auto& var : impl_->variables) {
        if (var.is_final) continue;
        
        for (const auto& constraint : var.constraints) {
            if (constraint.kind == TypeConstraint::Kind::MustBe) {
                var.inferred_type = constraint.base;
                var.is_final = true;
                break;
            }
        }
    }
}

BaseType TypePropagation::get_inferred_type(uint32_t var_id) const {
    if (var_id == 0 || var_id > impl_->variables.size()) return BaseType::Unknown;
    return impl_->variables[var_id - 1].inferred_type;
}

std::string TypePropagation::get_type_description(uint32_t var_id) const {
    if (var_id == 0 || var_id > impl_->variables.size()) return "unknown";
    const auto& var = impl_->variables[var_id - 1];
    return var.name + ":" + base_type_name(var.inferred_type);
}

void TypePropagation::analyze_stack_frame(const Function& fn) {
    stack_frame_.local_size = 0;
    stack_frame_.arguments.clear();
    stack_frame_.locals.clear();
    stack_frame_.analyzed = false;
    
    // Simple heuristic: look for sub rsp, N pattern
    // Real implementation would trace through all BBs
    for (BasicBlockId bb_id : fn.basic_blocks) {
        const BasicBlock* bb = impl_->binary->get_basic_block(bb_id);
        if (!bb) continue;
        
        for (InstructionId insn_id : bb->instructions) {
            const Instruction* insn = impl_->binary->get_instruction(insn_id);
            if (!insn) continue;
            
            // Check for "sub rsp, N" pattern
            if (insn->mnemonic == "sub" && !insn->operands.empty()) {
                // Could be stack allocation
                // In full implementation, parse operands properly
            }
        }
    }
    
    stack_frame_.analyzed = true;
}

TypePropagation::Result TypePropagation::get_result() const {
    Result r;
    r.register_states = impl_->register_states;
    r.stack_frame = stack_frame_;
    r.type_variables = impl_->variables;
    r.converged = true;  // v1 always "converges" (single pass)
    return r;
}

// TypeDatabase stub implementation
struct TypeDatabase::Impl {
    std::unordered_map<std::string, TypeId> name_to_id;
    std::vector<TypeInfo> types;
};

TypeDatabase::TypeDatabase() : impl_(std::make_unique<Impl>()) {}
TypeDatabase::~TypeDatabase() = default;

void TypeDatabase::load_builtins(bool is_64bit, bool is_windows) {
    // Load common types
    // In full implementation, load from embedded database
    impl_->types.clear();
    impl_->name_to_id.clear();
}

TypeId TypeDatabase::add_struct(const std::string& name, const std::vector<TypeInfo::Field>& fields) {
    TypeInfo type;
    type.id = TypeId(static_cast<uint32_t>(impl_->types.size()));
    type.name = name;
    type.kind = TypeInfo::Kind::Struct;
    type.fields = fields;
    
    // Calculate size
    type.size_bytes = 0;
    for (const auto& field : fields) {
        // In full implementation, lookup field type size
        type.size_bytes = std::max(type.size_bytes, field.offset + 8);  // Placeholder
    }
    
    impl_->types.push_back(type);
    impl_->name_to_id[name] = type.id;
    return type.id;
}

TypeId TypeDatabase::add_typedef(const std::string& name, TypeId underlying) {
    // For v1, just store as alias
    TypeInfo type;
    type.id = TypeId(static_cast<uint32_t>(impl_->types.size()));
    type.name = name;
    type.kind = TypeInfo::Kind::Void;  // Mark as alias
    
    impl_->types.push_back(type);
    impl_->name_to_id[name] = type.id;
    return type.id;
}

TypeId TypeDatabase::add_enum(const std::string& name, const std::vector<std::pair<std::string, int64_t>>& values) {
    TypeInfo type;
    type.id = TypeId(static_cast<uint32_t>(impl_->types.size()));
    type.name = name;
    type.kind = TypeInfo::Kind::Enum;
    type.size_bytes = 4;  // Usually int32
    
    impl_->types.push_back(type);
    impl_->name_to_id[name] = type.id;
    return type.id;
}

std::optional<TypeId> TypeDatabase::find_by_name(const std::string& name) const {
    auto it = impl_->name_to_id.find(name);
    if (it == impl_->name_to_id.end()) return std::nullopt;
    return it->second;
}

const TypeInfo* TypeDatabase::get_type(TypeId id) const {
    uint32_t idx = static_cast<uint32_t>(id);
    if (idx >= impl_->types.size()) return nullptr;
    return &impl_->types[idx];
}

TypeId TypeDatabase::get_handle_type() {
    return find_by_name("HANDLE").value_or(TypeId::Invalid);
}

TypeId TypeDatabase::get_pointer_type() {
    return find_by_name("void*").value_or(TypeId::Invalid);
}

TypeId TypeDatabase::get_string_type() {
    return find_by_name("char*").value_or(TypeId::Invalid);
}

TypeId TypeDatabase::get_size_t_type() {
    return find_by_name("size_t").value_or(TypeId::Invalid);
}

} // namespace atlus::ir
