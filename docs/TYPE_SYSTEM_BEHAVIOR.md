# Type System Minimal v1 Behavior

**Version:** 1.0  
**Status:** REQUIRED  
**Date:** 2024

---

## 1. Core Requirement

**Rule:** Even minimal v1 type system must define:
1. Type inference direction
2. Type conflict resolution
3. Pointer propagation semantics

**Rationale:** Prevents CFG + struct parsing divergence in Phase 3.

---

## 2. Type Inference Direction

### 2.1 Supported Directions

| Direction | Description | Example |
|-----------|-------------|---------|
| **Forward** | Propagate from definition to uses | `mov eax, 5` → eax = Int32 |
| **Backward** | Propagate from uses to definition | `call printf` → arg = StringPtr |
| **Bidirectional** | Meet in the middle | Register passes through calls |

### 2.2 Direction Rules by Source

| Source | Primary Direction | Secondary |
|--------|-----------------|-----------|
| Immediate constant | Forward | - |
| Memory load (known structure) | Forward | - |
| Function parameter | Backward (from callee) | Forward (to body) |
| Function return | Forward (from body) | Backward (to callers) |
| Register operand | Bidirectional | - |
| API call argument | Backward (from API prototype) | - |
| String literal | Forward | - |

### 2.3 Direction Conflict Resolution

**Rule:** When forward and backward inference conflict, backward wins for external interfaces.

**Rationale:** API prototypes are authoritative; local inference is heuristic.

```cpp
// Example:
mov rcx, 0x1234       ; Forward: rcx = Int32 (constant)
call CreateFileW      ; Backward: rcx = StringPtr (from API)

// Resolution: rcx = StringPtr (backward wins)
// Rationale: 0x1234 is likely placeholder or RVA
```

---

## 3. Type Conflict Resolution

### 3.1 Conflict Types

| Conflict | Description | Resolution |
|----------|-------------|------------|
| **Same base, different size** | Int32 vs Int64 | Use wider type (Int64) |
| **Integer vs Pointer** | Int32 vs Pointer | Context-dependent (see 3.2) |
| **Pointer types** | StringPtr vs DataAddr | Use more specific (StringPtr) |
| **Incompatible** | Float32 vs Pointer | Flag as "uncertain" |

### 3.2 Integer vs Pointer Resolution

**Rule:** Heuristic priority for integer/pointer ambiguity:

```cpp
Priority (highest to lowest):
1. API prototype match → Pointer
2. Used in load/store → Pointer
3. Used in arithmetic → Integer (unless pointer math pattern)
4. String literal → StringPtr
5. Small constant (< 0x10000) → Integer
6. Large constant (> 0x1000000) → Pointer (likely RVA)
7. Default → Integer (conservative)
```

**Example:**
```asm
mov rax, 0x140000000  ; Likely RVA → Pointer
add rax, 0x100        ; Pointer math → confirms Pointer
mov rcx, 5            ; Small constant → Integer
call malloc           ; Returns Pointer (from prototype)
```

### 3.3 Meet Operator (Type Lattice)

**Rule:** Define type meet (most general common subtype).

```
Meet(Int32, Int64) = Int64           ; Wider wins
Meet(Pointer, StringPtr) = Pointer   ; More general wins
Meet(Int32, Pointer) = Uncertain      ; Flag conflict
Meet(CodeAddr, DataAddr) = Pointer    ; Generic pointer
```

**Implementation:**
```cpp
BaseType meet_types(BaseType a, BaseType b) {
    if (a == b) return a;
    
    // Pointer hierarchy
    if (is_pointer(a) && is_pointer(b)) {
        if (is_more_specific(a, b)) return b;
        if (is_more_specific(b, a)) return a;
        return BaseType::Pointer;  // Generic
    }
    
    // Integer hierarchy
    if (is_integer(a) && is_integer(b)) {
        return wider_of(a, b);
    }
    
    // Conflict
    return BaseType::Unknown;
}
```

---

## 4. Pointer Propagation Semantics

### 4.1 Pointer Arithmetic Rules

**Rule:** Track pointer base and offset separately.

```cpp
struct PointerType {
    BaseType base_type = BaseType::Pointer;
    TypeId pointee;           // What it points to
    int64_t known_offset = 0;   // If field offset known
    bool is_array = false;
    size_t array_size = 0;
};
```

**Propagation:**
```asm
; Base pointer
mov rbx, [some_struct]     ; rbx = Pointer to SomeStruct

; Field access
mov rax, [rbx + 0x10]      ; rax = Pointer to SomeStruct.field_at_0x10
                           ; known_offset = 0x10

; Array access
mov rcx, [rbx + rax*8]     ; rcx = Pointer to SomeStruct.array_element
                           ; is_array = true
```

### 4.2 Structure Field Recovery

**Rule:** Accumulate field offsets to reconstruct structure layout.

```cpp
struct FieldInference {
    uint32_t offset;
    BaseType inferred_type;
    uint32_t access_count = 0;
};

// Accumulate across all function analysis:
for (each memory access [base + offset]) {
    if (base_type is struct S) {
        S.fields[offset].type = meet(S.fields[offset].type, access_type);
        S.fields[offset].access_count++;
    }
}
```

### 4.3 String Pointer Propagation

**Rule:** String literals propagate StringPtr type forward.

```cpp
// String detection:
if (data_at(addr) is printable_ascii && terminated_by_null) {
    create_symbol_at(addr, Type = String, content = string);
    type_variable_at(addr) = BaseType::StringPtr;
}

// Propagation:
lea rcx, [string_addr]     ; rcx = StringPtr
call printf                ; Confirms first arg = StringPtr
```

---

## 5. Constraint Solving (Minimal v1)

### 5.1 Constraint Types

| Constraint | Semantics | Example |
|------------|-----------|---------|
| `MustBe(T)` | Exactly type T | API prototype requires StringPtr |
| `MustBeInt` | Any integer | Register used in arithmetic |
| `MustBePtr` | Any pointer | Register used in load/store |
| `PointerTo(T)` | Pointer to T | Known structure field |
| `SameAs(V)` | Same as variable V | Register copied to another |

### 5.2 Solving Algorithm (v1 - Single Pass)

```cpp
void solve_constraints() {
    // Single-pass meet for all constraints
    for (auto& var : type_variables) {
        BaseType result = BaseType::Unknown;
        
        for (auto& constraint : var.constraints) {
            switch (constraint.kind) {
                case MustBe:
                    result = meet_types(result, constraint.base_type);
                    break;
                case MustBeInt:
                    result = meet_types(result, BaseType::Int64);  // Widest
                    break;
                case MustBePtr:
                    result = meet_types(result, BaseType::Pointer);
                    break;
                case PointerTo:
                    // Record pointee type separately
                    var.pointee_type = constraint.pointee;
                    result = meet_types(result, BaseType::Pointer);
                    break;
                case SameAs:
                    // Link variables (union-find)
                    union_variables(var.id, constraint.other_var);
                    break;
            }
        }
        
        var.inferred_type = result;
    }
}
```

**Note:** v1 uses single-pass. Full unification deferred to v2.

### 5.3 Iterative Refinement (Optional v1.1)

```cpp
bool changed = true;
int iteration = 0;
while (changed && iteration < MAX_ITERATIONS) {
    changed = false;
    
    for (auto& var : type_variables) {
        BaseType old_type = var.inferred_type;
        recompute_meet(var);
        
        if (var.inferred_type != old_type) {
            changed = true;
            
            // Propagate to linked variables
            for (auto linked : var.same_as_set) {
                propagate_change(linked, var.inferred_type);
            }
        }
    }
    iteration++;
}

// If not converged, widen to conservative type
if (iteration >= MAX_ITERATIONS) {
    widen_types_to_conservative();
}
```

---

## 6. Stack Frame Type Recovery

### 6.1 Local Variable Types

**Rule:** Infer from operations on stack slots.

```asm
mov [rbp-8], 0          ; slot[8] = Int32 (constant)
mov rax, [rbp-8]        ; rax = Int32 (load)
add rax, 1              ; rax = Int32 (arithmetic)
mov [rbp-8], rax        ; slot[8] = Int32 (store)

; Inference: [rbp-8] is Int64 (conservative, register width)
```

### 6.2 Parameter Types

**Rule:** Infer from calling convention + argument usage.

```cpp
// Windows x64 calling convention:
// RCX, RDX, R8, R9 = first 4 integer/pointer args

void infer_parameter_types(Function& fn) {
    for (int i = 0; i < 4; i++) {
        auto reg = calling_convention.integer_arg_regs[i];
        auto& param_type = fn.parameter_types[i];
        
        // Get type variable for register at function entry
        param_type = type_state_at_entry.get_type(reg);
    }
}
```

---

## 7. Integration with CFG Analysis

### 7.1 Basic Block Type State

**Rule:** Each BB has entry and exit type state.

```cpp
struct BBTypeState {
    // Maps register/stack slot to type variable
    std::unordered_map<uint32_t, TypeVariableId> register_types;
    std::unordered_map<int32_t, TypeVariableId> stack_types;
    
    // Merge point handling:
    // BB with multiple predecessors merges their exit states
    static BBTypeState merge(const std::vector<BBTypeState>& preds);
};
```

### 7.2 Type State Transfer Function

**Rule:** Each instruction transforms type state.

```cpp
TypeState transfer(TypeState state, const Instruction& insn) {
    switch (insn.opcode) {
        case MOV_REG_IMM:
            state.set_type(insn.dest_reg, type_of(insn.immediate));
            break;
            
        case MOV_REG_REG:
            state.set_type(insn.dest_reg, state.get_type(insn.src_reg));
            break;
            
        case MOV_REG_MEM:
            state.set_type(insn.dest_reg, 
                dereference_type(state.get_base_type(), insn.offset));
            break;
            
        case CALL:
            // Apply calling convention
            for (auto& arg : insn.arguments) {
                constrain_type(state.get_type(arg.reg), arg.expected_type);
            }
            // Set return type
            state.set_type(return_reg, callee.return_type);
            break;
    }
    return state;
}
```

---

## 8. Summary

**Minimal v1 Requirements:**
1. ✅ **Direction:** Forward/Backward/Bidirectional defined per source
2. ✅ **Conflict Resolution:** Meet operator, backward wins for APIs
3. ✅ **Pointer Propagation:** Offset tracking, field accumulation
4. ✅ **Constraint Solving:** Single-pass meet (v1), iterative (v1.1)
5. ✅ **Stack Recovery:** Local + parameter type inference
6. ✅ **CFG Integration:** Per-BB type state with merge points

**Deferred to v2:**
- Full unification with union-find
- Interprocedural analysis
- Generic type parameters
- Complex struct nesting

**Correctness Guarantee:**
- Conservative typing (no false positives for pointer vs int)
- Convergence guaranteed via widening
- Type info enhances but never breaks CFG analysis
