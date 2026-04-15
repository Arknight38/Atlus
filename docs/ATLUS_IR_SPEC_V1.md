# Atlus IR Specification v1.0

**Status:** Draft  
**Last Updated:** 2024  
**Version:** 1.0.0-alpha

---

## 1. Overview

The Atlus Intermediate Representation (IR) is the canonical semantic model for binary analysis. All analysis passes, UI views, and external integrations operate on this representation.

### 1.1 Design Goals

- **Deterministic**: Same binary → same IR (content-addressable)
- **Stable References**: IR node references survive incremental analysis
- **Serializable**: Complete session state can be saved/restored
- **Language Agnostic**: Underlying binary format independent (PE/ELF/Mach-O/raw)
- **Analysis Agnostic**: Supports multiple analysis strategies (heuristic, symbolic, debug-assisted)

### 1.2 Core Principles

1. **Truth Separation**: Raw binary = immutable source; IR = derived, cacheable truth
2. **Identity First**: Every node has stable identity before it has properties
3. **Dependency Tracking**: Every node knows which analyses produced it
4. **Lazy Precision**: Start with conservative types, refine through propagation

---

## 2. Identity System

### 2.1 Entity IDs

IR entities use strongly-typed IDs to prevent accidental mixing:

```cpp
enum class FunctionId : uint32_t { Invalid = 0xFFFFFFFF };
enum class InstructionId : uint32_t { Invalid = 0xFFFFFFFF };
// ... etc
```

**Properties:**
- Dense allocation (0..N-1) for array-based storage
- Validity check via `Invalid` sentinel
- `EntityIdHasher` for unordered_map/unordered_set

### 2.2 Content Hash

For deterministic reconstruction and deduplication:

```cpp
struct ContentHash {
    std::array<uint8_t, 16> bytes;  // 128-bit hash
};
```

**Computation Rules:**
- **Instruction sequences**: Hash of (bytes + length + address modulo ASLR)
- **Basic blocks**: Hash of concatenated instruction hashes
- **Types**: Hash of canonical type descriptor string
- **Strings**: Hash of normalized (UTF-8, null-terminated) content

**Usage:**
- Deduplicate identical basic blocks across functions
- Stable references across re-analysis
- Session file integrity verification

### 2.3 Identity Version

For incremental analysis and provenance tracking:

```cpp
struct IdentityVersion {
    uint32_t stage_sequence;     // Monotonic per analysis run
    uint64_t timestamp;          // For debugging
    uint32_t pass_iteration;     // For iterative passes (type propagation)
};
```

**Version Assignment:**
1. Analysis run begins: `run_seed = hash(binary_path + timestamp)`
2. Each stage increments `stage_sequence`
3. Iterative passes (type propagation) increment `pass_iteration`
4. Nodes created in stage N have version.stage_sequence = N

### 2.4 IRNodeIdentity

Every IR node embeds:

```cpp
struct IRNodeIdentity {
    ContentHash content_hash;      // Persistent identity
    DependencyMask dependencies;   // Which stages created this
    IdentityVersion version;       // When created
    DirtyFlag dirty_flag;          // Invalidation state
    uint32_t type_pass_count;      // Type inference progress
};
```

**DirtyFlag States:**
- `Clean` - Node is valid and up-to-date
- `NeedsUpdate` - Recompute derived data (e.g., after binary patch)
- `NeedsRebuild` - Structural dependencies changed
- `Invalid` - Node should be removed

---

## 3. Dependency Tracking

### 3.1 Dependency Mask

32-bit bitmask of `AnalysisStageDependency`:

```cpp
enum class AnalysisStageDependency : uint32_t {
    ParsePE = 0,          // PE header parsing
    MapSections = 1,      // Section boundary detection
    ScanFunctions = 2,    // Prologue heuristic scan
    Disassemble = 3,    // Instruction decoding
    BuildBasicBlocks = 4, // BB detection
    BuildCFG = 5,         // Control flow graph
    AnalyzeXRefs = 6,     // Cross-reference analysis
    TypeInference = 7,    // Type propagation (iterative)
    DataFlow = 8,         // Data flow analysis
    // ... 32 total slots
};
```

### 3.2 Invalidation Rules

When stage `S` re-runs:

```
for each node in IR:
    if node.identity.dependencies.has(S):
        if S is non-destructive (e.g., type inference):
            node.identity.dirty_flag = NeedsUpdate
        else:
            node.identity.dirty_flag = NeedsRebuild

// Cascade: mark all dependents of dirty nodes
do {
    changed = false
    for each edge (A -> B) in dependency graph:
        if A.is_dirty() and !B.is_dirty():
            B.mark_dirty(NeedsUpdate)
            changed = true
} while changed
```

### 3.3 Stable References

References that survive re-analysis:

```cpp
template<typename IdType>
struct StableRef {
    ContentHash content_hash;       // Persistent
    IdType current_id;              // May change
    IdentityVersion last_seen_version;
};
```

**Resolution Algorithm:**
1. If `current_id` is valid and node at that ID has matching `content_hash` → resolved
2. Search index for `content_hash` → update `current_id`
3. If node not found → reference is dangling (null)

---

## 4. Address Space Model

### 4.1 Address Spaces

Every address lives in exactly one space:

| Space | Description | Use Case |
|-------|-------------|----------|
| `File` | Byte offset in file | Raw I/O, patching |
| `Section` | Offset within section | Position-independent code |
| `RVA` | Relative Virtual Address | PE standard |
| `Image` | Virtual Address (RVA + preferred base) | Static analysis |
| `Runtime` | Actual runtime VA | Debugging, ASLR |

### 4.2 QualifiedAddress

```cpp
struct QualifiedAddress {
    uint64_t offset;
    AddressSpace space;
    SectionId section;  // For Section space
};
```

**Invariants:**
- `space == Section` → `section != Invalid`
- `space == File` → `offset < file_size`
- `space == RVA` → `offset < image_size`

### 4.3 Translation Rules

**File ↔ RVA:**
```
For section containing file_offset:
    rva = section.rva + (file_offset - section.file_offset)
```

**RVA ↔ Image:**
```
va = preferred_image_base + rva
```

**Image ↔ Runtime:**
```
runtime_va = runtime_base + (va - preferred_base)
```

**Section Space:**
```
file_offset = section.file_offset + section_offset
```

### 4.4 Translation Failures

Returns `nullopt` for:
- File offset outside any section → no RVA
- Unmapped regions (PE headers, padding)
- Runtime space before rebasing known
- Cross-space queries (file → section for non-section data)

---

## 5. IR Entities

### 5.1 Binary (Root)

The `ir::Binary` class owns all entities for a loaded file.

**Storage Model:**
```cpp
class Binary {
    // Stable pointer storage
    std::vector<std::unique_ptr<Section>> sections_;
    std::vector<std::unique_ptr<Function>> functions_;
    // ... etc
    
    // Fast lookup indexes
    std::unordered_map<uint64_t, SectionId> section_by_rva_;
    std::unordered_map<uint64_t, FunctionId> function_by_va_;
    std::unordered_map<ContentHash, BasicBlockId, ContentHashHasher> bb_by_content_;
};
```

**Entity Creation:**
1. Allocate `unique_ptr<T>` in storage vector
2. Assign ID (vector index)
3. Set identity (content_hash, dependencies, version)
4. Update indexes

### 5.2 Section

```cpp
struct Section {
    SectionId id;
    BinaryId parent_binary;
    IRNodeIdentity identity;
    
    std::string name;
    QualifiedAddress file_offset;
    QualifiedAddress rva;
    QualifiedAddress virtual_addr;
    uint32_t virtual_size;
    uint32_t raw_size;
    uint32_t characteristics;
    
    bool is_executable;
    bool is_writable;
    bool is_readable;
    
    // Populated by analysis
    std::vector<FunctionId> functions;
    std::vector<SymbolId> data_symbols;
};
```

### 5.3 Function

```cpp
struct Function {
    FunctionId id;
    SectionId section;
    SymbolId symbol;
    IRNodeIdentity identity;
    
    QualifiedAddress start_address;
    QualifiedAddress end_address;
    
    // Control flow graph
    std::vector<BasicBlockId> basic_blocks;
    BasicBlockId entry_block;
    
    // Cross-references (populated by AnalyzeXRefs)
    std::vector<XRef> calls_in;
    std::vector<XRef> calls_out;
    
    // Type analysis (populated by TypeInference)
    StackFrameId stack_frame;
    TypeId return_type;
    std::vector<TypeId> parameter_types;
    
    enum class Type { Standard, Thunk, Imported, Exported };
    Type type = Type::Standard;
};
```

### 5.4 BasicBlock

```cpp
struct BasicBlock {
    BasicBlockId id;
    FunctionId parent_function;
    IRNodeIdentity identity;
    
    QualifiedAddress start_address;
    QualifiedAddress end_address;
    
    std::vector<InstructionId> instructions;
    
    // CFG edges
    std::vector<BasicBlockId> successors;
    std::vector<BasicBlockId> predecessors;
    
    // Properties
    bool is_entry;
    bool is_exit;  // Returns or tail-calls
    
    // Merge point for type propagation
    std::vector<TypeVariableId> incoming_types;  // One per predecessor
};
```

### 5.5 Instruction

```cpp
struct Instruction {
    InstructionId id;
    BasicBlockId parent_bb;
    IRNodeIdentity identity;
    
    QualifiedAddress address;
    uint8_t length;
    
    // Disassembly
    std::string mnemonic;
    std::string operands_text;
    std::vector<Operand> operands;
    
    // Raw bytes (view only, owned by BinaryFile)
    struct { const uint8_t* data; uint32_t size; } bytes;
    
    // Control flow
    bool is_branch;
    bool is_call;
    bool is_return;
    bool is_conditional;
    
    // References from this instruction
    std::vector<XRef> outgoing_refs;
    
    // Type analysis (populated incrementally)
    std::vector<TypeVariableId> operand_types;
    TypeVariableId result_type;
};
```

### 5.6 Symbol

```cpp
struct Symbol {
    SymbolId id;
    IRNodeIdentity identity;
    
    std::string name;
    std::string demangled_name;
    QualifiedAddress address;
    
    enum class Type { Unknown, Function, Data, Import, Export, String, VTable };
    Type type;
    
    TypeId type_info;  // For data symbols
    std::string source_dll;  // For imports
    
    // String metadata
    struct {
        std::string content;
        bool is_unicode;
    } string_data;
};
```

### 5.7 XRef (Cross-Reference)

```cpp
struct XRef {
    enum class Type { Call, Jump, DataRead, DataWrite, Pointer };
    Type type;
    
    QualifiedAddress from_address;
    InstructionId from_instruction;
    
    QualifiedAddress to_address;
    std::variant<std::monostate, FunctionId, BasicBlockId, SymbolId> target;
};
```

---

## 6. Type System

### 6.1 BaseType Lattice

```
Unknown
├── Void
├── Bool
├── Char | WideChar
├── Int8 | Int16 | Int32 | Int64
├── UInt8 | UInt16 | UInt32 | UInt64
├── Float32 | Float64
├── Pointer → (pointee: TypeId)
│   ├── CodeAddr
│   ├── DataAddr
│   ├── StringPtr
│   └── VTablePtr
├── Struct → (fields: TypeInfo)
├── Array → (element: TypeId, count: uint32)
└── FunctionPtr
```

### 6.2 TypeVariable

```cpp
struct TypeVariable {
    uint32_t id;
    BaseType inferred_type;
    std::vector<TypeConstraint> constraints;
    bool is_final;
    
    enum class Source { Register, StackSlot, GlobalAddr, ... };
    Source source;
    
    std::string name;  // e.g., "rax", "[rbp-8]"
    InstructionId def_site;
};
```

### 6.3 Constraint Types

- `MustBe(BaseType)` - Exact type required
- `MustBeBaseType(BaseType)` - Must be specific base (e.g., any int)
- `PointerTo(TypeId)` - Pointer to specific type
- `SameAs(TypeVariableId)` - Must match another variable

### 6.4 Type Propagation Algorithm

```
// Phase 1: Initialization
for each instruction:
    for each operand:
        create TypeVariable with constraint from opcode

// Phase 2: Iterative constraint solving
changed = true
iteration = 0
while changed and iteration < MAX_ITERATIONS:
    changed = false
    for each type_variable:
        new_type = resolve_constraints(var.constraints)
        if new_type != var.inferred_type:
            var.inferred_type = new_type
            changed = true
    iteration++

// Phase 3: Widen and finalize
for each type_variable:
    if iteration >= MAX_ITERATIONS:
        var.inferred_type = widen(var.inferred_type)  // Conservative
    var.is_final = true
```

---

## 7. Serialization Format

### 7.1 Session File Structure

```
ATLUS_SESSION_v1
├── Header
│   ├── magic: "ATLUSv1"
│   ├── binary_path (relative or absolute)
│   ├── binary_hash (SHA-256 for integrity)
│   └── creation_timestamp
├── IR Entities (protobuf/msgpack)
│   ├── sections[]
│   ├── functions[]
│   ├── basic_blocks[]
│   ├── instructions[]
│   ├── symbols[]
│   ├── types[]
│   └── xrefs[]
├── Indexes (optional, can be rebuilt)
│   ├── symbol_by_name
│   └── xref_by_address
└── UI State (separate, non-essential)
    ├── panel_layout
    └── navigation_history
```

### 7.2 Entity Serialization

Every entity includes:
1. ID
2. Identity (content_hash, dependencies, version)
3. Core properties
4. Relationship IDs (as foreign keys)

**References:**
- Store IDs, not pointers
- Content hash for validation on load
- Skip UI state (transient)

### 7.3 Deterministic Rules

- Entity order: sort by content_hash before serialization
- ID remapping: IDs are session-local, regenerated on load
- Address translation: store all addresses as RVA (portable)
- Strings: UTF-8, normalized line endings

---

## 8. Query System

### 8.1 Query Types

**By Address:**
- `find_function_at(QualifiedAddress)` → FunctionId
- `find_symbol_at(QualifiedAddress)` → SymbolId
- `find_instruction_at(QualifiedAddress)` → InstructionId

**By Content:**
- `find_symbols_by_name(pattern, match_type)` → SymbolId[]
- `find_strings_by_content(pattern)` → SymbolId[]

**By Relationship:**
- `find_xrefs_to(FunctionId)` → XRef[]
- `find_callers(FunctionId)` → FunctionId[]
- `find_callees(FunctionId)` → FunctionId[]

**Graph Queries:**
- `get_cfg(FunctionId)` → BasicBlockId[] + edges
- `get_dominators(BasicBlockId)` → BasicBlockId[]
- `get_call_graph()` → FunctionId[] + call edges

### 8.2 Index Requirements

| Index | Key Type | Value Type | Usage |
|-------|----------|------------|-------|
| symbol_by_name | string | SymbolId | Name lookup |
| symbol_by_va | uint64_t | SymbolId | Address reverse lookup |
| function_by_va | uint64_t | FunctionId | Address lookup |
| instruction_by_va | uint64_t | InstructionId | Address lookup |
| string_by_content | string_hash | SymbolId[] | String search |
| xref_incoming | uint64_t | XRef[] | Reference search |
| xref_outgoing | uint64_t | XRef[] | Reference search |
| bb_by_content | ContentHash | BasicBlockId | Deduplication |

---

## 9. Implementation Contract

### 9.1 Required Implementations

Every IR entity requires:

1. **Storage** - `std::unique_ptr<T>[]` in `ir::Binary`
2. **Creation** - Factory method with identity assignment
3. **Lookup** - Index maintenance on creation
4. **Serialization** - To/from session format
5. **Validation** - Consistency checks (debug builds)

### 9.2 Invariants

**Pointer Stability:**
- `unique_ptr` in vector is never relocated
- Returned `const T*` remains valid until Binary destroyed

**ID Stability:**
- IDs are dense array indices
- Never reused after entity deletion (compaction pass renumbers)

**Index Consistency:**
- All indexes updated synchronously with entity creation
- Indexes rebuilt from scratch if corrupted

### 9.3 Error Handling

- Invalid ID access → nullptr (not exception)
- Translation failure → std::nullopt
- Missing index → transparent rebuild
- Identity mismatch → mark dirty, request re-analysis

---

## 10. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0-alpha | 2024 | Initial specification |

---

## Appendix A: Glossary

- **IR**: Intermediate Representation
- **ID**: Entity identifier (dense uint32)
- **Content Hash**: 128-bit hash of node content
- **QualifiedAddress**: Address with explicit space
- **XRef**: Cross-reference between addresses
- **TypeVariable**: Placeholder for type inference
- **AnalysisStage**: Discrete analysis pass in pipeline
- **DirtyFlag**: Invalidation state of IR node
