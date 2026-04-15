# Unified IR Transition Guide

## What Was Created

Three new header files that form the semantic backbone of Atlus:

### 1. `include/core/ir.h` - The Unified IR
**Purpose:** Single canonical representation for all binary entities.

**Key Entities:**
- `ir::Address` - Universal addressing (file/RVA/VA spaces)
- `ir::Binary` - Root container, owns all entities
- `ir::Section` - Memory region with executable/readable/writable flags
- `ir::Function` - Callable unit with CFG
- `ir::BasicBlock` - Single-entry, single-exit instruction sequence
- `ir::Instruction` - Disassembled instruction with operands
- `ir::Symbol` - Named addresses (functions, imports, exports, strings)
- `ir::XRef` - Cross-references (calls, jumps, data refs)
- `ir::TypeInfo` - Type system for memory interpretation

**Key Design Decisions:**
- Strongly-typed IDs (SectionId, FunctionId, etc.) prevent accidental mixing
- Entity storage in `std::vector<std::unique_ptr<T>>` for stable pointers
- Fast lookup via hash maps (address → ID)
- Relationships stored as ID vectors (not pointers) for serialization

### 2. `include/core/analysis_pipeline.h` - The Analysis DAG
**Purpose:** Dependency-aware, cacheable, incremental analysis.

**Key Components:**
- `AnalysisStage` enum - All analysis passes (ParsePE, BuildCFG, etc.)
- `StageRunner` - Interface for analysis implementations
- `AnalysisPipeline` - DAG execution, caching, invalidation
- `AnalysisContext` - High-level API for running analysis

**Dependency Chain:**
```
LoadBinary → ParsePE → MapSections → ScanFunctionEntries 
    → DisassembleFunctions → BuildBasicBlocks → BuildCFG 
    → AnalyzeXRefs → FindStrings
```

### 3. `include/core/index.h` - Fast Search System
**Purpose:** O(1) lookups and global search across all entity types.

**Key Components:**
- `GlobalIndex` - In-memory indexes for symbol/function/string/xref lookup
- `PersistentIndex` - SQLite-backed for large binaries
- `SearchQuery/SearchResult` - Unified search interface

**Indexes Maintained:**
- Symbol by name (exact, prefix, substring)
- Symbol/function/instruction by address
- String literals by content
- XRefs incoming/outgoing

## Updated Roadmap Priorities

### Phase 2 is now about "Infrastructure & Semantic Backbone"

**v1.1 - Unified IR + Pipeline (NEW P0 items):**
1. Unified IR Design (`ir.h` implementation)
2. Analysis Pipeline DAG (`analysis_pipeline.h` implementation)
3. Truth Separation Rule enforcement
4. Error handling overhaul
5. Large file support
6. Navigation primitives (moved to P0)

**v1.2 - Indexing + Performance:**
1. Global Indexing System (`index.h` implementation)
2. Multi-threaded analysis
3. Address Mapping Abstraction
4. IR Serialization (session format v1)

## Migration Strategy

### Phase 1: IR Foundation (Weeks 1-2)
1. Implement `ir.cpp` - Binary container, entity creation, address mapping
2. Create unit tests for IR entities
3. Add `ir::Address` conversion utilities

### Phase 2: Pipeline Integration (Weeks 3-4)
1. Implement `analysis_pipeline.cpp`
2. Create built-in stage runners for existing analysis
3. Migrate `analyzer.cpp` to use IR entities
4. Migrate `disassembler.cpp` to create IR Instructions

### Phase 3: Index Implementation (Weeks 5-6)
1. Implement `index.cpp` - In-memory indexes
2. Add search UI integration
3. Update navigation (history, bookmarks) to use indexes

### Phase 4: Migration (Weeks 7-8)
1. Gradually replace old structs with IR equivalents
2. Update UI panels to use `ir::Binary*` instead of raw vectors
3. Maintain backward compatibility during transition

## Key Migration Patterns

### Old Pattern:
```cpp
// analyzer.h
struct Function {
    uint64_t start_address;
    std::vector<Instruction> instructions;
    std::vector<XRef> calls_out;
};

// Usage
std::vector<Function> functions = analyzer.find_functions(section, base);
for (const auto& fn : functions) {
    for (const auto& insn : fn.instructions) {
        // process
    }
}
```

### New Pattern:
```cpp
// Usage with IR
ir::Binary binary(path, image_base, is_64bit);

// Pipeline runs stages and populates IR
pipeline.run_all(binary);

// Navigate via IDs
for (ir::FunctionId fn_id : binary.get_section(text_id)->functions) {
    const ir::Function* fn = binary.get_function(fn_id);
    for (ir::InstructionId insn_id : fn->instructions) {
        const ir::Instruction* insn = binary.get_instruction(insn_id);
        // process
    }
}

// Search via index
auto symbols = index.find_symbols_by_name("main");
```

## Benefits After Transition

1. **Single Source of Truth**: All analysis modules work with same entities
2. **Fast Lookup**: Address → entity is O(1) via indexes
3. **Incremental Analysis**: Pipeline only re-runs affected stages
4. **Deterministic Serialization**: IR entities serialize cleanly
5. **Type Safety**: Strong IDs prevent mixing entities
6. **Plugin-Friendly**: Clean API for external analyzers

## Files Modified

- `ROADMAP.md` - Updated Phase 2 priorities, added Truth Separation Rule

## Files Created

- `include/core/ir.h` - Unified IR entities
- `include/core/analysis_pipeline.h` - Analysis DAG system
- `include/core/index.h` - Search and indexing system
- `docs/IR_TRANSITION_GUIDE.md` - This document

## Next Steps

1. Review the header files for design alignment
2. Implement `ir.cpp` (Binary container + entity management)
3. Add unit tests for IR entities
4. Create first pipeline stage (ParsePE)
5. Gradually migrate existing code
