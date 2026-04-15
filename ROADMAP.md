# Atlus Roadmap

A comprehensive development plan for the Atlus binary diff and reverse engineering workbench.

---

## Table of Contents

1. [Core Features Roadmap](#core-features-roadmap) - Essential functionality organized by phase
2. [Optional Features](#optional-features) - Prioritized by importance
3. [Design Philosophy](#design-philosophy) - Guiding principles
4. [Best Practices](#best-practices) - Development standards

---

## Core Features Roadmap

### Phase 1: Foundation (Current State - v1.0)

| Feature | Status | Notes |
|---------|--------|-------|
| PE32/PE32+ parsing | Complete | Full header, section, import parsing via LIEF |
| Binary loading | Complete | Zero-copy container with bounds checking |
| x86/x64 disassembly | Complete | Zydis integration with control flow classification |
| Function detection | Complete | Prologue heuristic scanning |
| Four-level diff engine | Complete | Byte, section, function, AOB |
| Pattern scanner | Complete | IDA/CE-style signature generation |
| Dockable ImGui UI | Complete | 8 panels with persistence |
| Ghidra decompiler | Complete | Async subprocess integration |
| Settings persistence | Complete | INI-based configuration |
| Recent files | Complete | Persistent list with MRU ordering |

### Phase 2: Stability & Infrastructure (v1.1 - v1.2)

**Theme:** Build the semantic backbone that everything else depends on.

#### v1.1 - Core Truth Model (Foundation First)

| Feature | Priority | Description |
|---------|----------|-------------|
| **Atlus IR Spec v1** | **P0** | Complete spec: struct definitions, ownership, identity rules, serialization, invalidation rules, address space model (see `docs/ATLUS_IR_SPEC_V1.md`) |
| **IR Identity Contract** | **P0** | Deterministic identity stability rule (Option A): content-derived, portable, stable across sessions (see `docs/IR_IDENTITY_CONTRACT.md`) |
| **Unified IR Design** | **P0** | `ir.h`: Canonical entities with stable IDs |
| **IR Entity Governance** | **P0** | `ir_governance.h`: Identity/Ownership/Mutation/Invalidation rules per entity (prevents "data dump graph") |
| **IR Identity + Versioning** | **P0** | `ir_identity.h`: ContentHash, IdentityVersion, DependencyMask, DirtyFlag |
| **Truth Separation Rule** | **P0** | Enforce: Raw binary = immutable source; IR = derived cacheable truth; UI = projection only |
| Error handling overhaul | **P0** | Consistent error propagation, user-friendly messages |

#### v1.2 - Address Model + Pipeline + Type System

| Feature | Priority | Description |
|---------|----------|-------------|
| **Address Space Model** | **P0** | `address_space.h`: SegmentMapping, BaseAddressModel, RelocationTable, File/Section/RVA/Image/Runtime with full translation |
| **Pipeline Invalidation Matrix** | **P0** | Formal invalidation rules: Change Type → Invalidates table, cascade semantics (see `docs/PIPELINE_INVALIDATION_MATRIX.md`) |
| **Invalidation Engine** | **P0** | `invalidation.h`: Explicit triggers, invalidation rules, cascade logic |
| **Analysis Pipeline DAG** | **P0** | `analysis_pipeline.h`: Dependency graph, stage invalidation, incremental re-computation |
| **Type System Behavior** | **P0** | Minimal v1: inference direction, conflict resolution, pointer propagation (see `docs/TYPE_SYSTEM_BEHAVIOR.md`) |
| **Type System Scaffolding** | **P0** | `type_system.h`: BaseType, TypeVariable, StackFrame, CallingConvention |
| **Index Semantic Contract** | **P0** | Index = derived, lossy, non-authoritative; rebuildable from IR (see `docs/INDEX_SEMANTIC_CONTRACT.md`) |
| **Global Indexing System** | **P0** | `index.h`: Symbol index, instruction index, string index, xref index |
| **Query Layer** | **P0** | `query.h`: Unified API over IR+Index+Pipeline. "SQL layer over IR graph" |
| **Caching Boundary Contract** | **P0** | What is cacheable vs recomputed; tiered storage; invalidation strategy (see `docs/CACHING_BOUNDARY_CONTRACT.md`) |
| **IR Serialization** | **P1** | Deterministic session format (session file v1) |
| Multi-threaded analysis | **P1** | Parallel function detection, parallel diff |
| Disassembly caching | **P1** | Persistent SQLite cache of disassembly results |
| Incremental diff | **P1** | Only re-analyze changed regions using pipeline invalidation |
| Lazy loading | **P2** | On-demand section loading for large files |
| Large file support | **P2** | Memory-mapped files for >500MB binaries |
| Crash recovery | **P2** | Auto-save session state, restore on crash |
| Navigation primitives | **P2** | History back/forward, bookmarks, global search |
| GPU acceleration | **P3** | CUDA/OpenCL for pattern scanning |

### Phase 3: Analysis Depth (v1.3 - v1.5)

#### v1.3 - Advanced Disassembly + Type System Foundation

| Feature | Priority | Description |
|---------|----------|-------------|
| Control flow graphs | **P0** | Visual CFG generation per function |
| Basic block detection | **P0** | Build BBs from branch analysis |
| Cross-reference browser | **P0** | Navigate calls/data references globally |
| **Type System Scaffolding** | **P1** | `type_system.h`: BaseType, TypeVariable, StackFrame, CallingConvention - minimal v1 stub for future propagation |
| String references | **P1** | Auto-detect string literals, XRef tracking |
| Switch table recovery | **P1** | Jump table analysis for switch statements |
| Exception handling | **P2** | Parse x64 unwind info, SEH tables |

#### v1.4 - Data Analysis

| Feature | Priority | Description |
|---------|----------|-------------|
| Structure parsing | **P0** | Common structures (vtable, RTTI, strings) |
| Import reconstruction | **P1** | Rebuild import tables from IAT scans |
| Export analysis | **P1** | Export table with ordinals, forwarders |
| Resource parsing | **P2** | PE resources (icons, manifests, version) |
| TLS callback detection | **P2** | Thread-local storage callbacks |
| Relocation analysis | **P2** | Base relocation table parsing |

#### v1.5 - Patching & Modification

| Feature | Priority | Description |
|---------|----------|-------------|
| Byte patching | **P0** | In-hex-view patch with undo/redo |
| Patch application | **P0** | Export modified binary |
| NOP insertion | **P1** | Auto-relocate following code on NOP |
| Code cave detection | **P1** | Find usable slack space in binary |
| Assembly injection | **P2** | Type asm, auto-assemble to bytes (keystone) |
| Diff patch format | **P2** | Export/import BPS/IPS/xdelta patches |

### Phase 4: Interoperability (v2.0)

| Feature | Priority | Description |
|---------|----------|-------------|
| IDA Pro integration | **P0** | Import/export .idb, .i64 databases |
| x64dbg bridge | **P0** | Live debugging session integration |
| Ghidra server | **P1** | Direct Ghidra project import/export |
| JSON API | **P1** | Headless mode with structured output |
| Plugin system | **P2** | C++ plugin SDK for custom analyzers |
| Python scripting | **P2** | Embedded Python for automation |

### Phase 5: Extended Formats (v2.1 - v2.2)

| Feature | Priority | Description |
|---------|----------|-------------|
| ELF support | **P0** | Linux binary parsing (leverage LIEF) |
| Mach-O support | **P0** | macOS binary parsing |
| Raw firmware | **P1** | Base-address configurable raw binary |
| Archive parsing | **P2** | .lib, .a static library browsing |
| PDB parsing | **P2** | Microsoft debug symbol integration |
| DWARF parsing | **P3** | ELF debug symbol support |

---

## Optional Features

Sorted by importance (impact vs. effort ratio).

### Tier 1: High Impact, Medium Effort

| Rank | Feature | Value | Description |
|------|---------|-------|-------------|
| 1 | **Bookmarks/Annotations** | High | User-defined labels, comments on addresses. Persistent per-file hash. |
| 2 | **History Navigation** | High | Back/forward navigation through clicked locations (Alt+Left/Right). |
| 3 | **Search Everywhere** | High | Global search: strings, bytes, instructions, regex across all sections. |
| 4 | **Type System** | High | Define C structs, apply to offsets, visualize in hex view. |
| 5 | **Call Graph** | High | Visual graph of function call relationships (ImGui node editor). |
| 6 | **Entropy Analysis** | Medium | Section entropy visualization, packed/encrypted detection. |
| 7 | **YARA Integration** | Medium | YARA rule scanning for malware signatures. |
| 8 | **Compare Folders** | Medium | Batch diff across multiple file versions. |
| 9 | **Export Reports** | Medium | HTML/PDF analysis reports with diff summary. |
| 10 | **Theme Editor** | Low | Custom color schemes beyond Dark/Light/Classic. |

### Tier 2: Medium Impact, Variable Effort

| Rank | Feature | Value | Description |
|------|---------|-------|-------------|
| 11 | **Hex Color Maps** | Medium | Color bytes by type (code/data/unknown) from analysis. |
| 12 | **Inline Editing** | Medium | Edit disassembly instructions directly. |
| 13 | **Function Signatures** | Medium | FLIRT-style signature matching for library code. |
| 14 | **Stack Variable Recovery** | Medium | Local variable naming from stack frame analysis. |
| 15 | **Decompiler Comparison** | Medium | Side-by-side Ghidra/Hex-Rays/Retdec output. |
| 16 | **API Monitor Template** | Medium | Predefined hook points for common APIs. |
| 17 | **Binary Templates** | Low | 010 Editor-style template parsing. |
| 18 | **Tainting Engine** | Low | Data flow tainting from sources to sinks. |
| 19 | **Symbolic Execution** | Low | Basic path exploration for key functions. |
| 20 | **Collaboration** | Low | Multi-user annotation sharing (server-based). |

### Tier 3: Specialized/Nice-to-Have

| Rank | Feature | Value | Description |
|------|---------|-------|-------------|
| 21 | **Malware Scoring** | Low | Heuristic scoring based on IoC detection. |
| 22 | **Unpacker Detection** | Low | Common packer signature matching (UPX, Themida, etc). |
| 23 | **VTable Recovery** | Low | C++ virtual table reconstruction. |
| 24 | **Mangled Name Demangling** | Low | MSVC/Itanium C++ symbol demangling. |
| 25 | **Dependency Graph** | Low | DLL dependency visualization. |
| 26 | **Overlay Detection** | Low | Detect appended data after PE EOF. |
| 27 | **Certificate Validation** | Low | Authenticode signature verification. |
| 28 | **SRE Workflow Guide** | Low | Built-in tutorial/walkthrough mode. |
| 29 | **Command Palette** | Low | VS Code-style quick command access (Ctrl+Shift+P). |
| 30 | **Minimap** | Low | Overview minimap for hex/disassembly views. |

---

## Design Philosophy

### Core Principles

1. **Performance First**
   - Every millisecond matters when analyzing 100MB+ binaries
   - Lazy evaluation: compute only what's visible
   - Cache aggressively: memory is cheaper than recomputation
   - Zero-copy where possible: avoid unnecessary buffer duplication

2. **Reverse Engineering Workflow**
   - Design for the analyst's mental model, not the implementation's convenience
   - Context preservation: never lose the user's place during navigation
   - Progressive disclosure: show summary first, detail on demand
   - Keyboard-centric: every action must have a hotkey

3. **Deterministic & Reproducible**
   - Same input → same output, always
   - Session files capture complete analysis state
   - No "magic": every automated decision must be explainable

4. **Truth Separation Rule (Critical)**
   - **Raw binary data** = immutable source of truth (never modified)
   - **IR** = derived, cacheable, invalidatable truth
   - **UI** = projection only, never drives analysis state
   - **Analysis outputs** = reproducible derivations, not primary state
   - This prevents: UI-driven corruption, inconsistent edits, diff engine desync

5. **Extensibility Through Clarity**
   - Clean separation between core engine and UI
   - Headers document their contracts exhaustively
   - Plugin API mimics internal interfaces
   - Prefer composition over inheritance

6. **Defensive Against Malicious Input**
   - PE files are attack surface: parse with suspicion
   - All bounds-checked, all pointers validated
   - Fuzz-tested parsers for core formats
   - Graceful degradation: partial analysis > total failure

### UI Philosophy (Dear ImGui)

- **Immediate Mode Clarity**: UI state is transient, source of truth is the model
- **Docking Freedom**: Users arrange space to match their workflow
- **Visual Density**: Information-rich displays with consistent color coding
- **Consistent Feedback**: Every action has visible result or explicit error

### Code Organization

```
atlus_core
  /ir              → UNIFIED IR: Binary, Section, Function, BasicBlock, Instruction, Symbol, XRef, TypeInfo
    ir.h                 → Core entities and relationships
    ir_identity.h        → ContentHash, IdentityVersion, DependencyMask, DirtyFlag
    ir_governance.h      → Entity governance rules (identity/ownership/mutation/invalidation per entity)
    address_space.h      → SegmentMapping, BaseAddressModel, RelocationTable, 5-space translation
    type_system.h        → TypeVariable, StackFrame, CallingConvention, TypePropagation
  /pipeline        → Analysis DAG: stage dependencies, invalidation, incremental re-computation
    analysis_pipeline.h  → Pipeline DAG structure
    invalidation.h         → Explicit invalidation triggers and rules
  /query           → "SQL layer over IR graph"
    query.h                → Unified API: QueryBuilder, predefined queries, query plans
  /index           → Search + caching: symbol index, xref index, string index
  /analysis        → CFG, xrefs, functions, diff (operates on IR entities)
  /formats         → PE, ELF, Mach-O parsers (populate IR)

docs/
  ATLUS_IR_SPEC_V1.md    → Complete IR specification (contract for all implementations)
  IR_TRANSITION_GUIDE.md → Migration path from current codebase

atlus_runtime
  /threading       → Thread pools, work queues
  /memory_map      → Memory-mapped file abstraction
  /cache           → Persistent SQLite cache

atlus_ui
  /imgui_panels    → Dear ImGui panel implementations
  /navigation      → History, bookmarks, search UI
  /state_sync      → UI state separate from IR state

atlus_plugins    → Extension system (post-IR stabilization)
atlus_tests      → Comprehensive test suite
```

**Key Architectural Components:**
- `ir_governance.h`: Per-entity rules preventing "IR inflation" (identity/ownership/mutation/invalidation)
- `invalidation.h`: Executable invalidation semantics (binary change→full reset, disasm change→CFG only, etc.)
- `query.h`: Query Layer - "SQL over IR graph" - unified API for UI/CLI/plugins
- `address_space.h`: Full segment model with BaseAddressModel, RelocationTable for PE/ELF/Mach-O consistency
- `type_system.h`: Early propagation scaffolding (BaseType, TypeVariable, constraint solving stub)
- IR Spec v1 defines deterministic contracts for serialization and reconstruction

---

## Best Practices

### Development Standards

#### Code Style

- **Language**: C++20 minimum, C++23 where supported
- **Formatting**: 4-space indent, 120 char line limit, Allman braces
- **Naming**:
  - `snake_case` for functions, variables, members
  - `PascalCase` for types, classes, structs, enums
  - `SCREAMING_SNAKE_CASE` for macros, constants
  - `m_` prefix for member variables
  - `g_` prefix for global variables (use sparingly)

#### Documentation

```cpp
/**
 * @brief One-line summary
 * @param name Description of parameter
 * @return Description of return value
 * @throws Never, or specific exceptions
 * @pre Conditions that must be true before call
 * @post Conditions guaranteed after call
 * @note Additional important information
 */
```

#### Error Handling

```cpp
// Use Result<T, E> pattern for recoverable errors
Result<FunctionList, AnalysisError> analyze_functions(const PEFile& pe);

// Exceptions for programmer errors (logic_error)
// Status codes for user-actionable failures
// Never swallow exceptions silently
```

### Architecture Patterns

#### State Management

```cpp
// IR is the single source of truth for all analysis state
using BinaryIR = std::shared_ptr<ir::Binary>;

// All analysis outputs are artifacts in the pipeline cache
// Access via: binary->get_function(id), binary->get_instruction(id)

// UI state is strictly separate (transient only)
gui_state.h  → transient UI (selections, scroll positions, panel visibility)
ir::Binary   → persistent analysis (functions, BBs, instructions, xrefs)
pipeline     → reproducible derivations (CFG, computed analysis)

// Example: Getting a function's instructions
FunctionId fn_id = ...;
const Function* fn = binary->get_function(fn_id);
for (InstructionId insn_id : fn->instructions) {
    const Instruction* insn = binary->get_instruction(insn_id);
    // Use insn->mnemonic, insn->operands, etc.
}
```

#### Threading Model

```cpp
// Thread pool for CPU-bound analysis
ThreadPool g_analysis_pool{std::thread::hardware_concurrency()};

// Main thread: UI only
// Background threads: analysis tasks only
// Lock-free queues for UI ↔ worker communication
```

### Testing Requirements

| Component | Test Type | Coverage Target |
|-----------|-----------|-----------------|
| PE Parser | Fuzz + Unit | 100% branch coverage |
| Diff Engine | Property-based | All edge cases |
| Pattern Scanner | Unit + Golden | Reference output match |
| Disassembler | Integration | Round-trip correctness |
| UI | Manual + Screenshot | Critical paths |

### Security Checklist

Before any release:

- [ ] Fuzz test all file parsers with AFL/libFuzzer
- [ ] Run with AddressSanitizer, UBSan, ThreadSanitizer
- [ ] Review all `memcpy`/`memset` for size calculations
- [ ] Validate all integer arithmetic for overflow
- [ ] Check all `new` allocations for null (or use `nothrow`)
- [ ] Audit subprocess calls (decompiler) for injection
- [ ] Verify no secrets in binaries (API keys, paths)

### Version Numbering

Semantic Versioning: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes to file format or API
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, performance improvements

Release branches: `release/v1.x`
Feature branches: `feature/short-description`

### Performance Budgets

| Operation | Target | Maximum |
|-----------|--------|---------|
| Load 50MB PE | 100ms | 500ms |
| Disassemble 1000 functions | 500ms | 2s |
| Full diff (two 50MB files) | 2s | 10s |
| UI frame time | 8ms | 16ms |
| Memory overhead | 2x file size | 4x file size |

---

## Summary

**Immediate Priorities (Next 3 Months)**
1. **Atlus IR Spec v1** - Define the contract (struct definitions, identity rules, serialization, invalidation rules, address spaces)
2. **IR Entity Governance** (`ir_governance.h`) - Per-entity identity/ownership/mutation/invalidation rules
3. **IR Identity + Versioning** (`ir_identity.h` implementation) - ContentHash, DependencyMask, DirtyFlag
4. **Address Space Model** (`address_space.h` implementation) - SegmentMapping, BaseAddressModel, RelocationTable for 5-space translation
5. **Invalidation Engine** (`invalidation.h` implementation) - Explicit triggers and executable invalidation rules
6. **Analysis Pipeline DAG** (`analysis_pipeline.h` implementation)
7. **Type System Scaffolding** (`type_system.h` implementation) - Early propagation boundary
8. **Query Layer** (`query.h` implementation) - "SQL over IR graph"
9. **Global Indexing System** (`index.h` implementation)
10. Error handling overhaul, IR serialization, multi-threading, large file support

**Medium Term (6-12 Months)**
1. Control flow graphs and basic block detection
2. x64dbg live debugging integration
3. IDA database import/export
4. ELF and Mach-O format support

**Long Term (1-2 Years)**
1. Plugin SDK and Python scripting
2. Advanced decompiler integration (Hex-Rays)
3. Collaborative analysis features
4. Symbolic execution engine

---

*Last updated: 2024*
*Maintainers: See CONTRIBUTORS.md*
