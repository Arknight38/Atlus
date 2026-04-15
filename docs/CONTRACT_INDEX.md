# Atlus Architecture Contract Index

**Version:** 1.0  
**Date:** 2024

This document lists all formal contracts governing the Atlus architecture.

---

## Core IR Contracts

### 1. ATLUS_IR_SPEC_V1.md
**Purpose:** Complete IR specification  
**Contains:**
- Entity struct definitions (Function, BB, Instruction, Symbol, XRef, TypeInfo)
- Ownership and storage model
- Identity system mechanics (ContentHash, IdentityVersion)
- Dependency tracking and invalidation algorithms
- 5-space address model with translation formulas
- Type propagation algorithm
- Session file serialization format
- Query system requirements and index definitions

**Status:** REQUIRED reading for all IR implementers

---

### 2. IR_IDENTITY_CONTRACT.md
**Purpose:** Identity stability rules  
**Contains:**
- Deterministic identity derivation formulas per entity type
- Stability guarantees (content-determined, portable, session-independent)
- Identity collision handling (address tie-breaker)
- Option A vs Option B decision rationale
- Cross-binary identity matching semantics
- Index-IR binding contract (index stores ContentHash)
- Debug validation and violation detection

**Critical Rule:** Identity is content-derived, deterministic, portable, stable across sessions

---

### 3. IR_ENTITY_GOVERNANCE (in ir_governance.h)
**Purpose:** Per-entity governance rules  
**Contains:**
- Function governance (identity formula, ownership, mutation rules, invalidation deps)
- BasicBlock governance (content-addressed, deduplication support)
- Instruction governance (immutable after creation)
- Symbol governance (name-based vs address-based)
- XRef governance (derived only, validated)
- TypeInfo governance (content-based deduplication)
- Entity lifecycle state machine (Pending → Analyzing → Complete → Dirty → Invalid)

**Purpose:** Prevents "IR inflation" - ensures every entity has defined invariants

---

## Pipeline Contracts

### 4. PIPELINE_INVALIDATION_MATRIX.md
**Purpose:** Formal invalidation semantics  
**Contains:**
- Change Type → Invalidated Stages matrix
- Severity levels (Full/Major/Moderate/Minor/Cosmetic/None)
- Cascade rules and propagation graph
- Targeted invalidation algorithms
- State machine (Clean → NeedsUpdate/NeedsRebuild → Clean)
- Execution semantics (deterministic, complete, minimal)
- Correctness guarantees (deterministic, complete, minimal)

**Critical Rule:** Same change produces identical invalidation pattern; no over/under-invalidation

---

### 5. INVALIDATION_ENGINE (in invalidation.h)
**Purpose:** Executable invalidation system  
**Contains:**
- InvalidationTrigger enum (BinaryLoaded, BinaryPatched, etc.)
- InvalidationRule structure
- Predefined rule definitions (documented inline)
- InvalidationEngine class
- IncrementalState tracking
- Address-to-node resolution

**Implements:** PIPELINE_INVALIDATION_MATRIX rules

---

### 6. ANALYSIS_PIPELINE (in analysis_pipeline.h)
**Purpose:** Dependency-aware analysis execution  
**Contains:**
- AnalysisStage enum (all passes)
- StageRunner interface
- AnalysisPipeline DAG manager
- AnalysisContext high-level API

**Note:** Depends on invalidation semantics from PIPELINE_INVALIDATION_MATRIX

---

## Type System Contracts

### 7. TYPE_SYSTEM_BEHAVIOR.md
**Purpose:** Minimal v1 type system behavior  
**Contains:**
- Type inference direction (forward/backward/bidirectional) per source
- Direction conflict resolution (backward wins for external APIs)
- Type conflict resolution (meet operator rules)
- Integer vs Pointer resolution heuristics (priority list)
- Pointer propagation semantics (offset tracking, field accumulation)
- Constraint solving algorithm (single-pass v1, iterative v1.1)
- Stack frame type recovery
- CFG integration (per-BB type state with merge points)

**Critical Rule:** Prevents CFG + struct parsing divergence in Phase 3

---

### 8. TYPE_SYSTEM (in type_system.h)
**Purpose:** Type propagation scaffolding  
**Contains:**
- BaseType lattice
- TypeVariable with constraints
- TypeConstraint types (MustBe, PointerTo, SameAs)
- StackFrame model
- CallingConvention (SystemV, Windows)
- TypePropagation engine stub

**Implements:** TYPE_SYSTEM_BEHAVIOR.md rules

---

## Index and Query Contracts

### 9. INDEX_SEMANTIC_CONTRACT.md
**Purpose:** Index-IR relationship definition  
**Contains:**
- Core principle: Index is derived, lossy, non-authoritative
- What index is ALLOWED to store (ContentHash, keys, versions)
- What index is PROHIBITED from storing (full properties, bytes, disassembly)
- Lookup semantics (returns ContentHash, not direct reference)
- Cache consistency rules (rebuildable from IR)
- Index versioning and staleness detection
- Lossy representation guarantee (information loss policy)
- Performance contracts (lookup complexity, rebuild time)
- Error handling (stale entries, corruption)

**Critical Rule:** Index accelerates; IR authorizes. Index never becomes source of truth.

---

### 10. INDEX (in index.h)
**Purpose:** Fast search and lookup implementation  
**Contains:**
- GlobalIndex in-memory indexes
- PersistentIndex SQLite backend
- SearchQuery/SearchResult unified interface
- Index type definitions

**Implements:** INDEX_SEMANTIC_CONTRACT.md

---

### 11. QUERY_LAYER (in query.h)
**Purpose:** "SQL over IR graph"  
**Contains:**
- QueryResult unified container
- Query filters (AddressFilter, SymbolFilter, FunctionFilter, XRefFilter)
- QueryBuilder fluent interface
- Predefined queries (find_callers, find_callees, etc.)
- QueryContext with caching
- QueryPlan/QueryPlanner optimization

**Purpose:** Unified API for UI/CLI/plugins; prevents direct IR coupling

---

## Caching Contracts

### 12. CACHING_BOUNDARY_CONTRACT.md
**Purpose:** Cacheable vs recomputed definition  
**Contains:**
- Core principle: Cache stores only derived, recomputable data
- Cacheability matrix (what is/isn't cacheable)
- Cacheability decision tree
- Tiered storage (Memory → SQLite → Session)
- Cache key design (ContentHash + config + type)
- Invalidation strategy (version-based, lazy vs eager)
- Consistency levels (strong/eventual/best-effort)
- Performance budgets (hit rate targets, size limits)
- Failure handling (miss, corruption, disk full)
- Security considerations (poisoning prevention)

**Critical Rule:** Cache miss = recompute; corruption = discard; never affects correctness

---

### 13. CACHING_LAYER (implicit in pipeline/analysis)
**Implementation notes:**
- Disassembly caching (SQLite)
- Decompiler result caching
- Query result caching (QueryContext)
- Index caching (GlobalIndex/PersistentIndex)

**Implements:** CACHING_BOUNDARY_CONTRACT.md

---

## Address Space Contracts

### 14. ADDRESS_SPACE_MODEL (in address_space.h)
**Purpose:** 5-space address translation  
**Contains:**
- AddressSpace enum (File, Section, RVA, Image, Runtime)
- QualifiedAddress with space binding
- SegmentMapping (file↔memory abstraction)
- BaseAddressModel (ASLR, rebasing)
- RelocationTable (PE/ELF/Mach-O relocations)
- AddressTranslation engine
- MemoryModel abstraction (PE, firmware, live process)

**Supports:** PE, ELF, Mach-O, firmware, live debugging

---

## Architecture Summary

### Truth Hierarchy

```
Raw Binary (immutable source of truth)
    ↓
IR (derived, cacheable, invalidatable)
    ├─> Index (derived from IR, lossy, rebuildable)
    ├─> Cache (derived from IR, tiered storage)
    ↓
Query Layer (unified API over IR+Index+Cache)
    ↓
UI / CLI / Plugins (projection only)
```

### Contract Enforcement

| Contract | Enforced By |
|----------|-------------|
| Identity stability | `ir_identity.h` + debug validation |
| Invalidation rules | `invalidation.h` + formal matrix |
| Index semantics | `index.h` + rebuildable design |
| Caching boundary | Cache key design + version checking |
| Type behavior | `type_system.h` + constraint solver |
| Address translation | `address_space.h` + translation unit tests |

---

## Implementation Priority

1. **Phase 1:** IR entities + identity system + governance
2. **Phase 2:** Address model + invalidation engine + type scaffolding
3. **Phase 3:** Index + query layer + caching infrastructure
4. **Phase 4:** Analysis passes (CFG, xrefs, type propagation)

---

## Reading Order for New Developers

1. ATLUS_IR_SPEC_V1.md - Understand the data model
2. IR_IDENTITY_CONTRACT.md - Understand identity rules
3. PIPELINE_INVALIDATION_MATRIX.md - Understand change propagation
4. INDEX_SEMANTIC_CONTRACT.md - Understand index relationship
5. CACHING_BOUNDARY_CONTRACT.md - Understand caching rules
6. TYPE_SYSTEM_BEHAVIOR.md - Understand type inference

Then read header files for implementation details.
