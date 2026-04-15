# IR Identity Stability Contract

**Version:** 1.0  
**Status:** REQUIRED  
**Date:** 2024

---

## 1. Identity Stability Rule (Option A - Deterministic)

**Rule:** IR node identity SHALL be deterministic and derived from semantic content.

### 1.1 Identity Derivation Formula

| Entity | Identity Formula | Components |
|--------|------------------|------------|
| **Function** | `hash(prologue_bytes[0:16] \| start_address \| parent_binary_id)` | First 16 bytes + address + binary context |
| **BasicBlock** | `hash(concat(instruction_hashes) \| start_address)` | Instruction sequence + address |
| **Instruction** | `hash(raw_bytes \| length \| address_space)` | Raw bytes + metadata |
| **Symbol** | `hash(name) \| hash(address)` | Name-based OR address-based |
| **TypeInfo** | `hash(canonical_descriptor)` | Canonical type string |
| **XRef** | `hash(from_addr \| to_addr \| type)` | Relationship tuple |

### 1.2 Stability Guarantees

**GUARANTEE 1: Content-Determined Identity**
```
IF entity.content == entity'.content
THEN entity.identity == entity'.identity
```

**GUARANTEE 2: Session-Independent Identity**
```
Identity SHALL NOT depend on:
- Session ID
- Load timestamp  
- Analysis run count
- Memory address

Identity SHALL depend on:
- Binary content (bytes)
- Semantic structure (CFG, xrefs)
- Virtual addresses (RVA space, portable)
```

**GUARANTEE 3: Incremental Diff Compatibility**
```
IF binary A and binary B have identical function at RVA X
THEN function_A.identity == function_B.identity

This enables:
- Cross-binary function matching
- Persistent bookmarks across versions
- Diff correlation
```

### 1.3 Identity Collision Handling

**Rule:** Content hash collisions resolved by address tie-breaker.

```cpp
// Resolution order:
1. Compare ContentHash (128-bit, collision unlikely)
2. IF collision: compare QualifiedAddress
3. IF still collision: compare parent Binary ID
4. IF still collision: append incremental counter (deterministic)
```

**Collision Rate:** With 128-bit hash, theoretical collision rate is negligible for binary analysis scale (< 10M functions).

### 1.4 Why Not Option B (UUIDs)

| Aspect | Option A (Deterministic) | Option B (UUIDs) |
|--------|-------------------------|------------------|
| Cross-session stability | ✅ Automatic | Requires mapping table |
| Cross-binary matching | ✅ Automatic | Requires correlation pass |
| Incremental diff | ✅ Native | Complex mapping maintenance |
| Implementation complexity | Higher (hash computation) | Lower (random gen) |
| Correctness guarantees | Strong | Heuristic |
| Debugging | Content reveals identity | Opaque UUID |

**Decision:** Option A for correctness guarantees.

---

## 2. Identity Lifecycle Contract

### 2.1 Identity Assignment Timeline

```
Stage 1: Entity Creation
├─ Compute ContentHash from source data
├─ Assign EntityId (dense array index)
├─ Record IdentityVersion (analysis stage + timestamp)
└─ Set DirtyFlag = Clean

Stage 2: Analysis
├─ Entity modified during analysis
├─ IdentityVersion updated per stage
├─ Dependencies tracked in DependencyMask
└─ ContentHash unchanged unless bytes change

Stage 3: Completion
├─ ContentHash finalized
├─ EntityId frozen
├─ IdentityVersion final
└─ DirtyFlag = Clean, is_final = true

Stage 4: Invalidation
├─ Dependency triggered → DirtyFlag = NeedsUpdate
├─ Content change → New entity with NEW identity
└─ Old entity marked Invalid, removed during compaction
```

### 2.2 Identity Persistence Rules

**Rule 1:** ContentHash is the persistent identity across sessions.

**Rule 2:** EntityId is session-local (dense index), regenerated on load.

**Rule 3:** Session file stores ContentHash, not EntityId.

**Rule 4:** On load, rebuild EntityId → ContentHash mapping.

```cpp
// Session file entity record:
struct PersistentEntity {
    ContentHash identity;      // Persistent
    QualifiedAddress address;  // Portable (RVA space)
    DependencyMask deps;       // For invalidation on load
    // ... other properties
    // NOTE: No EntityId stored
};

// Rebuild on load:
EntityId id = binary.create_entity(record.properties);
// Internal: assigns new dense ID, preserves ContentHash
```

---

## 3. Cross-Binary Identity Contract

### 3.1 Cross-Binary Matching

**Use Case:** Diff engine needs to correlate functions between binary A and B.

**Rule:** Functions match IF:
1. ContentHash matches (prologue identical)
2. Relative position in binary similar (optional ranking)
3. Symbol name matches (if available, overrides hash)

**Implementation:**
```cpp
struct CrossBinaryMatch {
    ContentHash identity;           // Matching identity
    FunctionId id_in_binary_a;      // Local to session
    FunctionId id_in_binary_b;      // Local to session
    float confidence;               // 0.0-1.0
};

// Match confidence factors:
// - 1.0: Same ContentHash + same symbol name
// - 0.9: Same ContentHash + similar RVA delta
// - 0.7: Same ContentHash only
// - 0.5: Symbol name match only
```

### 3.2 Portability Constraints

**Rule:** ContentHash MUST NOT include:
- Absolute file paths
- Session timestamps
- Memory addresses
- Analysis tool version

**Rule:** ContentHash MUST include:
- Instruction bytes (stable)
- RVA addresses (relative, portable)
- Binary-specific context (for scoping)

---

## 4. Index Identity Binding

### 4.1 Index Contract

**Rule:** Index entries reference IR entities by **ContentHash**, not EntityId.

**Rationale:** EntityId changes per session. ContentHash is stable.

```cpp
// Index entry:
struct IndexEntry {
    ContentHash entity_identity;  // Stable reference
    std::string key;              // Index key (name, address, etc)
    uint32_t cache_version;       // For cache invalidation
};

// Lookup:
EntityId find_by_name(const std::string& name) {
    ContentHash hash = name_index_.lookup(name);
    return binary_->resolve_identity(hash);  // Current session ID
}
```

### 4.2 Index Rebuild Guarantee

**Rule:** Index SHALL be rebuildable from IR alone.

**Corollary:** Index corruption/loss is non-fatal; rebuild is O(N).

**Implementation:**
```cpp
void GlobalIndex::rebuild(const Binary& binary) {
    clear();
    for (const auto& fn : binary.functions()) {
        index_function(fn);
    }
    for (const auto& sym : binary.symbols()) {
        index_symbol(sym);
    }
    // ... etc
}
```

---

## 5. Enforcement

### 5.1 Debug-Only Identity Validation

```cpp
#ifdef ATLUS_DEBUG_IDENTITY
void validate_identity(const Function& fn) {
    ContentHash computed = FunctionGovernance::compute_identity(...);
    if (computed != fn.identity.content_hash) {
        report_identity_mismatch(fn, computed);
        // Possible causes:
        // - Entity mutated after finalization (BUG)
        // - Hash collision (RARE, needs tie-breaker)
        // - Identity not updated after content change (BUG)
    }
}
#endif
```

### 5.2 Identity Violation Errors

| Violation | Cause | Severity |
|-----------|-------|----------|
| `IDENTITY_CHANGED_AFTER_FINAL` | Entity modified after is_final=true | ERROR |
| `CONTENT_HASH_MISMATCH` | Computed hash != stored hash | WARNING |
| `UNSTABLE_IDENTITY_SOURCE` | Identity depends on unstable data | ERROR |
| `COLLISION_UNRESOLVED` | Hash collision not resolved | ERROR |

---

## 6. Summary

**Core Principle:** Identity is content-derived, deterministic, portable, and stable across sessions.

**Key Properties:**
1. ✅ Deterministic: Same content → same identity
2. ✅ Portable: RVA-based, works across binaries
3. ✅ Stable: Survives re-analysis and session reload
4. ✅ Unique: Collision resolution via address tie-breaker
5. ✅ Verifiable: Debug builds validate identity consistency

**Violations:** Detected in debug builds, fatal in correctness-critical paths.
