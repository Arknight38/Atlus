# Index Semantic Binding Contract

**Version:** 1.0  
**Status:** REQUIRED  
**Date:** 2024

---

## 1. Core Principle

**Rule:** The Index is a derived, lossy, non-authoritative representation of the IR.

**Corollary:** The Index can always be rebuilt from IR. IR cannot be rebuilt from Index.

---

## 2. Index Storage Rules

### 2.1 What the Index is ALLOWED to Store

| Data Type | Allowed? | Reason |
|-----------|----------|--------|
| Entity ContentHash | ✅ YES | Stable reference to IR entity |
| Entity addresses | ✅ YES | For fast lookup (derived from IR) |
| Entity names | ✅ YES | For name-based search (derived from IR) |
| XRef relationships | ✅ YES | Accelerates graph traversal |
| Search keys/hashes | ✅ YES | For indexed lookup |
| Cache version stamps | ✅ YES | For invalidation |

### 2.2 What the Index is PROHIBITED from Storing

| Data Type | Allowed? | Risk if Stored |
|-----------|----------|----------------|
| Entity properties (full) | ❌ NO | Becomes second source of truth |
| Instruction bytes | ❌ NO | Source of truth is BinaryFile |
| Disassembly text | ❌ NO | Derived, should recompute |
| Type information | ❌ NO | IR owns type system |
| Analysis artifacts | ❌ NO | Pipeline owns these |
| EntityId mappings | ❌ NO | Session-local, rebuild on load |

### 2.3 Storage Rule Summary

```cpp
// Index entry structure (minimal):
struct IndexEntry {
    // Reference to authoritative source
    ContentHash entity_identity;  // ✅ Allowed: stable reference
    
    // Search keys (derived)
    std::string name_key;         // ✅ Allowed: for search
    uint64_t address_key;         // ✅ Allowed: for lookup
    
    // Cache metadata
    uint32_t version;             // ✅ Allowed: invalidation
    
    // ❌ NOT ALLOWED in index:
    // - Entity properties (get from IR via identity)
    // - Derived data (compute on demand)
    // - Session-local IDs (use identity)
};
```

---

## 3. Index-IR Binding Contract

### 3.1 Lookup Semantics

**Rule 1:** Index lookups return `ContentHash`, not direct entity references.

```cpp
// Index returns stable identity:
ContentHash symbol_hash = index.find_symbol_by_name("main");

// Resolve to current session's entity:
SymbolId symbol_id = binary.resolve_identity(symbol_hash);
const Symbol* symbol = binary.get_symbol(symbol_id);

// ❌ WRONG: Index returns direct pointer/reference
// const Symbol* symbol = index.find_symbol_by_name("main"); // VIOLATION
```

**Rule 2:** IR is the single source of truth; index accelerates access only.

```cpp
// CORRECT: All data comes from IR
void display_symbol(const std::string& name) {
    ContentHash hash = index.find_symbol_by_name(name);
    SymbolId id = binary.resolve_identity(hash);
    const Symbol* sym = binary.get_symbol(id);
    
    // All properties from IR:
    std::cout << sym->name;           // From IR
    std::cout << sym->address.offset; // From IR
    std::cout << sym->type;           // From IR
}
```

### 3.2 Cache Consistency Rules

**Rule:** Index entries must be invalidated when referenced IR entities change.

```cpp
// On IR entity invalidation:
void on_entity_invalidated(ContentHash entity_hash) {
    // Invalidate all index entries referencing this entity
    index.invalidate_entries_for(entity_hash);
    
    // Mark for rebuild
    index.mark_dirty(entity_hash);
}
```

**Rule:** Index rebuild is non-blocking and idempotent.

```cpp
void GlobalIndex::rebuild(const Binary& binary) {
    // Clear derived data only (not the IR reference)
    clear_derived_entries();
    
    // Rebuild from authoritative source
    for (const auto& sym : binary.symbols()) {
        index_symbol(sym);
    }
}
```

### 3.3 Index Versioning

**Rule:** Index entries carry version stamps for cache validation.

```cpp
struct VersionedIndexEntry {
    ContentHash entity_identity;
    uint32_t entity_version;    // From IRNodeIdentity.version
    uint32_t index_version;     // Index generation number
    
    bool is_stale(const Binary& binary) const {
        const auto* entity = binary.find_by_identity(entity_identity);
        if (!entity) return true;  // Entity deleted
        
        // Check if entity version changed
        return entity->identity.version.stage_sequence != entity_version;
    }
};
```

---

## 4. Lossy Representation Guarantee

### 4.1 Information Loss Policy

**Rule:** Index may discard information that can be recomputed from IR.

**Permitted Loss:**
- String content (store hash only, look up in IR)
- Full type descriptors (store type ID, resolve in IR)
- Complex relationships (store endpoints, traverse via IR)

**Prohibited Loss:**
- Entity identity (must preserve ContentHash)
- Essential lookup keys (name, address)

### 4.2 Rebuild Guarantee

**Theorem:** Index is fully reconstructible from IR.

**Proof:**
1. IR contains all authoritative data (by definition)
2. Index stores only derived data + ContentHash references
3. ContentHash can be recomputed from IR content
4. Therefore, iterating IR and computing ContentHash rebuilds index

**Implementation:**
```cpp
void rebuild_index_from_ir() {
    GlobalIndex new_index;
    
    for (const auto& fn : binary.functions()) {
        // Compute identity from content
        ContentHash hash = FunctionGovernance::compute_identity(fn);
        
        // Rebuild index entry
        new_index.index_function(hash, fn.name, fn.start_address);
    }
    
    // Atomic swap
    std::swap(index_, new_index);
}
```

---

## 5. Index vs IR Authority Matrix

| Operation | Authoritative Source | Index Role |
|-----------|---------------------|------------|
| Entity properties | IR | Cache (may be stale) |
| Entity existence | IR | Reference (may be dangling) |
| Name → Entity | IR | Accelerator (fast path) |
| Address → Entity | IR | Accelerator (fast path) |
| XRef relationships | IR | Accelerator (precomputed) |
| Type information | IR | Not stored (lookup only) |
| Search results | IR | Filtered/ranked view |

---

## 6. Error Handling

### 6.1 Stale Index Entry

**Scenario:** Index returns ContentHash for entity that no longer exists.

**Handling:**
```cpp
QueryResult lookup(const std::string& name) {
    ContentHash hash = index.find_by_name(name);
    
    // Resolve to current entity
    EntityId id = binary.resolve_identity(hash);
    if (!is_valid(id)) {
        // Entity deleted - index stale
        index.mark_stale(name);
        return QueryResult::not_found();
    }
    
    return QueryResult{id};
}
```

### 6.2 Index Corruption

**Scenario:** Index data corrupted or inconsistent.

**Handling:**
```cpp
void validate_index() {
    for (const auto& entry : index.entries()) {
        if (!binary.has_entity(entry.entity_identity)) {
            // Corruption detected
            LOG(WARNING) << "Index corruption: dangling reference";
            
            // Non-fatal: rebuild from IR
            rebuild_index_from_ir();
            return;
        }
    }
}
```

---

## 7. Performance Contract

### 7.1 Index Lookup Complexity

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Name → Entity | O(1) | Hash map |
| Address → Entity | O(1) | Hash map |
| XRef lookup | O(1) | Precomputed index |
| Pattern search | O(N) | Linear scan with filter |
| Graph traversal | O(E) | Uses XRef index |

### 7.2 Rebuild Complexity

| Index Type | Rebuild Time | Memory |
|------------|--------------|--------|
| In-memory | O(N entities) | 2x index size during rebuild |
| Persistent | O(N log N) | Incremental updates |

---

## 8. Summary

**Core Principle:** Index accelerates; IR authorizes.

**Key Properties:**
1. ✅ **Derived:** All index data computable from IR
2. ✅ **Lossy:** May discard recomputable information
3. ✅ **Non-authoritative:** IR is source of truth
4. ✅ **Rebuildable:** Can reconstruct from IR at any time
5. ✅ **Versioned:** Detects staleness via version stamps

**Violation Detection:**
- Debug builds verify index entries resolve to valid IR entities
- Stale entries detected and marked for rebuild
- Corruption non-fatal (rebuild from IR)

**Risk Mitigated:**
- Index cannot become second source of truth
- Index corruption is recoverable
- Index staleness is detectable
