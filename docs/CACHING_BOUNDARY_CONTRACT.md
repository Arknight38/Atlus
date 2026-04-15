# Caching Layer Boundary Contract

**Version:** 1.0  
**Status:** REQUIRED  
**Date:** 2024

---

## 1. Core Principle

**Rule:** Cache stores only derived, recomputable data. Source of truth never cached.

**Corollary:** Cache loss or corruption is non-fatal; system degrades to recomputation.

---

## 2. Cacheability Matrix

### 2.1 Cacheable (Derived Data)

| Data | Cacheable? | Rationale | Invalidation Trigger |
|------|------------|-----------|---------------------|
| Disassembly text | ✅ YES | Derived from bytes | Binary patched, config change |
| Control flow graph | ✅ YES | Derived from disasm | Disassembly change |
| Cross-references | ✅ YES | Derived from xrefs pass | Xref analysis re-run |
| Type annotations | ✅ YES | Derived from inference | Type pass re-run |
| Function signatures | ✅ YES | Derived from analysis | Function re-analyzed |
| Decompiler output | ✅ YES | Derived from IR | Function change |
| Index structures | ✅ YES | Derived from IR | Entity invalidated |
| Query results | ✅ YES | Derived from IR+Index | Any upstream change |

### 2.2 Non-Cacheable (Source of Truth)

| Data | Cacheable? | Rationale | Storage |
|------|------------|-----------|---------|
| Raw binary bytes | ❌ NO | Immutable source | BinaryFile (memory map) |
| IR entities | ❌ NO | Authoritative state | ir::Binary |
| Analysis stage configs | ❌ NO | Affects all outputs | Settings file |
| User annotations | ❌ NO | User source of truth | Session file |
| Identity assignments | ❌ NO | Deterministic recomputed | Recomputed on load |

### 2.3 Cacheability Decision Tree

```
Can this data be recomputed from IR?
├─ NO → NOT CACHEABLE (source of truth)
└─ YES → Continue
     
     Is recomputation expensive (>100ms)?
     ├─ NO → NOT CACHEABLE (recompute on demand)
     └─ YES → Continue
          
          Is data deterministic (same input → same output)?
          ├─ NO → NOT CACHEABLE (unstable)
          └─ YES → CACHEABLE
```

---

## 3. Cache Storage Tiers

### 3.1 Tier 1: In-Memory (Session)

| Property | Value |
|----------|-------|
| Lifetime | Process lifetime |
| Capacity | Limited by RAM |
| Latency | ~ns |
| Invalidation | Automatic via identity version |
| Contents | Recent disassembly, active CFGs, query results |

**Implementation:**
```cpp
class MemoryCache {
    // Key: ContentHash (entity identity)
    // Value: Cached derived data + version
    std::unordered_map<ContentHash, CacheEntry> entries_;
    
    // LRU eviction
    std::list<ContentHash> lru_list_;
    size_t max_entries_ = 10000;
};
```

### 3.2 Tier 2: Persistent SQLite (Cross-Session)

| Property | Value |
|----------|-------|
| Lifetime | Persistent disk storage |
| Capacity | Limited by disk |
| Latency | ~ms (from disk) |
| Invalidation | Version stamp checking on load |
| Contents | Disassembly cache, decompiler results, large indexes |

**Schema:**
```sql
CREATE TABLE disassembly_cache (
    content_hash BLOB PRIMARY KEY,  -- 16 bytes
    version_sequence INTEGER,       -- For invalidation
    disassembly_text TEXT,          -- Cached derived data
    timestamp INTEGER               -- For LRU
);

CREATE INDEX idx_version ON disassembly_cache(version_sequence);
```

### 3.3 Tier 3: Session File (Project State)

| Property | Value |
|----------|-------|
| Lifetime | Per-analysis session |
| Capacity | Limited by file size |
| Latency | ~10ms (load/save) |
| Invalidation | Session-scoped |
| Contents | IR entities (minimal), user annotations, bookmarks |

**Note:** Session file stores IR entities, not cached derived data.

---

## 4. Cache Key Design

### 4.1 Cache Key Structure

```cpp
struct CacheKey {
    // Primary: What entity
    ContentHash entity_identity;
    
    // Secondary: What analysis configuration
    uint32_t analysis_config_hash;  // Disasm mode, heuristics, etc.
    
    // Tertiary: Cache entry type
    uint8_t entry_type;  // Disassembly=1, CFG=2, XRefs=3, etc.
    
    // Composite key for lookup
    uint64_t composite_hash() const {
        return hash_combine(entity_identity, analysis_config_hash, entry_type);
    }
};
```

### 4.2 Key Stability Rules

**Rule:** Cache key must change when input changes.

**Enforcement:**
- Entity identity changes → ContentHash changes → new key
- Analysis config changes → config_hash changes → new key
- Version mismatch → cache miss (even if key matches)

---

## 5. Cache Invalidation Strategy

### 5.1 Version-Based Invalidation

```cpp
struct CacheEntry {
    CacheKey key;
    
    // For validation:
    IdentityVersion source_version;  // When source was last modified
    uint32_t config_version;         // Analysis config version
    
    bool is_valid(const Binary& binary) const {
        // Find current entity
        auto entity = binary.find_by_identity(key.entity_identity);
        if (!entity) return false;  // Entity deleted
        
        // Check if entity modified since cache
        if (entity->identity.version != source_version) {
            return false;  // Stale
        }
        
        // Check config
        if (current_config_version() != config_version) {
            return false;  // Config changed
        }
        
        return true;
    }
};
```

### 5.2 Lazy vs Eager Invalidation

| Strategy | When Applied | Use Case |
|----------|--------------|----------|
| **Lazy** | On cache access | Memory cache (fast to rebuild) |
| **Eager** | On IR change | Persistent cache (expensive to rebuild) |
| **Periodic** | Background cleanup | Large persistent caches |

**Hybrid Approach:**
```cpp
// Memory cache: Lazy
CacheEntry* lookup(const CacheKey& key) {
    auto entry = memory_cache_.find(key);
    if (entry && !entry->is_valid(binary_)) {
        memory_cache_.erase(key);  // Lazy eviction
        return nullptr;
    }
    return entry;
}

// Persistent cache: Eager + Periodic
void on_entity_modified(ContentHash identity) {
    // Eager: Mark entries as potentially stale
    persistent_cache_.mark_stale(identity);
}

void periodic_cleanup() {
    // Remove entries stale for > 7 days
    persistent_cache_.evict_older_than(days(7));
}
```

---

## 6. Cache Consistency Levels

### 6.1 Consistency Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| **Strong** | Cache always consistent with IR | Small in-memory caches |
| **Eventual** | Cache may lag briefly | Large persistent caches |
| **Best-effort** | Stale entries acceptable | UI preview caches |

### 6.2 Level Selection

```cpp
enum class CacheConsistency {
    Strong,      // Synchronous invalidation
    Eventual,    // Async/periodic invalidation
    BestEffort   // Manual refresh only
};

template<CacheConsistency Level>
class TypedCache {
    // Strong: immediate invalidation
    // Eventual: background cleanup
    // BestEffort: user-triggered refresh
};
```

---

## 7. Cache Performance Budgets

### 7.1 Hit Rate Targets

| Cache Type | Target Hit Rate | Miss Penalty |
|------------|-----------------|--------------|
| Disassembly | > 90% | 10-50ms per function |
| CFG | > 85% | 5-20ms per function |
| Decompiler | > 80% | 100ms-5s per function |
| Queries | > 70% | Variable |

### 7.2 Size Limits

| Cache | Max Size | Eviction Policy |
|-------|----------|-----------------|
| Memory | 100MB | LRU |
| Persistent SQLite | 1GB | LRU + age |
| Session file | 10MB | None (complete state) |

---

## 8. Failure Handling

### 8.1 Cache Miss

**Behavior:** Recompute from IR.

**Optimization:** Async prefetch for likely-needed data.

```cpp
CacheEntry* get_or_compute(const CacheKey& key) {
    // Try cache
    if (auto entry = cache_.find(key)) {
        if (entry->is_valid()) {
            return entry;
        }
    }
    
    // Miss: recompute
    auto entry = compute_from_ir(key);
    cache_.insert(key, entry);
    
    // Prefetch likely neighbors
    prefetch_adjacent(key);
    
    return entry;
}
```

### 8.2 Cache Corruption

**Behavior:** Detect, discard, recompute.

**Detection:**
```cpp
bool validate_cache_integrity() {
    for (auto& entry : cache_.entries()) {
        auto entity = binary_.find_by_identity(entry.key.entity_identity);
        if (!entity) {
            LOG(WARNING) << "Dangling cache entry";
            cache_.erase(entry.key);
            continue;
        }
        
        // Recompute and compare (expensive, periodic only)
        if (entry.last_validated + hours(24) < now()) {
            auto recomputed = compute_from_ir(entry.key);
            if (entry.data_hash != hash(recomputed)) {
                LOG(ERROR) << "Cache corruption detected";
                cache_.erase(entry.key);
            }
        }
    }
}
```

### 8.3 Disk Full

**Behavior:** Graceful degradation to in-memory only.

```cpp
void on_disk_full() {
    LOG(WARNING) << "Cache disk full, switching to memory-only";
    persistent_cache_.disable_writes();
    
    // Keep working with reduced performance
    // User notified via UI
}
```

---

## 9. Security Considerations

### 9.1 Cache Poisoning Prevention

**Risk:** Malicious binary crafted to pollute cache.

**Mitigation:**
```cpp
// Limit cache size per binary
size_t max_cache_per_binary = 100MB;

// Validate cache entries on load
if (!entry.is_valid(binary_)) {
    discard(entry);
}

// Don't cache suspicious patterns
if (is_suspicious_function(fn)) {
    skip_caching(fn);
}
```

### 9.2 Sensitive Data

**Rule:** Don't cache:
- User's file paths
- Debug symbols from proprietary software
- Analysis of malware (isolate in session-only cache)

---

## 10. Summary

**Core Principle:** Cache accelerates; IR authorizes.

**Key Properties:**
1. ✅ **Derived Only:** Never cache source of truth
2. ✅ **Deterministic Keys:** ContentHash + config + type
3. ✅ **Version Validation:** Detect staleness via identity version
4. ✅ **Graceful Degradation:** Miss = recompute, corruption = discard
5. ✅ **Tiered Storage:** Memory (fast) → SQLite (persistent) → Session (state)

**Decision Matrix:**
- Cacheable: Derived + deterministic + expensive to recompute
- Non-cacheable: Source of truth, user data, unstable outputs

**Risk Mitigated:**
- Cache never becomes source of truth
- Corruption is recoverable (rebuild from IR)
- Performance degrades gracefully (slower, not broken)
