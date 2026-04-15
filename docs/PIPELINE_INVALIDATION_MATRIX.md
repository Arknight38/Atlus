# Pipeline Invalidation Matrix

**Version:** 1.0  
**Status:** REQUIRED  
**Date:** 2024

---

## 1. Formal Invalidation Rules

### 1.1 Change Type → Invalidated Stages Matrix

| Change Type | Invalidates Stages | Cascade | Severity | Rebuild Scope |
|-------------|-------------------|---------|----------|---------------|
| **Raw binary change** | ALL stages (ParsePE → FindStrings) | Yes | Full | Global |
| **Section boundary change** | MapSections, ScanFunctions, Disassemble, BB, CFG, XRefs | Yes | Major | Affected sections |
| **Disassembly config change** | Disassemble, BB, CFG, XRefs, TypeInference | Yes | Major | All code |
| **Single instruction patched** | Disassemble (at addr), BB (containing), CFG (if branch), XRefs (if ref) | Yes | Minor | Affected function |
| **Function boundary redefined** | Disassemble (function), BB, CFG, XRefs (function only) | No | Minor | Single function |
| **Heuristic tuning change** | ScanFunctions | Yes | Moderate | Incremental rescan |
| **Type database updated** | TypeInference only | No | Minor | Iterative propagation |
| **Debug symbols loaded** | ScanFunctions, TypeInference | Yes | Moderate | Merge mode |
| **Symbol renamed** | Index only | No | Cosmetic | Index rebuild |
| **User annotation added** | None (metadata only) | No | None | N/A |
| **Binary rebased (ASLR)** | None (runtime space only) | No | None | N/A |

### 1.2 Invalidation Severity Levels

| Severity | Description | Action |
|----------|-------------|--------|
| **Full** | Entire IR invalidated | Full re-analysis required |
| **Major** | Structural analysis affected | Multi-stage re-run |
| **Moderate** | Detection heuristics affected | Incremental rescan |
| **Minor** | Single entity or derived data | Targeted update |
| **Cosmetic** | Display only | Index rebuild |
| **None** | No IR impact | Metadata update |

---

## 2. Cascade Rules

### 2.1 Dependency Cascade Graph

```
ParsePE
  └─> MapSections
        └─> ScanFunctions
              └─> Disassemble
                    ├─> BuildBasicBlocks
                    │     └─> BuildCFG
                    │           └─> AnalyzeXRefs
                    │                 └─> TypeInference
                    └─> FindStrings

Key: X ──> Y means "X invalidation cascades to Y"
```

### 2.2 Cascade Propagation Rules

**Rule 1: Full Cascade**
```
IF stage S invalidated with cascade=true
THEN invalidate all descendants of S in dependency graph
```

**Rule 2: Partial Cascade (Targeted)**
```
IF instruction at address A invalidated
THEN cascade only within containing function
     (do NOT invalidate other functions)
```

**Rule 3: Selective Preservation**
```
IF TypeInference invalidated
THEN preserve:
  - Disassembly results
  - Basic block structure
  - CFG edges
  (only type annotations cleared)
```

### 2.3 Cascade Algorithm

```cpp
void cascade_invalidation(AnalysisStageDependency root) {
    std::queue<AnalysisStageDependency> queue;
    std::set<AnalysisStageDependency> visited;
    
    queue.push(root);
    visited.insert(root);
    
    while (!queue.empty()) {
        auto stage = queue.front();
        queue.pop();
        
        // Find all nodes depending on this stage
        for (auto& node : all_ir_nodes) {
            if (node.identity.dependencies.has(stage) && 
                !visited.contains(node.stage)) {
                
                node.mark_dirty(NeedsUpdate);
                
                // Add downstream stages to queue
                for (auto downstream : get_dependent_stages(stage)) {
                    if (!visited.contains(downstream)) {
                        queue.push(downstream);
                        visited.insert(downstream);
                    }
                }
            }
        }
    }
}
```

---

## 3. Targeted Invalidation Rules

### 3.1 Address-Based Targeting

| Change Location | Affected Entities |
|-----------------|-------------------|
| Section `.text` at offset X | Functions with file_offset in [X, X+size) |
| RVA 0x1000 | Function containing RVA 0x1000 |
| Instruction at VA 0x140001000 | BB containing VA, Function containing BB |
| Data at address A | Symbols at A, XRefs to A |

### 3.2 Targeting Algorithm

```cpp
std::vector<FunctionId> find_affected_functions(
    const Binary& binary,
    AddressRange range
) {
    std::vector<FunctionId> affected;
    
    for (const auto& fn : binary.functions()) {
        if (ranges_intersect(fn.address_range, range)) {
            affected.push_back(fn.id);
        }
    }
    
    // Also include functions referencing this range
    for (const auto& fn : binary.functions()) {
        for (const auto& xref : fn.calls_out) {
            if (range.contains(xref.to_address)) {
                affected.push_back(fn.id);
                break;
            }
        }
    }
    
    return affected;
}
```

---

## 4. Invalidation State Machine

### 4.1 Node State Transitions

```
          +------------------+
          |                  v
[Clean] --patch--> [Dirty: NeedsUpdate] --re-analysis--> [Clean]
   ^                      |
   |                      | major structural change
   |                      v
   +--------------- [Dirty: NeedsRebuild] --rebuild--> [Clean]
                            |
                            | entity deleted
                            v
                      [Invalid] --compaction--> [Removed]
```

### 4.2 State Transition Rules

| From | Event | To | Action |
|------|-------|-----|--------|
| Clean | Minor change | NeedsUpdate | Recompute derived data |
| Clean | Major change | NeedsRebuild | Rebuild structure |
| NeedsUpdate | Re-analysis complete | Clean | Mark clean |
| NeedsRebuild | Rebuild complete | Clean | Mark clean |
| Any | Entity deleted | Invalid | Queue for removal |
| Invalid | Compaction pass | Removed | Free memory |

---

## 5. Execution Semantics

### 5.1 Invalidation Trigger Handling

```cpp
void handle_invalidation_trigger(InvalidationTrigger trigger) {
    auto rule = get_invalidation_rule(trigger);
    
    // Step 1: Mark directly affected stages
    for (auto stage : rule.affected_stages) {
        pipeline_.mark_stage_dirty(stage);
    }
    
    // Step 2: Cascade if required
    if (rule.cascade_to_dependents) {
        for (auto stage : rule.affected_stages) {
            cascade_invalidation(stage);
        }
    }
    
    // Step 3: Mark affected IR nodes
    if (rule.targeted_range) {
        // Targeted: only nodes in range
        auto affected = find_affected_functions(binary_, *rule.targeted_range);
        for (auto fn_id : affected) {
            binary_.get_function(fn_id)->mark_dirty(rule.severity);
        }
    } else {
        // Global: all nodes with matching dependencies
        for (auto& node : binary_.all_nodes()) {
            if (node.depends_on(rule.affected_stages)) {
                node.mark_dirty(rule.severity);
            }
        }
    }
    
    // Step 4: Update incremental state
    incremental_state_.can_incremental = !rule.requires_full_reanalysis;
    incremental_state_.dirty_stages |= rule.affected_stages;
}
```

### 5.2 Re-Analysis Scheduling

```cpp
void schedule_reanalysis() {
    if (!incremental_state_.can_incremental) {
        // Full re-analysis
        pipeline_.run_all(binary_);
        return;
    }
    
    // Step 1: Re-run dirty stages
    for (auto stage : incremental_state_.dirty_stages) {
        pipeline_.run_stage(binary_, stage);
    }
    
    // Step 2: Update targeted entities
    for (auto fn_id : incremental_state_.dirty_functions) {
        reanalyze_function(fn_id);
    }
    
    // Step 3: Clear dirty flags
    for (auto& node : binary_.all_nodes()) {
        if (node.is_dirty()) {
            node.mark_clean();
        }
    }
    
    incremental_state_.clear();
}
```

---

## 6. Correctness Guarantees

### 6.1 Deterministic Invalidation

**Rule:** Same change applied to same IR state produces identical invalidation pattern.

**Enforcement:**
- Invalidation rules are pure functions (no randomness)
- Cascade order is deterministic (BFS with sorted stages)
- Node iteration order is stable (sorted by EntityId)

### 6.2 Completeness

**Rule:** All affected nodes are marked dirty; no false negatives.

**Enforcement:**
- Cascade graph covers all stage dependencies
- Address targeting checks both containing and referencing functions
- Debug builds verify: `assert(all_affected_marked_dirty())`

### 6.3 Minimality

**Rule:** No over-invalidation; only affected nodes marked dirty.

**Enforcement:**
- Targeted invalidation preferred over global
- Cascade respects function boundaries
- Type-only changes don't invalidate structure

---

## 7. Summary

**Core Principle:** Invalidation is deterministic, complete, and minimal.

**Key Properties:**
1. ✅ **Deterministic:** Same change → same invalidation pattern
2. ✅ **Complete:** All affected nodes marked dirty
3. ✅ **Minimal:** No over-invalidation
4. ✅ **Cascading:** Dependencies automatically updated
5. ✅ **Targeted:** Address-based targeting when possible

**Formal Matrix:** Change types mapped to invalidated stages with severity and scope.

**Implementation:** State machine with Clean → NeedsUpdate/NeedsRebuild → Clean transitions.
