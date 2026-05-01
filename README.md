# Atlus

A fast, native binary diff and reverse engineering workbench for Windows PE files.

**Architecture:** C++17 modular design with a unified IR (Intermediate Representation) system, content-addressed identity, explicit invalidation semantics, and a Qt6-based GUI.

**Target:** Windows x64/x86 PE files (`.exe`, `.dll`, `.sys`).

---

## Quick Start

```powershell
# Setup submodules (one-time)
git submodule update --init --recursive

# Build
cd scripts
.\build.ps1

# Run
.\build\Release\Atlus.exe
```

---

## Repository Structure

```
Atlus/
├── scripts/              # Build and setup scripts
│   ├── setup.ps1         # Bootstrap dependencies
│   └── build.ps1         # CMake build script
├── include/core/         # Public API headers
│   ├── ir.h              # Unified IR entities
│   ├── ir_identity.h     # ContentHash, versioning
│   ├── ir_governance.h   # Entity governance rules
│   ├── address_space.h   # 5-space address translation
│   ├── analysis_pipeline.h # DAG-based analysis stages
│   ├── invalidation.h    # Explicit invalidation engine
│   ├── diff_engine.h     # Four-level diff system
│   ├── disassembler.h    # Zydis wrapper
│   ├── query.h           # SQL-like IR query layer
│   ├── cfg_builder.h     # Control-flow graph builder
│   ├── revng_decompiler.h # rev.ng decompiler integration
│   ├── xref_analyzer.h   # Cross-reference analysis
│   ├── string_analyzer.h # String table extraction
│   ├── switch_analyzer.h # Switch-jump table detection
│   ├── structure_analyzer.h # Struct/union layout recovery
│   ├── thread_pool.h     # Background worker pool
│   └── ...
├── src/core/             # Library implementation
├── src/ui/qt/            # Qt6 GUI layer (panels, models, dialogs)
├── third_party/          # Submodules (Zydis, ImGui, LIEF, RetDec)
└── vs/                   # Visual Studio solution files
```

---

## Core Features

### 1. PE Analysis Engine (`atlus_core`)

#### Binary Loading (`loader.h`)
- Zero-copy `BinaryFile` container with bounds-checked access
- UTF-8 path support via Win32 APIs
- Size validation before allocation

#### PE Parsing (`pe_parser.h`, `pe_import_export.h`)
- Full PE32/PE32+ header parsing
- Section table extraction (name, VA, size, raw offset, flags)
- Import directory reconstruction (DLL names, imported functions, ordinals)
- Export directory enumeration (names, RVAs, ordinals, forwarders)
- RVA-to-file-offset translation with section boundary validation

#### Disassembly (`disassembler.h`, `disassembly_cache.h`)
- Zydis-backed decoder supporting x86-32 and x86-64 modes
- Full instruction metadata: address, length, mnemonic, operands, raw bytes
- Control flow classification: `is_branch()`, `is_call()`, `is_ret()`
- Decode-or-skip interface for resilient parsing
- LRU disassembly cache to avoid redundant decoding

#### Function Analysis (`analyzer.h`)
- Prologue heuristic detection: `push rbp` / `mov rbp,rsp` / `sub rsp,N` patterns
- Complete function disassembly with instruction lists
- Function boundary estimation based on instruction flow

#### Control Flow Graph (`cfg_builder.h`)
- Iterative leader-identification algorithm for basic-block discovery
- Successor / predecessor edge linking
- Conditional, unconditional, and fall-through edge classification
- Per-function and per-section batch CFG generation

#### Cross-Reference Analysis (`xref_analyzer.h`)
- Builds call-in and call-out graphs
- Resolves target addresses for direct calls/jumps
- Updates IR `XRef` entities (derived, read-only)

#### String & Data Analysis (`string_analyzer.h`, `switch_analyzer.h`, `structure_analyzer.h`)
- ASCII / wide-string table extraction with reference tracking
- Switch-jump table detection (`jmp [reg*4+base]`)
- Structure layout recovery from stack-frame and field-access patterns

### 2. Four-Level Diff System (`diff_engine.h`)

| Level | Name | Description | API |
|-------|------|-------------|-----|
| 1 | Byte Diff | Raw byte-by-byte comparison, tracks offset/old/new values | `DiffEngine::byte_diff()` |
| 2 | Section Diff | Section-aware comparison, classifies sections as Unchanged/Modified/Added/Removed | `DiffEngine::section_diff()` |
| 3 | Function Diff | Instruction-level comparison of matched functions by name | `DiffEngine::function_diff()` |
| 4 | AOB Signatures | Pattern generation from diff chunks with wildcard insertion | `PatternScanner::generate_signatures()` |

**Key Structures:**
- `ByteDiff` — per-byte change tracking
- `DiffChunk` — coalesced runs of changed bytes
- `SectionDiff` — section-level status with nested byte diffs
- `FunctionDiff` — function matching with instruction-level change lists
- `DiffResult` — aggregates all levels for single-call analysis

### 3. Pattern Scanner (`pattern_scanner.h`)

- **Signature Generation:** Builds IDA-style (`48 8B ?? ?? 00`) and Cheat Engine-style (`48 8B * * 00`) patterns from diff chunks
- **Smart Wildcards:** Analyzes byte variance within chunks to determine which positions need wildcards
- **Pattern Parsing:** Converts IDA-style strings back to internal `Pattern` representation
- **Binary Scanning:** Fast single-pattern scan returning all match offsets
- **Context Display:** Configurable byte context around hits in UI

### 4. rev.ng Decompiler Integration (`revng_decompiler.h`)

- **Auto-detected backend:** Native Linux / WSL / Docker on Windows
- **Async lift pipeline:** Background `import-binary` → `detect-abi` → ready
- **Decompilation:** C pseudocode for any function address
- **Control Flow Graph:** `emit-cfg` producing structured YAML
- **Call Graph:** `render-svg-call-graph` producing SVG
- **ABI Detection:** Automatic calling-convention inference
- **Result caching** keyed by function address
- **Progress callbacks** for each analysis stage

---

## GUI Features

### Dockable Panel Layout (Qt6)

Panels are implemented as `QDockWidget`s with dark-theme styling and configurable font sizes. Layout persists via `QSettings`.

| Panel | Contents | Interactions |
|-------|----------|--------------|
| **Functions** | Detected functions with name/address/size filterable list | Click to select function; triggers disassembly, CFG, and decompilation |
| **Sections** | PE section table with VA/size/flags/diff status | Click to jump to section in hex view |
| **Imports** | Hierarchical import tree (DLL → functions) with search | Filter by DLL or function name |
| **Exports** | Exported symbols with RVAs and ordinals | Click to jump to export address |
| **Hex** | Hex dump with ASCII sidebar, diff highlighting | Context menu: copy offset/bytes, jump to section. Changed bytes highlighted in diff mode |
| **Disassembly** | Instruction-level view with mnemonic/operand/bytes | Syntax highlighting; side-by-side diff view in diff mode |
| **Pseudocode** | C decompilation output from rev.ng | Line-numbered display with status indicator |
| **XRefs** | Cross-reference tables (calls in / calls out) | Click to navigate to source or target |
| **AOB Scanner** | Pattern input, scan results, generated signatures from diff | Pattern scan with context bytes; toggle IDA/CE format |
| **CFG** | Control-flow graph rendered from rev.ng YAML or local builder | Zoom and pan support |
| **Call Graph** | Whole-binary call graph rendered from rev.ng SVG | Zoom and pan support |
| **Log** | Timestamped operation log with level coloring | Auto-scroll toggle |

### Menu System

**File Menu:**
- `Open File` (Ctrl+O) — Single file analysis mode
- `Open Diff` (Ctrl+D) — Two-file comparison mode (old/new)
- `Recent Files` — Persistent list of last opened files
- `Close` — Clear session state

**Edit Menu:**
- `Settings` (Ctrl+,) — Appearance and behavior preferences

**View Menu:**
- Toggle visibility for all dock panels
- `Reset Layout` — Restore default dock positions

**Analysis Menu:**
- `Analysis Options...` — Per-session analysis configuration (rev.ng, scan toggles)
- `Reanalyze` — Re-run the full analysis pipeline on the current file
- `Find Functions` (F) — Prologue scan on current file
- `Find Functions (both files)` (Shift+F) — Dual-file prologue scan
- `Run Byte Diff` (B) — Level 1 diff
- `Run Section Diff` (S) — Level 2 diff
- `Run Function Diff` (Shift+D) — Level 3 diff
- `Full Diff` (Ctrl+Shift+D) — All levels + AOB signature generation
- `Scan AOB Pattern` (A) — Opens AOB panel and triggers scan

**Decompiler Menu:**
- `Enable rev.ng` — Toggle rev.ng integration on/off
- `Request CFG` — Emit CFG for selected function
- `Request Call Graph` — Render whole-binary call graph

### Settings System (`dialogs/settings_dialog.cpp`)

Persistent `QSettings` storage for:

**Appearance:**
- Font size (live reload)
- Dark / light theme toggle
- Hex view ASCII sidebar toggle
- Hex columns (8/16/32 bytes per row)

**Analysis:**
- Auto-scan functions on file open
- Auto-run full diff on diff open
- Disassembler mode (x86-64 / x86-32)

**AOB:**
- Show Cheat Engine-style patterns alongside IDA format
- Context bytes (0–32) around signatures and scan hits

**Log:**
- Maximum ring buffer size (100–10000 lines)

**Decompiler:**
- Path to rev.ng executable (browse button)
- Enable/disable rev.ng backend
- Cache clear button

### Analysis Options Dialog

Per-session configuration before running analysis:
- Function prologue scanning
- XRef analysis
- Import/Export analysis
- Signature generation
- rev.ng lift + advanced features (CFG, call graph, ABI, data layout, cross-XRefs)

---

## IR Architecture

Atlus uses a unified Intermediate Representation (IR) as the single source of truth for all analysis state.

### Truth Hierarchy

| Layer | Role | Persistence |
|-------|------|-------------|
| **Raw Binary** | Immutable source of truth | File on disk |
| **IR** | Derived, cacheable, invalidatable | Session files |
| **Pipeline Cache** | Reproducible derivations | Recomputed on demand |
| **UI State** | Transient projection | `QSettings` |

### IR Entities (`ir.h`)

- **Binary** — Root container, owns all entities
- **Section** — PE sections with 5-space address translation
- **Function** — Content-addressed via prologue hash + entry point
- **BasicBlock** — Content-addressed instruction sequences
- **Instruction** — Immutable after creation
- **Symbol** — Imports, exports, discovered labels
- **XRef** — Cross-references (derived, never user-creatable)
- **TypeInfo** — Type inference results

### Identity System (`ir_identity.h`)

- **ContentHash** — 128-bit hash for deterministic identity
- **IdentityVersion** — Provenance tracking (stage sequence, timestamp)
- **DependencyMask** — 32-bit analysis stage dependencies
- **DirtyFlag** — Invalidation states (Clean/NeedsUpdate/NeedsRebuild/Invalid)

### Pipeline & Invalidation

- **Analysis Pipeline** — DAG of analysis stages with explicit dependencies
- **Invalidation Engine** — Formal rules: change type → affected stages → cascade
- **Query Layer** — SQL-like API over IR graph (`query.h`)
- **Index** — Fast lookup tables for addresses, names, hashes (`index.h`)
- **Type System** — Inferred primitive and aggregate types (`type_system.h`)

### Key Design Documents

See `docs/` for detailed specifications:
- `ATLUS_IR_SPEC_V1.md` — Complete IR specification
- `IR_IDENTITY_CONTRACT.md` — Identity stability rules
- `PIPELINE_INVALIDATION_MATRIX.md` — Invalidation semantics
- `CACHING_BOUNDARY_CONTRACT.md` — Cache vs recompute rules

---

## Build Instructions

### Prerequisites

- Visual Studio 2022+ with Desktop C++ workload
- Windows SDK
- CMake 3.16+
- Git
- Qt6 (Core, Widgets, Concurrent) — installed via `aqtinstall` or official installer

### Quick Build

```powershell
cd scripts
.\setup.ps1    # One-time: bootstrap Qt6, Zydis, etc.
.\build.ps1    # Build Release
```

### Manual Build

```powershell
# Setup submodules
git submodule update --init --recursive

# Configure
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --config Release --parallel 8
```

### Output

- `build/Release/Atlus.exe`

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| Ctrl+O | Open single file |
| Ctrl+D | Open diff (old/new) |
| Ctrl+, | Open Settings |
| F | Find functions (single file) |
| Shift+F | Find functions (both files in diff mode) |
| B | Run byte diff |
| S | Run section diff |
| Shift+D | Run function diff |
| Ctrl+Shift+D | Full diff (all levels + AOB) |
| A | Scan AOB pattern |
| Alt+F4 | Exit |

---

## File Format Support

| Format | Status | Notes |
|--------|--------|-------|
| PE32 | Full | x86 Windows executables |
| PE32+ | Full | x64 Windows executables |
| Raw binary | Partial | Hex view only, no PE analysis |
| ELF | Partial | Parser stubs present; analysis pipeline not wired |
| Mach-O | Partial | Parser stubs present; analysis pipeline not wired |

---

## Limitations & Design Notes

- **Windows-only:** Win32 APIs for file dialogs, process management, and windowing
- **In-memory files:** Entire binary loaded into RAM; no memory-mapping for large files
- **Function detection:** Relies on prologue heuristics; may miss non-standard entry points
- **Decompiler:** Requires rev.ng backend (WSL, Docker, or native Linux); no built-in disassembler-to-C
- **ELF / Mach-O:** Parser infrastructure exists but is not yet fully integrated into the analysis pipeline

---

## Version History

- **1.1.0** — Qt6 rewrite & rev.ng integration
  - Migrated GUI from Dear ImGui to Qt6 Widgets
  - Added rev.ng decompiler backend with async lift pipeline
  - Added CFG Panel and Call Graph Panel
  - Added XRefs Panel with navigation
  - Added Analysis Options dialog
  - Added disassembly cache, thread pool, and background workers
  - Added string analyzer, switch analyzer, structure analyzer
  - Added export directory parsing
  - Added index and type system layers

- **1.0.0** — Initial release
  - Four-level diff engine (byte, section, function, AOB)
  - Zydis disassembler with x86/x64 support
  - ImGui dockable interface with 8 panels
  - Ghidra decompiler integration
  - Function prologue detection with XRef building
  - Settings persistence and recent files
