# Atlus

A fast, native binary diff and reverse engineering workbench for Windows PE files.

**Architecture:** C++20 modular design with a unified IR (Intermediate Representation) system, content-addressed identity, and explicit invalidation semantics. Dear ImGui-based GUI with dockable panels.

**Target:** Windows x64/x86 PE files (`.exe`, `.dll`, `.sys`).

---

## Quick Start

```powershell
# Setup (one-time)
git submodule update --init --recursive
cd scripts
.\setup.ps1

# Build
.\build.ps1 -j 8

# Run
.\build\Release\Atlus.exe
```

---

## Repository Structure

```
Atlus/
├── scripts/              # Build and setup scripts
│   ├── setup.ps1         # Bootstrap vcpkg dependencies
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
│   └── ...
├── src/core/             # Library implementation
├── src/ui/               # Dear ImGui GUI layer
├── third_party/          # Submodules (ImGui, LIEF, etc.)
└── docs/                 # Architecture specifications
```

---

## Core Features

### 1. PE Analysis Engine (`atlus_core`)

#### Binary Loading (`loader.h`)
- Zero-copy `BinaryFile` container with bounds-checked access
- UTF-8 path support via Win32 APIs
- Size validation before allocation

#### PE Parsing (`pe_parser.h`)
- Full PE32/PE32+ header parsing via LIEF
- Section table extraction (name, VA, size, raw offset, flags)
- Import directory reconstruction (DLL names, imported functions)
- RVA-to-file-offset translation with section boundary validation

#### Disassembly (`disassembler.h`)
- Zydis-backed decoder supporting x86-32 and x86-64 modes
- Full instruction metadata: address, length, mnemonic, operands, raw bytes
- Control flow classification: `is_branch()`, `is_call()`, `is_ret()`
- Decode-or-skip interface for resilient parsing

#### Function Analysis (`analyzer.h`)
- Prologue heuristic detection: `push rbp` / `mov rbp,rsp` / `sub rsp,N` patterns
- Complete function disassembly with instruction lists
- Cross-reference (XRef) building: calls in/out with address resolution
- Function boundary estimation based on instruction flow

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

### 4. Ghidra Decompiler Integration (`ghidra_decompiler.h`)

- Subprocess management for Ghidra's `decompile.exe` headless mode
- XML protocol communication via stdin/stdout
- C pseudocode extraction from `<c>` tags
- Result caching keyed by function address
- Background decompilation via `std::async` (non-blocking UI)
- Configurable path to decompiler executable

---

## GUI Features

### Dockable Panel Layout

Panels can be dragged, tabbed, split, and detached. Layout persists to `atlus_layout.ini`.

| Panel | Contents | Interactions |
|-------|----------|--------------|
| **Functions** | Detected functions with name/address/size filterable list | Click to select function, triggers disassembly + decompilation |
| **Sections** | PE section table with VA/size/flags/diff status | Click to jump to section in hex view |
| **Imports** | Hierarchical import tree (DLL → functions) with search | Filter by DLL or function name |
| **Hex / Diff** | Hex dump with ASCII sidebar, diff highlighting | Context menu: copy offset/byte, jump to section. Changed bytes shown in red (diff mode) |
| **Disassembly** | Instruction-level view with mnemonic/operand/bytes coloring | Side-by-side diff view in diff mode. Color-coded: calls (green), branches (blue), returns (red) |
| **Pseudocode** | C decompilation output from Ghidra | Line-numbered display, status indicator |
| **AOB Scanner** | Pattern input, scan results, generated signatures from diff | Pattern scan with context bytes. Toggle IDA/CE format display |
| **Log** | Timestamped operation log with level coloring | Auto-scroll toggle, horizontal scroll |

### Menu System

**File Menu:**
- `Open File` (Ctrl+O) — Single file analysis mode
- `Open Diff` (Ctrl+D) — Two-file comparison mode (old/new)
- `Recent Files` — Persistent list of last opened files
- `Close` — Clear session state

**Edit Menu:**
- `Settings` (Ctrl+,) — Modal with persistence

**View Menu:**
- Toggle visibility for all 8 panels
- `Reset Layout` — Delete ini, restore default dock positions

**Analysis Menu:**
- `Find Functions` (F) — Prologue scan on current file
- `Run Byte Diff` (B) — Level 1 diff
- `Run Section Diff` (S) — Level 2 diff
- `Find Functions (both files)` (Shift+F) — Dual-file prologue scan
- `Run Function Diff` (Shift+D) — Level 3 diff (requires both function lists)
- `Full Diff` (Ctrl+Shift+D) — Runs all levels + generates AOB signatures
- `Scan AOB Pattern` (A) — Opens AOB panel and triggers scan

### Settings System (`settings.cpp`)

Persistent INI storage for:

**Appearance:**
- Font size (10–20px, live reload)
- Color theme (Dark/Light/Classic)
- Hex view ASCII sidebar toggle
- Hex columns (8/16/32 bytes per row)

**Analysis:**
- Auto-scan functions on file open
- Auto-run full diff on diff open
- Disassembler mode (x86-64/x86-32)

**AOB:**
- Show Cheat Engine-style patterns alongside IDA format
- Context bytes (0–32) around signatures and scan hits

**Log:**
- Maximum ring buffer size (100–10000 lines)

**Decompiler:**
- Path to `decompile.exe` (browse button, file dialog)
- Start/Stop subprocess control
- Cache clear button

---

## IR Architecture

Atlus uses a unified Intermediate Representation (IR) as the single source of truth for all analysis state.

### Truth Hierarchy

| Layer | Role | Persistence |
|-------|------|-------------|
| **Raw Binary** | Immutable source of truth | File on disk |
| **IR** | Derived, cacheable, invalidatable | Session files |
| **Pipeline Cache** | Reproducible derivations | Recomputed on demand |
| **UI State** | Transient projection | Layout INI only |

### IR Entities (`ir.h`)

- **Binary** — Root container, owns all entities
- **Section** — PE/ELF sections with 5-space address translation
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
- CMake 3.20+
- Git

### Quick Build

```powershell
cd scripts
.\setup.ps1    # One-time: bootstrap vcpkg, install LIEF
.\build.ps1    # Build Release
```

### Manual Build

```powershell
# Setup submodules
git submodule update --init --recursive

# Configure
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release `-DCMAKE_TOOLCHAIN_FILE=third_party/vcpkg/scripts/buildsystems/vcpkg.cmake

# Build
cmake --build build --config Release --parallel 8
```

### Output

- `build/Release/Atlus.exe`
- DLLs auto-copied from vcpkg

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
| ELF | None | Not implemented |
| Mach-O | None | Not implemented |

---

## Limitations & Design Notes

- **Windows-only:** Win32 APIs for file dialogs, process management, and windowing
- **Single-threaded UI:** Background decompilation only; all other analysis is synchronous
- **In-memory files:** Entire binary loaded into RAM; no memory-mapping for large files
- **Function detection:** Relies on prologue heuristics; may miss non-standard entry points
- **Decompiler:** Requires bundled Ghidra `decompile.exe`; no fallback disassembler-to-C

---

## Version History

- **1.0.0** — Initial release
  - Four-level diff engine (byte, section, function, AOB)
  - Zydis disassembler with x86/x64 support
  - ImGui dockable interface with 8 panels
  - Ghidra decompiler integration
  - Function prologue detection with XRef building
  - Settings persistence and recent files
