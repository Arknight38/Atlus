# Atlus

A fast, native binary diff and reverse engineering workbench for Windows PE files.

**Architecture:** Multi-layer C++20 design with a static analysis library (`atlus_core`) driving a Dear ImGui-based GUI. Built for speed, extensibility, and reverse engineering workflows.

**Target:** Windows x64/x86 PE files (`.exe`, `.dll`, `.sys`).

**Dependencies:**
- [LIEF](https://github.com/lief-project/LIEF) via vcpkg — PE/ELF/Mach-O parsing
- [Dear ImGui](https://github.com/ocornut/imgui) (docking branch) — Immediate-mode UI
- [Zydis](https://github.com/zyantific/zydis) — x86/x64 disassembler
- Ghidra `decompile.exe` — C pseudocode generation (bundled, optional)

---

## Repository Structure

```
Atlus/
├── README.md
├── .gitignore
├── .gitmodules
├── vs/                           # Visual Studio solution
│   ├── Atlus.sln
│   ├── vcpkg.json                # LIEF dependency
│   ├── Atlus.vcpkg.props
│   ├── Directory.Build.props
│   ├── atlus_core.vcxproj        # Static library (analysis engine)
│   ├── atlus_imgui.vcxproj       # ImGui + backends
│   └── atlus_gui.vcxproj         # Executable (links core + imgui)
├── include/core/                 # Public API headers
│   ├── analyzer.h                # Function detection and analysis
│   ├── diff_engine.h             # Four-level diff system
│   ├── disassembler.h            # Zydis wrapper
│   ├── formatter.h               # Console output formatting
│   ├── ghidra_decompiler.h       # Decompiler subprocess manager
│   ├── loader.h                  # Raw binary I/O
│   ├── pattern_scanner.h         # AOB signature generation/scanning
│   └── pe_parser.h               # PE structure parsing
├── src/core/                     # Library implementation
└── src/ui/                       # GUI layer (ImGui)
    ├── main.cpp                  # Entry point, window/message loop
    ├── menu_bar.cpp              # File dialogs, analysis menu, layout
    └── panels_*.cpp              # Panel implementations
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

## Technical Implementation Details

### State Management (`gui_state.h`)

Global state split into functional groups:
- **Session:** `g_file_a/b`, `g_pe_a/b`, `g_file_loaded`, `g_diff_mode`
- **Analysis Results:** `g_diff_result`, `g_functions`, `g_signatures`, `g_disassembly`
- **UI State:** Panel visibility flags, dock state, recent files list
- **Decompiler:** Globals for async operation tracking (`g_decompile_pending`, `g_decompile_future`)

### Hex View Virtualization

Uses `ImGuiListClipper` for O(1) memory regardless of file size. Calculates visible rows from scroll position. Right-click context menu provides offset-aware actions.

### Diff Highlighting

Byte-level diff status tracked in `std::unordered_set<size_t> g_diff_offset_set` for O(1) lookup during hex rendering. Red color applied only to changed bytes.

### Function Selection Flow

1. User clicks function in Functions panel
2. `g_selected_fn` pointer updated
3. Disassembly cache cleared (`g_last_disasm_fn` invalidation)
4. Pseudocode cleared
5. If decompiler running: new `std::async` task launched
6. Pseudocode panel polls future status, displays result when ready

### Recent Files

Stored as vector in memory, persisted to `atlus_recent.ini`. Duplicate detection on add. Selected files move to front.

---

## Build Instructions

### Prerequisites

- Visual Studio 2022/2025 with Desktop C++ workload
- Windows SDK
- Bundled vcpkg at `VC\vcpkg\vcpkg.exe`
- Git (for submodules)

### Initial Setup

```powershell
# 1. Clone with submodules (ImGui + Zydis)
git submodule update --init --recursive

# 2. Install LIEF via vcpkg (slow on first run)
cd vs
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\vcpkg\vcpkg.exe" install --triplet x64-windows
```

### Build

```powershell
# Open vs/Atlus.sln in Visual Studio
# - Select x64 + Debug or Release
# - Build solution (F7)
# - Output: vs/out/x64/Debug/atlus.exe

# Or command line:
msbuild vs\Atlus.sln /p:Configuration=Release /p:Platform=x64
```

**Note:** If the ImGui submodule fails, manually clone the docking branch:
```powershell
Remove-Item -Recurse -Force third_party/imgui
git clone --depth 1 --branch docking https://github.com/ocornut/imgui third_party/imgui
```

### Output

- `vs/out/x64/(Debug|Release)/atlus.exe`
- Required DLLs copied adjacent (LIEF, Zydis runtime)

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
