# Atlus

A fast, native binary diff and reverse engineering tool for Windows PE files.

Built in C++20 with a clean multi-layer architecture — designed to grow into a full RE workbench. The shipping app is a **Windows GUI** (Dear ImGui + DirectX 11) with a dockable, draggable panel layout (Ghidra/IDA style). The diff engine lives in a static library (`atlus_core`) for reuse inside the UI.

**Dependencies:** [LIEF](https://github.com/lief-project/LIEF) via **[vcpkg](https://github.com/microsoft/vcpkg)** (`vs/vcpkg.json`). [Dear ImGui](https://github.com/ocornut/imgui) **docking branch** under `third_party/imgui`. **MSBuild** only (no CMake).

**Prerequisites (Windows):** Visual Studio 2022/2025 with **Desktop development with C++**, **x64**, and the bundled vcpkg (`VC\vcpkg\vcpkg.exe`). First LIEF install is slow and needs network.

---

## Repository layout

```
atlus/
├── README.md
├── .gitignore
├── vs/
│   ├── Atlus.sln               # Open this in Visual Studio
│   ├── vcpkg.json
│   ├── Atlus.vcpkg.props
│   ├── Directory.Build.props
│   ├── atlus_core.vcxproj
│   ├── atlus_imgui.vcxproj
│   └── atlus_gui.vcxproj       # → builds atlus.exe
├── include/core/               # Public headers
├── src/core/                   # Library implementation
└── src/ui/main.cpp             # GUI entry point
```

---

## GUI layout

The app uses ImGui's docking system. All panels are draggable and can be split, tabbed, or detached.

**Default layout on first launch:**

```
┌─────────────┬──────────────────────────┬────────────┐
│  Functions  │  Hex / Diff              │  AOB       │
│  Sections   │  Disassembly             │  Scanner   │
│  Imports    ├──────────────────────────┴────────────┤
│             │  Log                                  │
└─────────────┴───────────────────────────────────────┘
```

Layout is saved to `atlus_layout.ini` next to the exe. Use **View → Reset layout** to restore the default.

### Opening files

- **File → Open file** (or `Ctrl+O`): opens a single PE/binary for hex view, section browsing, and prologue scan.
- **File → Open diff**: opens two files in sequence (old then new) for byte diff, section diff, and AOB signature generation.

---

## Diff levels

| Level | Feature             | Status |
|-------|---------------------|--------|
| 1     | Byte diff           | Done   |
| 2     | Section-aware diff  | Done   |
| 3     | Function diff       | Done   |
| 4     | AOB pattern scanner | Done   |

*(Levels 1–4 are implemented in `atlus_core`. The GUI surfaces hex view, the section table, and the import tree. Diff colouring and AOB wiring are the next steps — see TODOs in `main.cpp`.)*

---

## Building

### 1. Submodules (first time)

From the repository root:

```powershell
git submodule update --init --recursive
```

This will clone:
- **ImGui (docking branch)** - required for the dockable UI
- **Zydis** - x86/x64 disassembler for function analysis
- **Zycore** - dependency library required by Zydis

### 2. ImGui (manual setup only if submodules fail)

The standard ImGui master branch does **not** include the docking API. If submodules don't work, manually clone the `docking` branch:

```powershell
Remove-Item -Recurse -Force third_party/imgui
git clone --depth 1 --branch docking https://github.com/ocornut/imgui third_party/imgui
```

### 3. vcpkg / LIEF (first time)

From **`vs/`**:

```powershell
cd vs
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\vcpkg\vcpkg.exe" install --triplet x64-windows
```

Adjust the path to `vcpkg.exe` for your VS install.

### 4. Build

Open **`vs/Atlus.sln`**, select **x64** and **Debug** or **Release**, build. Startup project: **atlus_gui** (output: **`atlus.exe`**).

Command line:

```powershell
msbuild vs\Atlus.sln /p:Configuration=Debug /p:Platform=x64
```

Outputs: **`vs/out/x64/Debug/atlus.exe`** (and DLLs copied next to it).

**Retargeting:** Projects use toolset **v145**. If yours differs, use **Retarget solution**.

### Linux / macOS

Not set up (Windows GUI only).

---

## Roadmap

### Done
- [x] Byte diff, section diff, AOB scanner (`atlus_core`)
- [x] LIEF-backed PE parsing (sections, imports, image base, entry point)
- [x] ImGui dockable layout (Functions / Sections / Imports / Hex / Disasm / AOB / Log)
- [x] Win32 `IFileOpenDialog` — single file and two-file diff mode
- [x] Hex view with virtual scrolling (`ImGuiListClipper`) — handles large files
- [x] GUI wiring — all core analysis features now connected to the UI
- [x] Zydis integration — live disassembly and function-level diffing

### Next up (GUI wiring) - COMPLETED ✅
- [x] Wire `DiffEngine::byte_diff` into hex panel — colour changed bytes red
- [x] Wire `DiffEngine::section_diff` into Sections panel — show diff status column
- [x] Wire `PatternScanner::generate_signatures` into AOB panel — populate signature list after diff
- [x] Wire `Analyzer::find_functions` into Functions panel — populate list, click to scroll Disasm

### Requires Zydis - COMPLETED ✅
- [x] Live disassembly in Disassembly panel
- [x] Function diff (Level 3) — side-by-side instruction view

### Polish
- [ ] Patch workflow (apply diff, export patched binary)
- [ ] About modal with version + license info
- [ ] Installer or portable zip