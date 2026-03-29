#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_set>
#include <deque>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstdarg>
#include <optional>
#include "imgui.h"
#include "core/loader.h"
#include "core/pe_parser.h"
#include "core/disassembler.h"
#include "core/analyzer.h"
#include "core/pattern_scanner.h"
#include "core/diff_engine.h"
#include "core/ghidra_decompiler.h"

// ── Session state ─────────────────────────────────────────────────────────────
extern atlus::BinaryFile g_file_a;      // single file, or "old" in diff mode
extern atlus::BinaryFile g_file_b;      // "new" file in diff mode
extern atlus::PEInfo     g_pe_a;
extern atlus::PEInfo     g_pe_b;
extern bool              g_file_loaded;
extern bool              g_diff_mode;

// ── Analysis results ─────────────────────────────────────────────────────────────
extern atlus::DiffResult          g_diff_result;          // Full diff result
extern std::vector<atlus::Function> g_functions;           // Detected functions
extern std::vector<atlus::Function> g_functions_b;         // Functions from file B
extern atlus::Function*            g_selected_fn;         // Current function
extern std::vector<atlus::AobSignature> g_signatures;      // AOB signatures from diff
extern std::vector<size_t>         g_aob_hits;             // AOB scan results
extern std::vector<atlus::Instruction> g_disassembly;      // Current disassembly view
extern std::vector<atlus::Instruction> g_disassembly_b;    // Disassembly from file B
extern std::vector<atlus::FunctionDiff> g_function_diffs;  // Function-level diffs

// ── Log ───────────────────────────────────────────────────────────────────────
extern std::deque<std::string> g_log_lines;
extern std::unordered_set<size_t> g_diff_offset_set;  // Fast diff lookup for hex panel

void Log(const char* fmt, ...);
extern HWND g_hwnd;
void SetMenuBarHwnd(HWND hwnd);
void AddRecentFile(const std::string& path);
bool LoadFile(const std::string& path, atlus::BinaryFile& file, atlus::PEInfo& pe);
void BuildDefaultLayout(ImGuiID dockspace_id);

// ── Panel visibility toggles ──────────────────────────────────────────────────
extern bool g_show_functions;
extern bool g_show_sections;
extern bool g_show_hex;
extern bool g_show_disasm;
extern bool g_show_aob;
extern bool g_show_imports;
extern bool g_show_log;

// ── Dock layout ───────────────────────────────────────────────────────────────
extern bool g_dock_built;
extern int  g_dock_frames;

// ── AOB scan trigger (set by menu/shortcut, consumed by panel) ─────────────
extern bool g_aob_scan_trigger;

// ── Pseudocode decompilation ─────────────────────────────────────────────────
extern std::string g_pseudocode;
extern bool        g_show_pseudocode;

// Convenience: bring decompiler globals into global namespace for UI files
using atlus::g_decompiler;
using atlus::g_decompile_future;
using atlus::g_decompile_pending;

// ── Hex panel navigation ───────────────────────────────────────────────────────
extern size_t g_hex_jump_to;  // Offset to jump to when set to SIZE_MAX

// ── Recent files ───────────────────────────────────────────────────────────────
extern std::vector<std::string> g_recent_files;

// ── Settings ───────────────────────────────────────────────────────────────────
struct AtlusSettings {
    // Appearance
    float   font_size        = 13.0f;
    int     color_theme      = 0;       // 0=Dark, 1=Light, 2=Classic
    bool    show_hex_ascii   = true;    // ASCII sidebar in hex panel
    int     hex_cols         = 1;       // Combo index: 0=8, 1=16, 2=32 bytes per row

    // Analysis
    bool    auto_find_fns    = false;   // run prologue scan on file open
    bool    auto_full_diff   = false;   // run full diff automatically on diff open
    int     disasm_mode      = 0;       // 0=x64, 1=x86

    // AOB
    bool    aob_show_ce      = false;   // show CE-style patterns alongside IDA
    int     aob_context_bytes = 8;      // context bytes around each signature

    // Log
    int     log_max_lines    = 2000;    // ring-buffer cap
    
    // Decompiler
    std::string ghidra_path  = "third_party/ghidra/decompile.exe";  // Path to decompiler
};

extern AtlusSettings g_settings;
extern bool          g_show_settings;

// ── Forward declarations ───────────────────────────────────────────────────────
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
void DrawMenuBar();
void DrawFunctionsPanel();
void DrawSectionsPanel();
void DrawImportsPanel();
void DrawHexPanel();
void DrawDisasmPanel();
void DrawAobPanel();
void DrawLogPanel();
void DrawSettingsModal();

// ── Settings persistence ───────────────────────────────────────────────────────
void SaveSettings();
void LoadSettings();

/// Apply font size change (rebuilds font atlas)
void ApplyFontSize(float px);

/// Clear analysis UI state after loading a new file (invalidates pointers into g_functions).
void ResetSessionAfterLoad(bool is_diff_mode);
