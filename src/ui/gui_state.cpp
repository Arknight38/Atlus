#include "gui_state.h"
#include <cstdio>
#include <algorithm>
#include <filesystem>
#include <cstdio>

// Include full headers only where needed
#include "core/loader.h"
#include "core/pe_parser.h"
#include "core/diff_engine.h"
#include "core/pattern_scanner.h"
#include "core/analyzer.h"
#include "core/disassembler.h"

void ResetDisasmPanelCaches();

// ── Session state ─────────────────────────────────────────────────────────────
atlus::BinaryFile g_file_a;
atlus::BinaryFile g_file_b;
atlus::PEInfo     g_pe_a;
atlus::PEInfo     g_pe_b;
bool              g_file_loaded = false;
bool              g_diff_mode   = false;

// ── Analysis results ─────────────────────────────────────────────────────────────
atlus::DiffResult          g_diff_result;
std::vector<atlus::Function> g_functions;
std::vector<atlus::Function> g_functions_b;
atlus::Function*            g_selected_fn = nullptr;
std::vector<atlus::AobSignature> g_signatures;
std::vector<size_t>         g_aob_hits;
std::vector<atlus::Instruction> g_disassembly;
std::vector<atlus::Instruction> g_disassembly_b;
std::vector<atlus::FunctionDiff> g_function_diffs;

// ── Log ───────────────────────────────────────────────────────────────────────
std::deque<std::string> g_log_lines;
std::unordered_set<size_t> g_diff_offset_set;

HWND g_hwnd = nullptr;

void Log(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    // Enforce log line limit (O(1) with deque)
    if (g_log_lines.size() >= (size_t)g_settings.log_max_lines) {
        g_log_lines.pop_front();
    }
    g_log_lines.emplace_back(buf);
}

void SetMenuBarHwnd(HWND hwnd) {
    g_hwnd = hwnd;
}

void AddRecentFile(const std::string& path) {
    // Remove if already exists
    auto it = std::find(g_recent_files.begin(), g_recent_files.end(), path);
    if (it != g_recent_files.end()) {
        g_recent_files.erase(it);
    }
    
    // Add to front
    g_recent_files.insert(g_recent_files.begin(), path);
    
    // Keep only last 10 files
    while (g_recent_files.size() > 10) {
        g_recent_files.pop_back();
    }
}

// ── Panel visibility toggles ──────────────────────────────────────────────────
bool g_show_functions = true;
bool g_show_sections  = true;
bool g_show_hex       = true;
bool g_show_disasm    = true;
bool g_show_aob       = true;
bool g_show_imports   = true;
bool g_show_log       = true;
bool g_show_pseudocode = false;  // Off by default

// ── Dock layout ───────────────────────────────────────────────────────────────
bool g_dock_built  = false;
int  g_dock_frames = 0;

// ── Hex panel navigation ───────────────────────────────────────────────────────
size_t g_hex_jump_to = SIZE_MAX;  // Special value means no jump requested

// ── AOB scan trigger ───────────────────────────────────────────────────────────
bool g_aob_scan_trigger = false;

// ── Pseudocode decompilation ─────────────────────────────────────────────────
std::string g_pseudocode;

// ── Recent files ───────────────────────────────────────────────────────────────
std::vector<std::string> g_recent_files;

// ── Settings ───────────────────────────────────────────────────────────────────
AtlusSettings g_settings;
bool          g_show_settings = false;

// ── Settings persistence ───────────────────────────────────────────────────────
void SaveSettings() {
    FILE* f = fopen("atlus_settings.ini", "w");
    if (!f) return;
    
    fprintf(f, "[Appearance]\n");
    fprintf(f, "font_size=%.1f\n", g_settings.font_size);
    fprintf(f, "color_theme=%d\n", g_settings.color_theme);
    fprintf(f, "show_hex_ascii=%d\n", g_settings.show_hex_ascii ? 1 : 0);
    fprintf(f, "hex_cols=%d\n", g_settings.hex_cols);
    
    fprintf(f, "\n[Analysis]\n");
    fprintf(f, "auto_find_fns=%d\n", g_settings.auto_find_fns ? 1 : 0);
    fprintf(f, "auto_full_diff=%d\n", g_settings.auto_full_diff ? 1 : 0);
    fprintf(f, "disasm_mode=%d\n", g_settings.disasm_mode);
    
    fprintf(f, "\n[AOB]\n");
    fprintf(f, "aob_show_ce=%d\n", g_settings.aob_show_ce ? 1 : 0);
    fprintf(f, "aob_context_bytes=%d\n", g_settings.aob_context_bytes);
    
    fprintf(f, "\n[Decompiler]\n");
    fprintf(f, "ghidra_path=%s\n", g_settings.ghidra_path.c_str());
    
    fprintf(f, "\n[Recent]\n");
    for (size_t i = 0; i < g_recent_files.size() && i < 10; ++i) {
        fprintf(f, "file%zu=%s\n", i, g_recent_files[i].c_str());
    }
    
    fclose(f);
}

// ── Font size application ─────────────────────────────────────────────────────
// Forward declaration for ImGui DX11 backend functions
extern void ImGui_ImplDX11_InvalidateDeviceObjects();
extern bool ImGui_ImplDX11_CreateDeviceObjects();

void ApplyFontSize(float px) {
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();
    
    ImFontConfig config;
    config.SizePixels = px;
    io.Fonts->AddFontDefault(&config);
    
    // Rebuild font atlas
    ImGui_ImplDX11_InvalidateDeviceObjects();
    ImGui_ImplDX11_CreateDeviceObjects();
    
    Log("[info]  Font size applied: %.0f px", px);
}

void ResetSessionAfterLoad(bool is_diff_mode) {
    (void)is_diff_mode;
    g_selected_fn = nullptr;
    g_functions.clear();
    g_functions_b.clear();
    g_disassembly.clear();
    g_disassembly_b.clear();
    g_signatures.clear();
    g_aob_hits.clear();
    g_function_diffs.clear();
    g_diff_offset_set.clear();
    g_diff_result = {};
    g_hex_jump_to = SIZE_MAX;
    ResetDisasmPanelCaches();
}

void LoadSettings() {
    FILE* f = fopen("atlus_settings.ini", "r");
    if (!f) return;
    
    char line[256];
    char section[64] = "";
    
    while (fgets(line, sizeof(line), f)) {
        // Remove newline
        char* p = strchr(line, '\n');
        if (p) *p = '\0';
        
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == ';' || line[0] == '#') continue;
        
        // Section headers
        if (line[0] == '[') {
            char* end = strchr(line, ']');
            if (end) {
                *end = '\0';
                strncpy(section, line + 1, sizeof(section) - 1);
                section[sizeof(section) - 1] = '\0';
            }
            continue;
        }
        
        // Key=value pairs
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char* key = line;
        char* value = eq + 1;
        
        if (strcmp(section, "Appearance") == 0) {
            if (strcmp(key, "font_size") == 0) g_settings.font_size = (float)atof(value);
            else if (strcmp(key, "color_theme") == 0) g_settings.color_theme = atoi(value);
            else if (strcmp(key, "show_hex_ascii") == 0) g_settings.show_hex_ascii = atoi(value) != 0;
            else if (strcmp(key, "hex_cols") == 0) {
                int v = atoi(value);
                if (v >= 0 && v <= 2) g_settings.hex_cols = v;
                else if (v == 8) g_settings.hex_cols = 0;
                else if (v == 16) g_settings.hex_cols = 1;
                else if (v == 32) g_settings.hex_cols = 2;
                else g_settings.hex_cols = 1;
            }
        }
        else if (strcmp(section, "Analysis") == 0) {
            if (strcmp(key, "auto_find_fns") == 0) g_settings.auto_find_fns = atoi(value) != 0;
            else if (strcmp(key, "auto_full_diff") == 0) g_settings.auto_full_diff = atoi(value) != 0;
            else if (strcmp(key, "disasm_mode") == 0) g_settings.disasm_mode = atoi(value);
        }
        else if (strcmp(section, "AOB") == 0) {
            if (strcmp(key, "aob_show_ce") == 0) g_settings.aob_show_ce = atoi(value) != 0;
            else if (strcmp(key, "aob_context_bytes") == 0) g_settings.aob_context_bytes = atoi(value);
        }
        else if (strcmp(section, "Log") == 0) {
            if (strcmp(key, "log_max_lines") == 0) g_settings.log_max_lines = atoi(value);
        }
        else if (strcmp(section, "Decompiler") == 0) {
            if (strcmp(key, "ghidra_path") == 0) g_settings.ghidra_path = value;
        }
        else if (strcmp(section, "Recent") == 0) {
            if (strncmp(key, "file", 4) == 0) {
                g_recent_files.push_back(value);
            }
        }
    }
    
    fclose(f);
}
