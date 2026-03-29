// Atlus GUI — Dear ImGui + Win32 + DirectX 11
// Layout: DockSpace fills the full window (Ghidra/IDA style).
// All panels are dockable — drag their title bars to reposition/split/tab them.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <shobjidl.h>   // IFileOpenDialog
#include <shlwapi.h>    // PathFindExtensionW (available if needed)
#include <string>
#include <vector>
#include <cstdio>   // std::remove for layout reset

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")   // CoInitializeEx / CoCreateInstance
#pragma comment(lib, "uuid.lib")    // CLSID_FileOpenDialog

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include "imgui_internal.h"         // DockBuilder API

#include "core/loader.h"
#include "core/pe_parser.h"
#include "core/diff_engine.h"
#include "core/pattern_scanner.h"
#include "core/analyzer.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ── D3D11 globals ─────────────────────────────────────────────────────────────
static ID3D11Device*           g_pd3dDevice           = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext     = nullptr;
static IDXGISwapChain*         g_pSwapChain            = nullptr;
static bool                    g_SwapChainOccluded     = false;
static UINT                    g_ResizeWidth           = 0;
static UINT                    g_ResizeHeight          = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView  = nullptr;

static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void CreateRenderTarget();
static void CleanupRenderTarget();
static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ── Session state ─────────────────────────────────────────────────────────────
static atlus::BinaryFile g_file_a;      // single file, or "old" in diff mode
static atlus::BinaryFile g_file_b;      // "new" file in diff mode
static atlus::PEInfo     g_pe_a;
static atlus::PEInfo     g_pe_b;
static bool              g_file_loaded = false;
static bool              g_diff_mode   = false;

// ── Analysis results ─────────────────────────────────────────────────────────────
static atlus::DiffResult          g_diff_result;          // Full diff result
static std::vector<atlus::Function> g_functions;           // Detected functions
static std::vector<atlus::Function> g_functions_b;         // Functions from file B
static atlus::Function*            g_selected_fn = nullptr; // Current function
static std::vector<atlus::AobSignature> g_signatures;      // AOB signatures from diff
static std::vector<size_t>         g_aob_hits;             // AOB scan results
static std::vector<atlus::Instruction> g_disassembly;      // Current disassembly view
static std::vector<atlus::Instruction> g_disassembly_b;    // Disassembly from file B
static std::vector<atlus::FunctionDiff> g_function_diffs;  // Function-level diffs

// ── Log ───────────────────────────────────────────────────────────────────────
static std::vector<std::string> g_log_lines;

static void Log(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    g_log_lines.emplace_back(buf);
}

// ── Panel visibility toggles ──────────────────────────────────────────────────
static bool g_show_functions = true;
static bool g_show_sections  = true;
static bool g_show_hex       = true;
static bool g_show_disasm    = true;
static bool g_show_aob       = true;
static bool g_show_imports   = true;
static bool g_show_log       = true;
static bool g_dock_built  = false;
static int  g_dock_frames = 0;

// ─────────────────────────────────────────────────────────────────────────────
// Win32 file dialog
// Uses IFileOpenDialog (Vista+). Returns UTF-8 path, or "" on cancel/error.
// ─────────────────────────────────────────────────────────────────────────────
static HWND g_hwnd = nullptr;

static std::string OpenFileDialog(HWND owner, const wchar_t* title) {
    std::string result;

    IFileOpenDialog* pfd = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr,
                                  CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pfd));
    if (FAILED(hr)) {
        Log("[error] CoCreateInstance(IFileOpenDialog) failed: 0x%08X", hr);
        return result;
    }

    COMDLG_FILTERSPEC filters[] = {
        { L"PE files (*.exe, *.dll, *.sys, *.bin)", L"*.exe;*.dll;*.sys;*.bin" },
        { L"All files (*.*)",                        L"*.*"                    },
    };
    pfd->SetFileTypes(ARRAYSIZE(filters), filters);
    pfd->SetFileTypeIndex(1);
    pfd->SetTitle(title);

    hr = pfd->Show(owner);
    if (SUCCEEDED(hr)) {
        IShellItem* psi = nullptr;
        if (SUCCEEDED(pfd->GetResult(&psi))) {
            PWSTR wide_path = nullptr;
            if (SUCCEEDED(psi->GetDisplayName(SIGDN_FILESYSPATH, &wide_path)) && wide_path) {
                int len = WideCharToMultiByte(CP_UTF8, 0, wide_path, -1,
                                              nullptr, 0, nullptr, nullptr);
                if (len > 0) {
                    result.resize(len - 1);
                    WideCharToMultiByte(CP_UTF8, 0, wide_path, -1,
                                        result.data(), len, nullptr, nullptr);
                }
                CoTaskMemFree(wide_path);
            }
            psi->Release();
        }
    }
    // HRESULT_FROM_WIN32(ERROR_CANCELLED) is normal — user pressed Cancel

    pfd->Release();
    return result;
}

// Load a BinaryFile and parse its PEInfo. Logs success/failure.
static bool LoadFile(const std::string& path,
                     atlus::BinaryFile& out_file,
                     atlus::PEInfo&     out_pe) {
    if (path.empty()) return false;

    out_file = atlus::Loader::load(path);
    if (out_file.empty()) {
        Log("[error] Could not read: %s", path.c_str());
        return false;
    }
    Log("[info]  Loaded %s  (%zu bytes)", path.c_str(), out_file.size());

    out_pe = atlus::PEParser::parse(out_file);
    if (out_pe.valid) {
        Log("[info]  PE OK — %zu sections, image base 0x%llX, %s",
            out_pe.sections.size(),
            (unsigned long long)out_pe.image_base,
            out_pe.is_64bit ? "x64" : "x86");
    } else {
        Log("[warn]  Not a valid PE — hex view only.");
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Default dock layout (runs once; atlus_layout.ini takes over after that)
// ─────────────────────────────────────────────────────────────────────────────
static void BuildDefaultLayout(ImGuiID dockspace_id) {
    if (g_dock_frames < 2) { g_dock_frames++; return; }
    if (g_dock_built) return;
    g_dock_built = true;

    ImGui::DockBuilderRemoveNode(dockspace_id);
    ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspace_id, ImGui::GetMainViewport()->Size);

    // ┌─────────────┬──────────────────────────┬────────────┐
    // │  Left       │  Center (Hex / Disasm)   │  Right     │
    // │  Functions  │                          │  AOB       │
    // │  Sections   ├──────────────────────────┤            │
    // │  Imports    │  Bottom (Log)            │            │
    // └─────────────┴──────────────────────────┴────────────┘

    ImGuiID left, center, bottom, right;
    ImGui::DockBuilderSplitNode(dockspace_id, ImGuiDir_Left,  0.20f, &left,   &center);
    ImGui::DockBuilderSplitNode(center,       ImGuiDir_Down,  0.22f, &bottom, &center);
    ImGui::DockBuilderSplitNode(center,       ImGuiDir_Right, 0.28f, &right,  &center);

    ImGui::DockBuilderDockWindow("Functions",   left);
    ImGui::DockBuilderDockWindow("Sections",    left);
    ImGui::DockBuilderDockWindow("Imports",     left);
    ImGui::DockBuilderDockWindow("Hex / Diff",  center);
    ImGui::DockBuilderDockWindow("Disassembly", center);
    ImGui::DockBuilderDockWindow("AOB Scanner", right);
    ImGui::DockBuilderDockWindow("Log",         bottom);

    ImGui::DockBuilderFinish(dockspace_id);
}

// ─────────────────────────────────────────────────────────────────────────────
// Panel implementations
// ─────────────────────────────────────────────────────────────────────────────

static void DrawMenuBar() {
    if (!ImGui::BeginMainMenuBar()) return;

    // ── File ──────────────────────────────────────────────────────────────────
    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open file", "Ctrl+O")) {
            std::string path = OpenFileDialog(g_hwnd, L"Open PE / binary file");
            if (!path.empty()) {
                g_diff_mode = false;
                g_file_b = {}; g_pe_b = {};
                if (LoadFile(path, g_file_a, g_pe_a))
                    g_file_loaded = true;
            }
        }
        if (ImGui::MenuItem("Open diff (old / new)", "Ctrl+D")) {
            std::string path_a = OpenFileDialog(g_hwnd, L"Select OLD / baseline file");
            if (!path_a.empty()) {
                std::string path_b = OpenFileDialog(g_hwnd, L"Select NEW / patched file");
                if (!path_b.empty()) {
                    bool ok_a = LoadFile(path_a, g_file_a, g_pe_a);
                    bool ok_b = LoadFile(path_b, g_file_b, g_pe_b);
                    g_file_loaded = ok_a;
                    g_diff_mode   = ok_a && ok_b;
                    if (g_diff_mode)
                        Log("[info]  Diff mode ready.");
                }
            }
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Close", nullptr, false, g_file_loaded)) {
            g_file_a = {}; g_file_b = {};
            g_pe_a   = {}; g_pe_b   = {};
            g_file_loaded = false;
            g_diff_mode   = false;
            
            // Clear analysis results
            g_diff_result = {};
            g_functions.clear();
            g_functions_b.clear();
            g_selected_fn = nullptr;
            g_signatures.clear();
            g_aob_hits.clear();
            g_disassembly.clear();
            g_disassembly_b.clear();
            g_function_diffs.clear();
            
            Log("[info]  Session closed.");
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4"))
            ::PostQuitMessage(0);
        ImGui::EndMenu();
    }

    // ── View ──────────────────────────────────────────────────────────────────
    if (ImGui::BeginMenu("View")) {
        ImGui::MenuItem("Functions",   nullptr, &g_show_functions);
        ImGui::MenuItem("Sections",    nullptr, &g_show_sections);
        ImGui::MenuItem("Hex / Diff",  nullptr, &g_show_hex);
        ImGui::MenuItem("Disassembly", nullptr, &g_show_disasm);
        ImGui::MenuItem("AOB Scanner", nullptr, &g_show_aob);
        ImGui::MenuItem("Imports",     nullptr, &g_show_imports);
        ImGui::MenuItem("Log",         nullptr, &g_show_log);
        ImGui::Separator();
        if (ImGui::MenuItem("Reset layout")) {
            std::remove("atlus_layout.ini");
            ImGui::GetIO().IniFilename = "atlus_layout.ini"; // re-enable saving
            g_dock_built  = false;   // re-arm builder
            g_dock_frames = 0;
        }
        ImGui::EndMenu();
    }

    // ── Analysis ──────────────────────────────────────────────────────────────
    if (ImGui::BeginMenu("Analysis")) {
        if (ImGui::MenuItem("Run byte diff", nullptr, false, g_diff_mode)) {
            g_diff_result.byte_diffs = atlus::DiffEngine::byte_diff(g_file_a, g_file_b);
            g_diff_result.chunks = atlus::DiffEngine::make_chunks(g_diff_result.byte_diffs);
            Log("[info]  Byte diff: %zu changed bytes in %zu chunks", 
                g_diff_result.byte_diffs.size(), g_diff_result.chunks.size());
        }
        if (ImGui::MenuItem("Run section diff", nullptr, false, g_diff_mode)) {
            g_diff_result.section_diffs = atlus::DiffEngine::section_diff(g_pe_a, g_pe_b);
            Log("[info]  Section diff: %zu sections compared", 
                g_diff_result.section_diffs.size());
        }
        if (ImGui::MenuItem("Find functions (both files)", nullptr, false, g_diff_mode)) {
            const auto* text_a = g_pe_a.find_section(".text");
            const auto* text_b = g_pe_b.find_section(".text");
            
            if (text_a && text_b) {
                atlus::Analyzer analyzer(atlus::Disassembler::Mode::X86_64);
                g_functions = analyzer.find_functions(*text_a, g_pe_a.image_base);
                g_functions_b = analyzer.find_functions(*text_b, g_pe_b.image_base);
                
                Log("[info]  Found %zu functions in old file, %zu in new file.", 
                    g_functions.size(), g_functions_b.size());
            } else {
                Log("[error] No .text section found in one or both files.");
            }
        }
        if (ImGui::MenuItem("Scan AOB pattern", nullptr, false, g_file_loaded)) {
            // TODO: trigger PatternScanner::scan with the pattern in the AOB panel input.
            //       Easiest: set a bool g_aob_scan_requested = true here and consume it
            //       inside DrawAobPanel() on the next frame.
            Log("[info]  AOB scan requested (not yet wired).");
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Run function diff", nullptr, false, g_diff_mode && !g_functions.empty() && !g_functions_b.empty())) {
            g_function_diffs = atlus::DiffEngine::function_diff(g_functions, g_functions_b);
            Log("[info]  Function diff: %zu functions compared", g_function_diffs.size());
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Full diff (all levels)", nullptr, false, g_diff_mode)) {
            g_diff_result = atlus::DiffEngine::full_diff(g_file_a, g_file_b, true, false);
            g_signatures = atlus::PatternScanner::generate_signatures(g_diff_result.chunks);
            Log("[info]  Full diff: %zu bytes, %zu sections, %zu signatures", 
                g_diff_result.byte_diffs.size(), 
                g_diff_result.section_diffs.size(),
                g_signatures.size());
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Find functions (single file)", nullptr, false, g_file_loaded && !g_diff_mode)) {
            const auto* text = g_pe_a.find_section(".text");
            if (text) {
                atlus::Analyzer analyzer(atlus::Disassembler::Mode::X86_64);
                g_functions = analyzer.find_functions(*text, g_pe_a.image_base);
                Log("[info]  Found %zu functions.", g_functions.size());
            } else {
                Log("[error] No .text section found.");
            }
        }
        ImGui::EndMenu();
    }

    // ── Help ──────────────────────────────────────────────────────────────────
    if (ImGui::BeginMenu("Help")) {
        if (ImGui::MenuItem("About Atlus")) {
            // TODO: ImGui::OpenPopup("##about") — modal with version + license text.
        }
        ImGui::EndMenu();
    }

    // Right-aligned status breadcrumb
    std::string status;
    if (!g_file_loaded)     status = "No file loaded";
    else if (g_diff_mode)   status = "[diff]  " + g_file_a.path + "  vs  " + g_file_b.path;
    else                    status = g_file_a.path;

    float sw = ImGui::CalcTextSize(status.c_str()).x + 16.0f;
    ImGui::SetCursorPosX(ImGui::GetContentRegionMax().x - sw);
    ImGui::TextDisabled("%s", status.c_str());

    ImGui::EndMainMenuBar();
}

// ── Left: functions ───────────────────────────────────────────────────────────
static void DrawFunctionsPanel() {
    if (!g_show_functions) return;
    if (!ImGui::Begin("Functions", &g_show_functions)) { ImGui::End(); return; }

    ImGui::TextDisabled("Functions (prologue scan)");
    ImGui::Separator();

    if (!g_file_loaded) { ImGui::TextDisabled("(open a file first)"); ImGui::End(); return; }

    if (g_functions.empty()) {
        ImGui::TextDisabled("[ run Analysis > Find functions ]");
        ImGui::End();
        return;
    }

    constexpr ImGuiTableFlags tf = 
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;

    if (ImGui::BeginTable("func_tbl", 3, tf)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableHeadersRow();

        for (auto& fn : g_functions) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            
            bool sel = (g_selected_fn == &fn);
            if (ImGui::Selectable(fn.name.c_str(), sel, ImGuiSelectableFlags_SpanAllColumns)) {
                g_selected_fn = &fn;
                g_disassembly.clear(); // Clear previous disassembly
            }
            
            ImGui::TableSetColumnIndex(1); 
            ImGui::Text("0x%08llX", (unsigned long long)fn.start_address);
            ImGui::TableSetColumnIndex(2); 
            ImGui::Text("%zu", fn.size_bytes);
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

// ── Left: sections ────────────────────────────────────────────────────────────
static void DrawSectionsPanel() {
    if (!g_show_sections) return;
    if (!ImGui::Begin("Sections", &g_show_sections)) { ImGui::End(); return; }

    ImGui::TextDisabled("PE sections");
    ImGui::Separator();

    if (!g_file_loaded) { ImGui::TextDisabled("(open a file first)"); ImGui::End(); return; }
    if (!g_pe_a.valid)  { ImGui::TextDisabled("(not a valid PE)");    ImGui::End(); return; }

    constexpr ImGuiTableFlags tf =
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;

    const int ncols = g_diff_mode ? 5 : 4;
    if (ImGui::BeginTable("sec_tbl", ncols, tf)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name",  ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("VAddr", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("VSize", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        if (g_diff_mode)
            ImGui::TableSetupColumn("Diff", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& sec : g_pe_a.sections) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(sec.name.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::Text("0x%08X", sec.vaddr);
            ImGui::TableSetColumnIndex(2); ImGui::Text("0x%X",   sec.vsize);
            ImGui::TableSetColumnIndex(3); ImGui::Text("0x%X",   sec.flags);
            if (g_diff_mode) {
                ImGui::TableSetColumnIndex(4);
                // Look up section name in diff results
                auto it = std::find_if(g_diff_result.section_diffs.begin(), 
                                      g_diff_result.section_diffs.end(),
                                      [&sec](const atlus::SectionDiff& diff) {
                                          return diff.name == sec.name;
                                      });
                
                if (it != g_diff_result.section_diffs.end()) {
                    switch (it->status) {
                        case atlus::SectionDiff::Status::Modified:
                            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255,200,0,255));
                            ImGui::Text("Modified");
                            ImGui::PopStyleColor();
                            break;
                        case atlus::SectionDiff::Status::Added:
                            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(80,220,80,255));
                            ImGui::Text("Added");
                            ImGui::PopStyleColor();
                            break;
                        case atlus::SectionDiff::Status::Removed:
                            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(220,80,80,255));
                            ImGui::Text("Removed");
                            ImGui::PopStyleColor();
                            break;
                        case atlus::SectionDiff::Status::Unchanged:
                        default:
                            ImGui::TextDisabled("Unchanged");
                            break;
                    }
                } else {
                    ImGui::TextDisabled("—");
                }
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

// ── Left: imports ─────────────────────────────────────────────────────────────
static void DrawImportsPanel() {
    if (!g_show_imports) return;
    if (!ImGui::Begin("Imports", &g_show_imports)) { ImGui::End(); return; }

    ImGui::TextDisabled("Import table");
    ImGui::Separator();

    if (!g_file_loaded) { ImGui::TextDisabled("(open a file first)"); ImGui::End(); return; }
    if (!g_pe_a.valid || g_pe_a.imports.empty()) {
        ImGui::TextDisabled("(no imports or not a valid PE)");
        ImGui::End();
        return;
    }

    for (const auto& ie : g_pe_a.imports) {
        if (ImGui::TreeNode(ie.dll.c_str())) {
            for (const auto& fn : ie.functions)
                ImGui::TextUnformatted(fn.c_str());
            ImGui::TreePop();
        }
    }
    ImGui::End();
}

// ── Center: hex viewer ────────────────────────────────────────────────────────
static void DrawHexPanel() {
    if (!g_show_hex) return;
    if (!ImGui::Begin("Hex / Diff", &g_show_hex)) { ImGui::End(); return; }

    if (!g_file_loaded) { ImGui::TextDisabled("(open a file first)"); ImGui::End(); return; }

    ImGui::TextDisabled("%s  |  %zu bytes", g_file_a.path.c_str(), g_file_a.size());
    ImGui::Separator();

    const auto& data = g_file_a.data;
    const int   cols = 16;
    const int   rows = (int)((data.size() + cols - 1) / cols);

    ImGui::BeginChild("hex_scroll", ImVec2(0, 0), false,
                      ImGuiWindowFlags_HorizontalScrollbar);

    ImGuiListClipper clipper;
    clipper.Begin(rows);
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const size_t base = (size_t)row * cols;

            ImGui::Text("%08zX  ", base);

            for (int col = 0; col < cols; ++col) {
                ImGui::SameLine();
                const size_t idx = base + col;
                if (idx < data.size()) {
                    // Check if this byte is in the diff results
                    bool is_changed = false;
                    if (g_diff_mode && !g_diff_result.byte_diffs.empty()) {
                        auto diff_it = std::find_if(g_diff_result.byte_diffs.begin(),
                                                  g_diff_result.byte_diffs.end(),
                                                  [idx](const atlus::ByteDiff& diff) {
                                                      return diff.offset == idx;
                                                  });
                        is_changed = (diff_it != g_diff_result.byte_diffs.end());
                    }
                    
                    if (is_changed) {
                        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255,80,80,255));
                        ImGui::Text("%02X", data[idx]);
                        ImGui::PopStyleColor();
                    } else {
                        ImGui::Text("%02X", data[idx]);
                    }
                } else {
                    ImGui::TextDisabled("  ");
                }
                if (col == 7) ImGui::SameLine(0, 8);
            }

            // ASCII sidebar
            ImGui::SameLine(0, 16);
            char ascii[17];
            for (int col = 0; col < cols; ++col) {
                const size_t idx = base + col;
                ascii[col] = (idx < data.size() && data[idx] >= 0x20 && data[idx] < 0x7F)
                             ? (char)data[idx] : '.';
            }
            ascii[cols] = '\0';
            ImGui::TextUnformatted(ascii);
        }
    }
    clipper.End();

    ImGui::EndChild();
    ImGui::End();
}

// ── Center: disassembly ───────────────────────────────────────────────────────
static void DrawDisasmPanel() {
    if (!g_show_disasm) return;
    if (!ImGui::Begin("Disassembly", &g_show_disasm)) { ImGui::End(); return; }

    if (!g_file_loaded) { ImGui::TextDisabled("(open a file first)"); ImGui::End(); return; }

    if (g_diff_mode && g_selected_fn) {
        // Side-by-side diff view
        ImGui::TextDisabled("Function diff (side-by-side)");
        ImGui::Separator();
        
        if (g_selected_fn) {
            ImGui::Text("Function: %s", g_selected_fn->name.c_str());
            ImGui::Text("Address: 0x%08llX - 0x%08llX", 
                       (unsigned long long)g_selected_fn->start_address,
                       (unsigned long long)g_selected_fn->end_address);
            ImGui::Separator();
            
            // Disassemble both versions if not already done
            if (g_disassembly.empty()) {
                uint32_t rva = (uint32_t)(g_selected_fn->start_address - g_pe_a.image_base);
                auto offset_opt = atlus::PEParser::rva_to_offset(g_pe_a, rva);
                if (offset_opt) {
                    size_t offset = *offset_opt;
                    
                    if (offset < g_file_a.size()) {
                        atlus::Disassembler disasm(atlus::Disassembler::Mode::X86_64);
                        size_t func_size = (size_t)g_selected_fn->size_bytes;
                        size_t available = g_file_a.size() - offset;
                        size_t to_disasm = std::min(func_size, available);
                        
                        g_disassembly = disasm.disassemble(
                            g_file_a.data.data() + offset,
                            to_disasm,
                            g_selected_fn->start_address
                        );
                    }
                }
            }
            
            if (g_disassembly_b.empty() && g_selected_fn && !g_functions_b.empty()) {
                // Find corresponding function in file B
                auto it = std::find_if(g_functions_b.begin(), g_functions_b.end(),
                    [&](const atlus::Function& fn) {
                        return fn.name == g_selected_fn->name;
                    });
                
                if (it != g_functions_b.end()) {
                    uint32_t rva = (uint32_t)(it->start_address - g_pe_b.image_base);
                    auto offset_opt = atlus::PEParser::rva_to_offset(g_pe_b, rva);
                    if (offset_opt) {
                        size_t offset = *offset_opt;
                        
                        if (offset < g_file_b.size()) {
                            atlus::Disassembler disasm(atlus::Disassembler::Mode::X86_64);
                            size_t func_size = (size_t)it->size_bytes;
                            size_t available = g_file_b.size() - offset;
                            size_t to_disasm = std::min(func_size, available);
                            
                            g_disassembly_b = disasm.disassemble(
                                g_file_b.data.data() + offset,
                                to_disasm,
                                it->start_address
                            );
                        }
                    }
                }
            }
            
            // Side-by-side display
            if (!g_disassembly.empty() || !g_disassembly_b.empty()) {
                constexpr ImGuiTableFlags tf = 
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;
                
                if (ImGui::BeginTable("diff_tbl", 8, tf)) {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("OLD Address", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                    ImGui::TableSetupColumn("OLD Bytes", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("OLD Mnemonic", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                    ImGui::TableSetupColumn("OLD Operands", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                    ImGui::TableSetupColumn("NEW Address", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                    ImGui::TableSetupColumn("NEW Bytes", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("NEW Mnemonic", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                    ImGui::TableSetupColumn("NEW Operands", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();
                    
                    size_t max_rows = std::max(g_disassembly.size(), g_disassembly_b.size());
                    
                    for (size_t i = 0; i < max_rows; ++i) {
                        ImGui::TableNextRow();
                        
                        // Old version (left side)
                        if (i < g_disassembly.size()) {
                            const auto& insn = g_disassembly[i];
                            
                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("0x%08llX", (unsigned long long)insn.address);
                            
                            ImGui::TableSetColumnIndex(1);
                            std::string bytes_str;
                            for (uint8_t b : insn.bytes) {
                                char buf[4];
                                snprintf(buf, sizeof(buf), "%02X ", b);
                                bytes_str += buf;
                            }
                            if (!bytes_str.empty()) bytes_str.pop_back();
                            ImGui::TextUnformatted(bytes_str.c_str());
                            
                            ImGui::TableSetColumnIndex(2);
                            if (insn.is_call()) {
                                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(80,200,80,255));
                            } else if (insn.is_branch()) {
                                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(80,120,200,255));
                            } else if (insn.is_ret()) {
                                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200,80,80,255));
                            }
                            ImGui::TextUnformatted(insn.mnemonic.c_str());
                            if (insn.is_call() || insn.is_branch() || insn.is_ret()) {
                                ImGui::PopStyleColor();
                            }
                            
                            ImGui::TableSetColumnIndex(3);
                            ImGui::TextUnformatted(insn.operands.c_str());
                        } else {
                            for (int col = 0; col < 4; ++col) {
                                ImGui::TableSetColumnIndex(col);
                                ImGui::TextDisabled("-");
                            }
                        }
                        
                        // New version (right side)
                        if (i < g_disassembly_b.size()) {
                            const auto& insn = g_disassembly_b[i];
                            
                            ImGui::TableSetColumnIndex(4);
                            ImGui::Text("0x%08llX", (unsigned long long)insn.address);
                            
                            ImGui::TableSetColumnIndex(5);
                            std::string bytes_str;
                            for (uint8_t b : insn.bytes) {
                                char buf[4];
                                snprintf(buf, sizeof(buf), "%02X ", b);
                                bytes_str += buf;
                            }
                            if (!bytes_str.empty()) bytes_str.pop_back();
                            ImGui::TextUnformatted(bytes_str.c_str());
                            
                            ImGui::TableSetColumnIndex(6);
                            if (insn.is_call()) {
                                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(80,200,80,255));
                            } else if (insn.is_branch()) {
                                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(80,120,200,255));
                            } else if (insn.is_ret()) {
                                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200,80,80,255));
                            }
                            ImGui::TextUnformatted(insn.mnemonic.c_str());
                            if (insn.is_call() || insn.is_branch() || insn.is_ret()) {
                                ImGui::PopStyleColor();
                            }
                            
                            ImGui::TableSetColumnIndex(7);
                            ImGui::TextUnformatted(insn.operands.c_str());
                        } else {
                            for (int col = 4; col < 8; ++col) {
                                ImGui::TableSetColumnIndex(col);
                                ImGui::TextDisabled("-");
                            }
                        }
                    }
                    
                    ImGui::EndTable();
                }
            }
        }
    } else {
        // Single file disassembly view
        ImGui::TextDisabled("Live disassembly");
        ImGui::Separator();
        
        if (g_selected_fn) {
            ImGui::Text("Function: %s", g_selected_fn->name.c_str());
            ImGui::Text("Address: 0x%08llX - 0x%08llX", 
                       (unsigned long long)g_selected_fn->start_address,
                       (unsigned long long)g_selected_fn->end_address);
            ImGui::Separator();
            
            // Disassemble the function if not already done
            if (g_disassembly.empty()) {
                uint32_t rva = (uint32_t)(g_selected_fn->start_address - g_pe_a.image_base);
                auto offset_opt = atlus::PEParser::rva_to_offset(g_pe_a, rva);
                if (!offset_opt) return;
                size_t offset = *offset_opt;
                
                if (offset < g_file_a.size()) {
                    atlus::Disassembler disasm(atlus::Disassembler::Mode::X86_64);
                    size_t func_size = (size_t)g_selected_fn->size_bytes;
                    size_t available = g_file_a.size() - offset;
                    size_t to_disasm = std::min(func_size, available);
                    
                    g_disassembly = disasm.disassemble(
                        g_file_a.data.data() + offset,
                        to_disasm,
                        g_selected_fn->start_address
                    );
                    
                    Log("[info]  Disassembled %zu instructions from %s", 
                        g_disassembly.size(), g_selected_fn->name.c_str());
                }
            }
            
            // Show disassembly
            if (!g_disassembly.empty()) {
                constexpr ImGuiTableFlags tf = 
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;
                
                if (ImGui::BeginTable("disasm_tbl", 4, tf)) {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                    ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                    ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();
                    
                    ImGuiListClipper clipper;
                    clipper.Begin((int)g_disassembly.size());
                    while (clipper.Step()) {
                        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                            const auto& insn = g_disassembly[row];
                            
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("0x%08llX", (unsigned long long)insn.address);
                            
                            ImGui::TableSetColumnIndex(1);
                            std::string bytes_str;
                            for (uint8_t b : insn.bytes) {
                                char buf[4];
                                snprintf(buf, sizeof(buf), "%02X ", b);
                                bytes_str += buf;
                            }
                            if (!bytes_str.empty()) bytes_str.pop_back();
                            ImGui::TextUnformatted(bytes_str.c_str());
                            
                            ImGui::TableSetColumnIndex(2);
                            if (insn.is_call()) {
                                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(80,200,80,255));
                            } else if (insn.is_branch()) {
                                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(80,120,200,255));
                            } else if (insn.is_ret()) {
                                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200,80,80,255));
                            }
                            ImGui::TextUnformatted(insn.mnemonic.c_str());
                            if (insn.is_call() || insn.is_branch() || insn.is_ret()) {
                                ImGui::PopStyleColor();
                            }
                            
                            ImGui::TableSetColumnIndex(3);
                            ImGui::TextUnformatted(insn.operands.c_str());
                        }
                    }
                    clipper.End();
                    
                    ImGui::EndTable();
                }
            }
        } else {
            ImGui::TextDisabled("[ select a function from the Functions panel ]");
        }
    }
    
    ImGui::End();
}

// ── Right: AOB scanner ────────────────────────────────────────────────────────
static void DrawAobPanel() {
    if (!g_show_aob) return;
    if (!ImGui::Begin("AOB Scanner", &g_show_aob)) { ImGui::End(); return; }

    ImGui::TextDisabled("Array-of-bytes scanner");
    ImGui::Separator();

    static char pattern_buf[256] = "";

    float btn_w = ImGui::CalcTextSize("Scan").x + ImGui::GetStyle().FramePadding.x * 2 + 8.0f;
    ImGui::SetNextItemWidth(-btn_w - ImGui::GetStyle().ItemSpacing.x);
    ImGui::InputText("##pattern", pattern_buf, sizeof(pattern_buf),
                     ImGuiInputTextFlags_CharsUppercase);
    ImGui::SameLine();

    bool can_scan = g_file_loaded && pattern_buf[0] != '\0';
    if (!can_scan) ImGui::BeginDisabled();
    if (ImGui::Button("Scan")) {
        auto pat = atlus::PatternScanner::parse_ida(pattern_buf);
        if (pat) {
            g_aob_hits = atlus::PatternScanner::scan(g_file_a.data, *pat);
            Log("[info]  AOB: %zu hit(s) for pattern %s",
                g_aob_hits.size(), pattern_buf);
        } else {
            Log("[error] Invalid IDA pattern: %s", pattern_buf);
        }
    }
    if (!can_scan) ImGui::EndDisabled();

    // Show scan results
    if (!g_aob_hits.empty()) {
        ImGui::Separator();
        ImGui::TextDisabled("Scan results:");
        for (size_t hit : g_aob_hits) {
            ImGui::Text("0x%08zX", hit);
        }
    }

    ImGui::Separator();
    ImGui::TextDisabled("Signatures from last diff:");
    ImGui::Spacing();

    if (g_signatures.empty()) {
        ImGui::TextDisabled("[ run a diff first ]");
    } else {
        constexpr ImGuiTableFlags tf = 
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;

        if (ImGui::BeginTable("sig_tbl", 2, tf)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Pattern", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (auto& sig : g_signatures) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); 
                ImGui::Text("0x%08zX", sig.offset);
                ImGui::TableSetColumnIndex(1);
                
                if (ImGui::Selectable(sig.ida_style.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    ImGui::SetClipboardText(sig.ida_style.c_str());
                    Log("[info]  Copied pattern to clipboard");
                }
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Click to copy");
                }
            }
            ImGui::EndTable();
        }
    }
    ImGui::End();
}

// ── Bottom: log ───────────────────────────────────────────────────────────────
static void DrawLogPanel() {
    if (!g_show_log) return;
    if (!ImGui::Begin("Log", &g_show_log, ImGuiWindowFlags_HorizontalScrollbar)) {
        ImGui::End(); return;
    }

    static bool auto_scroll = true;
    ImGui::Checkbox("Auto-scroll", &auto_scroll);
    ImGui::SameLine();
    if (ImGui::Button("Clear")) g_log_lines.clear();
    ImGui::Separator();

    ImGui::BeginChild("log_scroll", ImVec2(0, 0), false,
                      ImGuiWindowFlags_HorizontalScrollbar);
    for (const auto& line : g_log_lines)
        ImGui::TextUnformatted(line.c_str());
    if (auto_scroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();

    ImGui::End();
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
int main(int, char**) {
    // COM is required for IFileOpenDialog
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    WNDCLASSEXW wc = {sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
                      GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
                      L"AtlusGuiClass", nullptr};
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Atlus",
                                WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800,
                                nullptr, nullptr, wc.hInstance, nullptr);
    g_hwnd = hwnd;

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        CoUninitialize();
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    (void)io;

    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.IniFilename  = "atlus_layout.ini";

    ImGui::StyleColorsDark();

    ImGuiStyle& style       = ImGui::GetStyle();
    style.WindowRounding    = 2.0f;
    style.FrameRounding     = 2.0f;
    style.ScrollbarRounding = 2.0f;
    style.TabRounding       = 2.0f;
    style.FramePadding      = ImVec2(6, 3);
    style.ItemSpacing       = ImVec2(6, 4);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    Log("[info]  Atlus started.  File > Open  or  Ctrl+O  to load a binary.");

    bool done = false;
    while (!done) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        // Ctrl+O shortcut (processed before ImGui::NewFrame so it's reliable)
        if (::GetAsyncKeyState(VK_CONTROL) & 0x8000) {
            if (::GetAsyncKeyState('O') & 0x0001) {
                std::string path = OpenFileDialog(g_hwnd, L"Open PE / binary file");
                if (!path.empty()) {
                    g_diff_mode = false;
                    g_file_b = {}; g_pe_b = {};
                    if (LoadFile(path, g_file_a, g_pe_a))
                        g_file_loaded = true;
                }
            }
        }

        if (g_SwapChainOccluded &&
            g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED) {
            ::Sleep(10);
            continue;
        }
        g_SwapChainOccluded = false;

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight,
                                         DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // ── Full-screen DockSpace ──────────────────────────────────────────────
        {
            const ImGuiViewport* vp = ImGui::GetMainViewport();
            ImGui::SetNextWindowPos(vp->WorkPos);
            ImGui::SetNextWindowSize(vp->WorkSize);
            ImGui::SetNextWindowViewport(vp->ID);

            constexpr ImGuiWindowFlags host_flags =
                ImGuiWindowFlags_NoTitleBar            |
                ImGuiWindowFlags_NoCollapse            |
                ImGuiWindowFlags_NoResize              |
                ImGuiWindowFlags_NoMove                |
                ImGuiWindowFlags_NoBringToFrontOnFocus |
                ImGuiWindowFlags_NoNavFocus            |
                ImGuiWindowFlags_MenuBar;

            ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,   0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,    ImVec2(0, 0));
            ImGui::Begin("##DockspaceHost", nullptr, host_flags);
            ImGui::PopStyleVar(3);

            if (ImGui::BeginMenuBar()) ImGui::EndMenuBar();

            ImGuiID dockspace_id = ImGui::GetID("AtlusDockSpace");
            ImGui::DockSpace(dockspace_id, ImVec2(0, 0), ImGuiDockNodeFlags_None);
            BuildDefaultLayout(dockspace_id);

            ImGui::End();
        }

        DrawMenuBar();
        DrawFunctionsPanel();
        DrawSectionsPanel();
        DrawImportsPanel();
        DrawHexPanel();
        DrawDisasmPanel();
        DrawAobPanel();
        DrawLogPanel();

        ImGui::Render();
        const float cc[4] = {0.10f, 0.10f, 0.12f, 1.0f};
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, cc);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        const HRESULT hr = g_pSwapChain->Present(1, 0);
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    CoUninitialize();
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// D3D11 boilerplate
// ─────────────────────────────────────────────────────────────────────────────

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount                        = 2;
    sd.BufferDesc.Width                   = 0;
    sd.BufferDesc.Height                  = 0;
    sd.BufferDesc.Format                  = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator   = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags                              = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage                        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow                       = hWnd;
    sd.SampleDesc.Count                   = 1;
    sd.SampleDesc.Quality                 = 0;
    sd.Windowed                           = TRUE;
    sd.SwapEffect                         = DXGI_SWAP_EFFECT_DISCARD;

    constexpr UINT flags = 0;
    D3D_FEATURE_LEVEL level{};
    const D3D_FEATURE_LEVEL levels[2] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};

    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
        levels, 2, D3D11_SDK_VERSION,
        &sd, &g_pSwapChain, &g_pd3dDevice, &level, &g_pd3dDeviceContext);

    if (res == DXGI_ERROR_UNSUPPORTED)
        res = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, flags,
            levels, 2, D3D11_SDK_VERSION,
            &sd, &g_pSwapChain, &g_pd3dDevice, &level, &g_pd3dDeviceContext);

    if (res != S_OK) return false;
    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain)        { g_pSwapChain->Release();       g_pSwapChain        = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)        { g_pd3dDevice->Release();        g_pd3dDevice        = nullptr; }
}

static void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

static void CleanupRenderTarget() {
    if (g_mainRenderTargetView) {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }
}

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) return 0;
        g_ResizeWidth  = static_cast<UINT>(LOWORD(lParam));
        g_ResizeHeight = static_cast<UINT>(HIWORD(lParam));
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}