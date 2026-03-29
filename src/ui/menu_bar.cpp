#include "gui_state.h"
#include "imgui.h"
#include "imgui_internal.h"         // DockBuilder API
#include <windows.h>
#include <shobjidl.h>
#include <algorithm>
#include <filesystem>
#include "core/loader.h"
#include "core/pe_parser.h"
#include "core/diff_engine.h"
#include "core/pattern_scanner.h"
#include "core/analyzer.h"
#include "core/disassembler.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

// Helper to get disassembler mode from settings
static atlus::Disassembler::Mode GetDisasmMode() {
    return (g_settings.disasm_mode == 0) 
        ? atlus::Disassembler::Mode::X86_64 
        : atlus::Disassembler::Mode::X86_32;
}

// ─────────────────────────────────────────────────────────────────────────────
// Win32 file dialog
// Uses IFileOpenDialog (Vista+). Returns UTF-8 path, or "" on cancel/error.
// ─────────────────────────────────────────────────────────────────────────────
std::string OpenFileDialog(HWND owner, const wchar_t* title) {
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
bool LoadFile(const std::string& path,
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
void BuildDefaultLayout(ImGuiID dockspace_id) {
    if (g_dock_frames < 2) { g_dock_frames++; return; }
    if (g_dock_built) return;
    g_dock_built = true;

    ImGui::DockBuilderRemoveNode(dockspace_id);  // Clear any existing layout
    ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
    // DockBuilderSetNodeSize requires both dimensions > 0 (see imgui.cpp IM_ASSERT).
    ImVec2 node_sz = ImGui::GetMainViewport()->WorkSize;
    if (node_sz.x < 1.0f || node_sz.y < 1.0f)
        node_sz = ImGui::GetMainViewport()->Size;
    if (node_sz.x < 1.0f) node_sz.x = 1.0f;
    if (node_sz.y < 1.0f) node_sz.y = 1.0f;
    ImGui::DockBuilderSetNodeSize(dockspace_id, node_sz);

    ImGuiID left, center, bottom, right;
    left = ImGui::DockBuilderSplitNode(dockspace_id, ImGuiDir_Left, 0.25f, nullptr, &dockspace_id);
    right = ImGui::DockBuilderSplitNode(dockspace_id, ImGuiDir_Right, 0.33f, nullptr, &dockspace_id);
    bottom = ImGui::DockBuilderSplitNode(dockspace_id, ImGuiDir_Down, 0.30f, nullptr, &center);

    ImGui::DockBuilderDockWindow("Functions", left);
    ImGui::DockBuilderDockWindow("Sections", left);
    ImGui::DockBuilderDockWindow("Imports", left);
    ImGui::DockBuilderDockWindow("Hex / Diff", center);
    ImGui::DockBuilderDockWindow("Disassembly", center);
    ImGui::DockBuilderDockWindow("AOB Scanner", right);
    ImGui::DockBuilderDockWindow("Log", bottom);

    ImGui::DockBuilderFinish(dockspace_id);
}

// ─────────────────────────────────────────────────────────────────────────────
// Menu bar
// ─────────────────────────────────────────────────────────────────────────────
void DrawMenuBar() {
    if (!ImGui::BeginMainMenuBar()) return;

    // ── File ──────────────────────────────────────────────────────────────────
    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open file", "Ctrl+O")) {
            std::string path = OpenFileDialog(g_hwnd, L"Open PE / binary file");
            if (!path.empty()) {
                g_diff_mode = false;
                g_file_b = {}; g_pe_b = {};
                if (LoadFile(path, g_file_a, g_pe_a)) {
                    g_file_loaded = true;
                    ResetSessionAfterLoad(false);
                    AddRecentFile(path);
                }
                    
                // Auto-scan functions if setting is enabled
                if (g_settings.auto_find_fns && g_file_loaded) {
                    const auto* text = g_pe_a.find_section(".text");
                    if (text) {
                        atlus::Analyzer analyzer(GetDisasmMode());
                        g_functions = analyzer.find_functions(*text, g_pe_a.image_base);
                        Log("[info]  Auto-found %llu functions.", (unsigned long long)g_functions.size());
                    }
                }
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
                    if (g_diff_mode) {
                        ResetSessionAfterLoad(true);
                        AddRecentFile(path_a);
                        AddRecentFile(path_b);
                        Log("[info]  Diff mode ready.");
                        
                        // Auto-run full diff if setting is enabled
                        if (g_settings.auto_full_diff) {
                            g_diff_result = atlus::DiffEngine::full_diff(g_file_a, g_file_b, true, false);
                            g_signatures = atlus::PatternScanner::generate_signatures(g_diff_result.chunks);
                            Log("[info]  Auto-full diff: %llu bytes, %llu sections, %llu signatures", 
                                g_diff_result.byte_diffs.size(), 
                                g_diff_result.section_diffs.size(),
                                g_signatures.size());
                        }
                    }
                }
            }
        }
        ImGui::Separator();
        
        // Recent files submenu
        if (!g_recent_files.empty()) {
            if (ImGui::BeginMenu("Recent files")) {
                for (size_t i = 0; i < g_recent_files.size(); ++i) {
                    const auto& path = g_recent_files[i];
                    std::string filename = std::filesystem::path(path).filename().string();
                    if (ImGui::MenuItem(filename.c_str())) {
                        g_diff_mode = false;
                        g_file_b = {}; g_pe_b = {};
                        if (LoadFile(path, g_file_a, g_pe_a)) {
                            g_file_loaded = true;
                            ResetSessionAfterLoad(false);
                            AddRecentFile(path);  // Move to front
                            
                            // Auto-scan functions if setting is enabled
                            if (g_settings.auto_find_fns && g_file_loaded) {
                                const auto* text = g_pe_a.find_section(".text");
                                if (text) {
                                    atlus::Analyzer analyzer(GetDisasmMode());
                                    g_functions = analyzer.find_functions(*text, g_pe_a.image_base);
                                    Log("[info]  Auto-found %llu functions.", (unsigned long long)g_functions.size());
                                }
                            }
                        }
                    }
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
        }
        
        if (ImGui::MenuItem("Close", nullptr, false, g_file_loaded)) {
            g_selected_fn = nullptr;  // Fix dangling pointer
            g_functions.clear();
            g_functions_b.clear();
            g_file_a = {}; g_file_b = {};
            g_pe_a   = {}; g_pe_b   = {};
            g_file_loaded = false;
            g_diff_mode   = false;
            
            // Clear analysis results
            g_diff_result = {};
            g_signatures.clear();
            g_aob_hits.clear();
            g_disassembly.clear();
            g_disassembly_b.clear();
            g_function_diffs.clear();
            g_diff_offset_set.clear();
            
            Log("[info]  Session closed.");
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4"))
            ::PostQuitMessage(0);
        ImGui::EndMenu();
    }

    // ── Edit ──────────────────────────────────────────────────────────────────
    if (ImGui::BeginMenu("Edit")) {
        if (ImGui::MenuItem("Settings", "Ctrl+,"))
            g_show_settings = true;
        ImGui::EndMenu();
    }

    // ── View ──────────────────────────────────────────────────────────────────
    if (ImGui::BeginMenu("View")) {
        ImGui::MenuItem("Functions",   nullptr, &g_show_functions);
        ImGui::MenuItem("Sections",    nullptr, &g_show_sections);
        ImGui::MenuItem("Hex / Diff",  nullptr, &g_show_hex);
        ImGui::MenuItem("Disassembly", nullptr, &g_show_disasm);
        ImGui::MenuItem("Pseudocode",  nullptr, &g_show_pseudocode);
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
        // Single file actions first
        if (ImGui::MenuItem("Find functions (single file)", "F", false, g_file_loaded && !g_diff_mode)) {
            const auto* text = g_pe_a.find_section(".text");
            if (text) {
                atlus::Analyzer analyzer(GetDisasmMode());
                g_functions = analyzer.find_functions(*text, g_pe_a.image_base);
                Log("[info]  Found %zu functions.", g_functions.size());
            } else {
                Log("[error] No .text section found.");
            }
        }
        
        ImGui::Separator();
        
        // Diff mode actions
        if (ImGui::MenuItem("Run byte diff", "B", false, g_diff_mode)) {
            g_diff_result.byte_diffs = atlus::DiffEngine::byte_diff(g_file_a, g_file_b);
            g_diff_result.chunks = atlus::DiffEngine::make_chunks(g_diff_result.byte_diffs);
            
            // Build fast lookup set
            g_diff_offset_set.clear();
            for (const auto& diff : g_diff_result.byte_diffs) {
                g_diff_offset_set.insert(diff.offset);
            }
            
            Log("[info]  Byte diff: %llu changed bytes in %llu chunks", 
                (unsigned long long)g_diff_result.byte_diffs.size(), 
                (unsigned long long)g_diff_result.chunks.size());
        }
        if (ImGui::MenuItem("Run section diff", "S", false, g_diff_mode)) {
            g_diff_result.section_diffs = atlus::DiffEngine::section_diff(g_pe_a, g_pe_b);
            Log("[info]  Section diff: %llu sections compared", 
                (unsigned long long)g_diff_result.section_diffs.size());
        }
        if (ImGui::MenuItem("Find functions (both files)", "Shift+F", false, g_diff_mode)) {
            const auto* text_a = g_pe_a.find_section(".text");
            const auto* text_b = g_pe_b.find_section(".text");
            
            if (text_a && text_b) {
                atlus::Analyzer analyzer(GetDisasmMode());
                g_functions = analyzer.find_functions(*text_a, g_pe_a.image_base);
                g_functions_b = analyzer.find_functions(*text_b, g_pe_b.image_base);
                
                Log("[info]  Found %llu functions in old file, %llu in new file.", 
                    (unsigned long long)g_functions.size(), 
                    (unsigned long long)g_functions_b.size());
            } else {
                Log("[error] No .text section found in one or both files.");
            }
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Run function diff", "Shift+D", false, g_diff_mode && !g_functions.empty() && !g_functions_b.empty())) {
            g_function_diffs = atlus::DiffEngine::function_diff(g_functions, g_functions_b);
            Log("[info]  Function diff: %llu functions compared", 
                (unsigned long long)g_function_diffs.size());
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Full diff (all levels)", "Ctrl+Shift+D", false, g_diff_mode)) {
            g_diff_result = atlus::DiffEngine::full_diff(g_file_a, g_file_b, true, false);
            g_signatures = atlus::PatternScanner::generate_signatures(g_diff_result.chunks);
            
            // Build fast lookup set
            g_diff_offset_set.clear();
            for (const auto& diff : g_diff_result.byte_diffs) {
                g_diff_offset_set.insert(diff.offset);
            }
            
            Log("[info]  Full diff: %llu bytes, %llu sections, %llu signatures", 
                (unsigned long long)g_diff_result.byte_diffs.size(), 
                (unsigned long long)g_diff_result.section_diffs.size(),
                (unsigned long long)g_signatures.size());
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Scan AOB pattern", "A", false, g_file_loaded)) {
            g_aob_scan_trigger = true;
            g_show_aob = true;  // Ensure panel is visible
        }
        ImGui::EndMenu();
    }

    // ── Help ──────────────────────────────────────────────────────────────────
    if (ImGui::BeginMenu("Help")) {
        if (ImGui::MenuItem("About Atlus")) {
            ImGui::OpenPopup("##about");
        }
        ImGui::EndMenu();
    }

    // About modal
    if (ImGui::BeginPopupModal("##about", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove)) {
        ImGui::Text("Atlus - Binary Analysis Tool");
        ImGui::Separator();
        
        ImGui::Text("Version: 1.0.0");
        ImGui::Spacing();
        
        ImGui::Text("Built with:");
        ImGui::BulletText("Dear ImGui - https://github.com/ocornut/imgui");
        ImGui::BulletText("Zydis Disassembler - https://github.com/zyantific/zydis");
        ImGui::BulletText("LIEF - https://github.com/lief-project/LIEF");
        ImGui::Spacing();
        
        ImGui::Text("Keyboard Shortcuts:");
        ImGui::BulletText("F - Find functions (single file)");
        ImGui::BulletText("B - Run byte diff");
        ImGui::BulletText("S - Run section diff");
        ImGui::BulletText("Shift+D - Run function diff");
        ImGui::BulletText("Ctrl+Shift+D - Full diff");
        ImGui::BulletText("A - Scan AOB pattern");
        ImGui::Spacing();
        
        if (ImGui::Button("OK", ImVec2(80, 0))) {
            ImGui::CloseCurrentPopup();
        }
        
        ImGui::SetItemDefaultFocus();
        ImGui::EndPopup();
    }

    // Right-aligned status breadcrumb
    std::string status;
    if (!g_file_loaded)     status = "No file loaded";
    else if (g_diff_mode) {
        auto filename_a = std::filesystem::path(g_file_a.path).filename().string();
        auto filename_b = std::filesystem::path(g_file_b.path).filename().string();
        status = "[diff]  " + filename_a + "  vs  " + filename_b;
    } else {
        status = std::filesystem::path(g_file_a.path).filename().string();
    }

    float sw = ImGui::CalcTextSize(status.c_str()).x + 16.0f;
    ImGui::SetCursorPosX(ImGui::GetContentRegionMax().x - sw);
    ImGui::TextDisabled("%s", status.c_str());
    
    // Show full paths on hover
    if (ImGui::IsItemHovered()) {
        if (!g_file_loaded) {
            ImGui::SetTooltip("No file loaded");
        } else if (g_diff_mode) {
            ImGui::SetTooltip("Old: %s\nNew: %s", g_file_a.path.c_str(), g_file_b.path.c_str());
        } else {
            ImGui::SetTooltip("%s", g_file_a.path.c_str());
        }
    }

    ImGui::EndMainMenuBar();
}
