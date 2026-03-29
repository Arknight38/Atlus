#include "gui_state.h"
#include "imgui.h"
#include <cstring>
#include "core/ghidra_decompiler.h"

// Forward declaration from menu_bar.cpp
std::string OpenFileDialog(HWND owner, const wchar_t* title);

// ─────────────────────────────────────────────────────────────────────────────
// Settings modal
// ─────────────────────────────────────────────────────────────────────────────
void DrawSettingsModal() {
    if (!g_show_settings) return;
    
    ImGui::SetNextWindowSize(ImVec2(480, 360), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Settings", &g_show_settings,
                      ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoDocking)) {
        ImGui::End(); 
        return;
    }

    if (ImGui::BeginTabBar("settings_tabs")) {

        if (ImGui::BeginTabItem("Appearance")) {
            ImGui::SliderFloat("Font size", &g_settings.font_size, 10.0f, 20.0f, "%.0f px");
            if (ImGui::IsItemDeactivatedAfterEdit()) {
                ApplyFontSize(g_settings.font_size);
            }
            
            ImGui::Combo("Theme", &g_settings.color_theme, "Dark\0Light\0Classic\0");
            if (ImGui::IsItemEdited()) {
                if      (g_settings.color_theme == 0) ImGui::StyleColorsDark();
                else if (g_settings.color_theme == 1) ImGui::StyleColorsLight();
                else                                   ImGui::StyleColorsClassic();
                Log("[info]  Theme changed");
            }
            
            ImGui::Checkbox("Show ASCII sidebar in hex view", &g_settings.show_hex_ascii);
            ImGui::Combo("Hex columns", &g_settings.hex_cols, "8\016\032\0");
            if (ImGui::IsItemEdited()) {
                Log("[info]  Hex columns changed to %d", g_settings.hex_cols);
            }
            
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Analysis")) {
            ImGui::Checkbox("Auto-scan functions on file open", &g_settings.auto_find_fns);
            ImGui::Checkbox("Auto-run full diff on diff open",  &g_settings.auto_full_diff);
            ImGui::Combo("Disassembler mode", &g_settings.disasm_mode, "x86-64\0x86-32\0");
            
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("AOB")) {
            ImGui::Checkbox("Show CE-style patterns", &g_settings.aob_show_ce);
            ImGui::SliderInt("Context bytes", &g_settings.aob_context_bytes, 0, 32);
            
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Log")) {
            ImGui::SliderInt("Max log lines", &g_settings.log_max_lines, 100, 10000);
            if (ImGui::IsItemEdited()) {
                while (g_log_lines.size() > (size_t)g_settings.log_max_lines) {
                    g_log_lines.pop_front();
                }
                Log("[info]  Log max lines changed to %d", g_settings.log_max_lines);
            }
            
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Decompiler")) {
            ImGui::Text("Ghidra Decompiler Path:");
            
            char path_buf[512] = {};
            strncpy(path_buf, g_settings.ghidra_path.c_str(), sizeof(path_buf) - 1);
            
            if (ImGui::InputText("##ghidra_path", path_buf, sizeof(path_buf))) {
                g_settings.ghidra_path = path_buf;
            }
            
            ImGui::SameLine();
            if (ImGui::Button("Browse##ghidra")) {
                std::string path = OpenFileDialog(g_hwnd, L"Select Ghidra decompile.exe");
                if (!path.empty()) {
                    g_settings.ghidra_path = path;
                }
            }
            
            ImGui::Separator();
            
            bool running = g_decompiler.is_running();
            
            ImGui::Text("Status: %s", running ? "Running" : "Stopped");
            
            if (ImGui::Button(running ? "Stop" : "Start")) {
                if (running) {
                    g_decompiler.stop();
                    Log("[info]  Decompiler stopped");
                } else {
                    if (g_decompiler.start(g_settings.ghidra_path)) {
                        Log("[info]  Decompiler started: %s", g_settings.ghidra_path.c_str());
                    } else {
                        Log("[error] Failed to start decompiler: %s", g_settings.ghidra_path.c_str());
                    }
                }
            }
            
            ImGui::SameLine();
            if (ImGui::Button("Clear Cache")) {
                g_decompiler.clear_cache();
                Log("[info]  Decompiler cache cleared");
            }
            
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::Separator();
    if (ImGui::Button("Close")) {
        g_show_settings = false;
        SaveSettings();  // Auto-save on close
    }

    ImGui::End();
}
