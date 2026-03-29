#include "gui_state.h"
#include "imgui.h"
#include <chrono>
#include <future>
#include <sstream>
#include "core/ghidra_decompiler.h"

// ── Pseudocode panel ───────────────────────────────────────────────────────────
void DrawPseudocodePanel() {
    if (!g_show_pseudocode) return;
    if (!ImGui::Begin("Pseudocode", &g_show_pseudocode)) { ImGui::End(); return; }

    ImGui::TextDisabled("Ghidra Decompiler Output");
    ImGui::Separator();

    if (!g_file_loaded) { 
        ImGui::TextDisabled("(open a file first)"); 
        ImGui::End(); 
        return; 
    }

    if (!g_selected_fn) {
        ImGui::TextDisabled("[ select a function from the Functions panel ]");
        ImGui::End();
        return;
    }

    // Show function info
    ImGui::Text("Function: %s", g_selected_fn->name.c_str());
    ImGui::Text("Address: 0x%08llX", (unsigned long long)g_selected_fn->start_address);
    
    // Show decompiler status
    bool running = g_decompiler.is_running();
    if (running) {
        ImGui::SameLine(ImGui::GetContentRegionMax().x - 80);
        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "[Running]");
    } else {
        ImGui::SameLine(ImGui::GetContentRegionMax().x - 80);
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f), "[Stopped]");
    }
    
    ImGui::Separator();

    // Show decompilation status
    if (g_decompile_pending) {
        // Check if future is ready
        if (g_decompile_future.valid()) {
            auto status = g_decompile_future.wait_for(std::chrono::seconds(0));
            if (status == std::future_status::ready) {
                auto result = g_decompile_future.get();
                g_decompile_pending = false;
                
                if (result.success) {
                    g_pseudocode = result.pseudocode;
                    Log("[info]  Decompilation complete: %s", g_selected_fn->name.c_str());
                } else {
                    g_pseudocode = "// Decompilation failed: " + result.error;
                    Log("[error] Decompilation failed: %s", result.error.c_str());
                }
            } else {
                ImGui::TextDisabled("Decompiling...");
                ImGui::End();
                return;
            }
        }
    }

    // Display pseudocode or status
    if (!g_pseudocode.empty()) {
        ImGui::BeginChild("pseudocode_view", ImVec2(0, 0), true, 
                          ImGuiWindowFlags_HorizontalScrollbar);
        
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]);
        
        std::istringstream stream(g_pseudocode);
        std::string line;
        int line_num = 1;
        
        while (std::getline(stream, line)) {
            ImGui::Text("%4d |  %s", line_num++, line.c_str());
        }
        
        ImGui::PopFont();
        ImGui::EndChild();
    } else {
        if (!running) {
            ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f), 
                "Decompiler not running. Check path in Settings → Decompiler");
            
            if (ImGui::Button("Open Settings")) {
                g_show_settings = true;
            }
        } else {
            ImGui::TextDisabled("(no pseudocode - select a function to trigger decompilation)");
        }
    }

    ImGui::End();
}
