#include "gui_state.h"
#include "imgui.h"
#include <cstring>
#include <algorithm>
#include <cctype>
#include <future>
#include "core/analyzer.h"
#include "core/ghidra_decompiler.h"

// ── Left: functions ───────────────────────────────────────────────────────────
void DrawFunctionsPanel() {
    if (!g_show_functions) return;
    if (!ImGui::Begin("Functions", &g_show_functions)) { ImGui::End(); return; }

    ImGui::TextDisabled("Functions (prologue scan)");
    ImGui::Separator();

    if (!g_file_loaded) { ImGui::TextDisabled("(open a file first)"); ImGui::End(); return; }

    // Search filter
    static char fn_filter[128] = "";
    ImGui::InputText("Filter", fn_filter, sizeof(fn_filter));
    ImGui::Separator();

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
            // Apply filter (case-insensitive)
            if (fn_filter[0] != '\0') {
                std::string fn_lower = fn.name;
                std::string filter_lower = fn_filter;
                std::transform(fn_lower.begin(), fn_lower.end(), fn_lower.begin(), ::tolower);
                std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(), ::tolower);
                if (fn_lower.find(filter_lower) == std::string::npos) {
                    continue;
                }
            }
            
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            
            bool sel = (g_selected_fn == &fn);
            if (ImGui::Selectable(fn.name.c_str(), sel, ImGuiSelectableFlags_SpanAllColumns)) {
                g_selected_fn = &fn;
                g_disassembly.clear();      // Clear previous disassembly
                g_disassembly_b.clear();    // Clear diff side too
                g_pseudocode.clear();       // Clear previous pseudocode
                
                // Trigger decompilation in background
                if (g_decompiler.is_running()) {
                    // Cancel any pending decompilation
                    if (g_decompile_future.valid() && g_decompile_pending.load()) {
                        // Note: std::future cannot be cancelled, we just abandon it
                        g_decompile_pending.store(false);
                    }
                    
                    // Start new decompilation
                    g_decompile_pending.store(true);
                    g_decompile_future = std::async(std::launch::async, [&]() {
                        return g_decompiler.decompile(
                            g_file_a.path,
                            fn.start_address,
                            fn.size_bytes
                        );
                    });
                }
            }
            
            ImGui::TableSetColumnIndex(1); 
            ImGui::Text("0x%08llX", (unsigned long long)fn.start_address);
            ImGui::TableSetColumnIndex(2); 
            ImGui::Text("%llu", (unsigned long long)fn.size_bytes);
        }
        ImGui::EndTable();
    }
    ImGui::End();
}
