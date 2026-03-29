#include "gui_state.h"
#include "imgui.h"

// ── Bottom: log ───────────────────────────────────────────────────────────────

// Auto-scroll state
static bool log_auto_scroll = true;

void DrawLogPanel() {
    if (!g_show_log) return;
    if (!ImGui::Begin("Log", &g_show_log)) { ImGui::End(); return; }

    ImGui::TextDisabled("Log messages");
    ImGui::SameLine(ImGui::GetContentRegionMax().x - 100);
    ImGui::Checkbox("Auto-scroll", &log_auto_scroll);
    ImGui::Separator();

    ImGui::BeginChild("log_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    for (const auto& line : g_log_lines) {
        // Color coding based on log level
        if (line.find("[error]") == 0) {
            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255,100,100,255));
        } else if (line.find("[warn]") == 0) {
            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255,200,100,255));
        } else if (line.find("[info]") == 0) {
            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200,200,200,255));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(150,150,150,255));
        }
        
        ImGui::TextUnformatted(line.c_str());
        ImGui::PopStyleColor();
    }

    // Auto-scroll to bottom (only if enabled)
    if (log_auto_scroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
        ImGui::SetScrollHereY(1.0f);
    }

    ImGui::EndChild();
    ImGui::End();
}
