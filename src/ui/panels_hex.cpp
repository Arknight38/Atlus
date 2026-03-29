#include "gui_state.h"
#include "imgui.h"
#include <algorithm>
#include "core/pe_parser.h"

// Context menu state - file scope so popup can read values set on right-click
static size_t ctx_offset = 0;
static uint8_t ctx_byte = 0;

// ── Center: hex viewer ────────────────────────────────────────────────────────
void DrawHexPanel() {
    if (!g_show_hex) return;
    if (!ImGui::Begin("Hex / Diff", &g_show_hex)) { ImGui::End(); return; }

    if (!g_file_loaded) { ImGui::TextDisabled("(open a file first)"); ImGui::End(); return; }

    ImGui::TextDisabled("%s  |  %llu bytes", g_file_a.path.c_str(), (unsigned long long)g_file_a.size());
    ImGui::Separator();

    const auto& data = g_file_a.data;
    const int   cols_map[] = {8, 16, 32};
    int           col_idx = g_settings.hex_cols;
    if (col_idx < 0 || col_idx > 2) col_idx = 1;  // combo indices 0..2 (legacy ini used 8/16/32)
    const int   cols = cols_map[col_idx];
    const int   rows = (int)((data.size() + cols - 1) / cols);

    ImGui::BeginChild("hex_scroll", ImVec2(0, 0), false,
                      ImGuiWindowFlags_HorizontalScrollbar);

    // Handle jump request
    if (g_hex_jump_to != SIZE_MAX) {
        const int jump_row = (int)(g_hex_jump_to / cols);
        const float row_height = ImGui::GetTextLineHeightWithSpacing();
        ImGui::SetScrollY((float)jump_row * row_height);
        g_hex_jump_to = SIZE_MAX;  // Clear request
    }

    ImGuiListClipper clipper;
    clipper.Begin(rows);
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const size_t base = (size_t)row * cols;

            ImGui::Text("%08llX  ", (unsigned long long)base);

            for (int col = 0; col < cols; ++col) {
                ImGui::SameLine();
                const size_t idx = base + col;
                if (idx < data.size()) {
                    // Fast diff lookup using the unordered_set
                    bool is_changed = g_diff_mode && g_diff_offset_set.count(idx) > 0;
                    
                    if (is_changed) {
                        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255,80,80,255));
                        ImGui::Text("%02X", data[idx]);
                        ImGui::PopStyleColor();
                    } else {
                        ImGui::Text("%02X", data[idx]);
                    }
                    
                    // Right-click context menu
                    if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
                        ctx_offset = idx;
                        ctx_byte = data[idx];
                        ImGui::OpenPopup("hex_ctx");
                    }
                } else {
                    ImGui::TextDisabled("  ");
                }
                if (col == 7) ImGui::SameLine(0, 8);
            }

            // ASCII sidebar (if enabled)
            if (g_settings.show_hex_ascii) {
                ImGui::SameLine(0, 16);
                char ascii[33];  // Max 32 columns + null
                for (int col = 0; col < cols; ++col) {
                    const size_t idx = base + col;
                    ascii[col] = (idx < data.size() && data[idx] >= 0x20 && data[idx] < 0x7F)
                                 ? (char)data[idx] : '.';
                }
                ascii[cols] = '\0';
                ImGui::TextUnformatted(ascii);
            }
        }
    }
    clipper.End();

    // Context menu
    if (ImGui::BeginPopup("hex_ctx")) {
        if (ImGui::MenuItem("Copy offset")) {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)ctx_offset);
            ImGui::SetClipboardText(buf);
            Log("[info]  Copied offset: %s", buf);
        }
        if (ImGui::MenuItem("Copy byte")) {
            char buf[8];
            snprintf(buf, sizeof(buf), "0x%02X", ctx_byte);
            ImGui::SetClipboardText(buf);
            Log("[info]  Copied byte: %s", buf);
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Jump to section")) {
            // Find containing section and jump
            for (const auto& sec : g_pe_a.sections) {
                uint32_t file_offset = atlus::PEParser::rva_to_offset(g_pe_a, sec.vaddr).value_or(0);
                if (ctx_offset >= file_offset && ctx_offset < file_offset + sec.vsize) {
                    g_hex_jump_to = file_offset;
                    Log("[info]  Jumped to section %s", sec.name.c_str());
                    break;
                }
            }
        }
        ImGui::EndPopup();
    }

    ImGui::EndChild();
    ImGui::End();
}
