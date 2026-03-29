#include "gui_state.h"
#include "imgui.h"
#include <algorithm>
#include "core/pe_parser.h"
#include "core/diff_engine.h"
#include "core/analyzer.h"

// ── Left: sections ────────────────────────────────────────────────────────────
void DrawSectionsPanel() {
    if (!g_show_sections) return;
    if (!ImGui::Begin("Sections", &g_show_sections)) { ImGui::End(); return; }

    ImGui::TextDisabled("PE sections");
    ImGui::Separator();

    if (!g_file_loaded) { ImGui::TextDisabled("(open a file first)"); ImGui::End(); return; }
    if (!g_pe_a.valid)  { ImGui::TextDisabled("(not a valid PE)");    ImGui::End(); return; }

    constexpr ImGuiTableFlags tf =
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;

    const int ncols = g_diff_mode ? 4 : 5;
    if (ImGui::BeginTable("sec_tbl", ncols, tf)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("VA", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        if (!g_diff_mode) {
            ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        }
        ImGui::TableSetupColumn("Diff", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableHeadersRow();

        for (auto& sec : g_pe_a.sections) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            
            const char* name = sec.name.c_str();
            if (ImGui::Selectable(name, false, ImGuiSelectableFlags_SpanAllColumns)) {
                // Jump to section in hex view
                uint32_t rva = sec.vaddr;
                auto offset_opt = atlus::PEParser::rva_to_offset(g_pe_a, rva);
                if (offset_opt) {
                    g_hex_jump_to = *offset_opt;
                }
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("0x%08X", sec.vaddr);
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%llu", (unsigned long long)sec.vsize);
            
            int col_idx = 3;
            if (!g_diff_mode) {
                ImGui::TableSetColumnIndex(col_idx++);
                ImGui::Text("0x%08X", sec.flags);
            }
            
            ImGui::TableSetColumnIndex(col_idx);
            
            if (g_diff_mode) {
                // Show diff status
                auto it = std::find_if(g_diff_result.section_diffs.begin(), g_diff_result.section_diffs.end(),
                    [&](const atlus::SectionDiff& diff) { return diff.name == sec.name; });
                
                if (it != g_diff_result.section_diffs.end()) {
                    switch (it->status) {
                        case atlus::SectionDiff::Status::Modified: ImGui::TextColored(ImVec4(1,1,0,1), "MOD"); break;
                        case atlus::SectionDiff::Status::Added:    ImGui::TextColored(ImVec4(0,1,0,1), "ADD"); break;
                        case atlus::SectionDiff::Status::Removed:  ImGui::TextColored(ImVec4(1,0,0,1), "REM"); break;
                        default: ImGui::Text("-"); break;
                    }
                } else {
                    ImGui::Text("-");
                }
            } else {
                ImGui::TextDisabled("-");
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

// ── Left: imports ─────────────────────────────────────────────────────────────
void DrawImportsPanel() {
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

    // Search filter
    static char imp_filter[128] = "";
    ImGui::InputText("Filter", imp_filter, sizeof(imp_filter));
    ImGui::Separator();

    // Helper to check if filter matches
    auto filter_matches = [&](const char* text) -> bool {
        if (imp_filter[0] == '\0') return true;
        std::string text_lower = text;
        std::string filter_lower = imp_filter;
        std::transform(text_lower.begin(), text_lower.end(), text_lower.begin(), ::tolower);
        std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(), ::tolower);
        return text_lower.find(filter_lower) != std::string::npos;
    };

    for (const auto& ie : g_pe_a.imports) {
        // Check if DLL name matches filter, or any of its functions do
        bool dll_matches = filter_matches(ie.dll.c_str());
        bool any_fn_matches = false;
        for (const auto& fn : ie.functions) {
            if (filter_matches(fn.c_str())) {
                any_fn_matches = true;
                break;
            }
        }
        
        if (!dll_matches && !any_fn_matches) continue;
        
        if (ImGui::TreeNode(ie.dll.c_str())) {
            for (const auto& fn : ie.functions) {
                if (imp_filter[0] == '\0' || filter_matches(fn.c_str())) {
                    ImGui::TextUnformatted(fn.c_str());
                }
            }
            ImGui::TreePop();
        }
    }
    ImGui::End();
}
