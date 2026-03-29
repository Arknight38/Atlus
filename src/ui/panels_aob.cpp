#include "gui_state.h"
#include "imgui.h"
#include <algorithm>
#include <numeric>
#include "core/pattern_scanner.h"

// ── Right: AOB scanner ───────────────────────────────────────────────────────
void DrawAobPanel() {
    if (!g_show_aob) return;
    if (!ImGui::Begin("AOB Scanner", &g_show_aob)) { ImGui::End(); return; }

    ImGui::TextDisabled("Array of Bytes pattern scanner");
    ImGui::Separator();

    if (!g_file_loaded) { ImGui::TextDisabled("(open a file first)"); ImGui::End(); return; }

    // Pattern input
    static char pattern[256] = "";
    ImGui::InputTextWithHint("Pattern", "e.g. 48 8B ?? ?? ?? ?? 48 89", pattern, sizeof(pattern));

    // Check for external scan trigger (from menu/shortcut)
    if (g_aob_scan_trigger && pattern[0] != '\0') {
        g_aob_scan_trigger = false;  // Consume the trigger
        ImGui::Button("Scan");  // Just to keep layout consistent, actual scan below
    } else {
        ImGui::SameLine();
    }

    if ((ImGui::Button("Scan") || g_aob_scan_trigger) && pattern[0] != '\0') {
        g_aob_scan_trigger = false;  // Ensure consumed
        Log("[info]  AOB scan for pattern: %s", pattern);
        g_aob_hits.clear();
        
        // Parse IDA-style pattern and scan
        auto pat = atlus::PatternScanner::parse_ida(pattern);
        if (pat) {
            g_aob_hits = atlus::PatternScanner::scan(g_file_a.data, *pat);
            Log("[info]  Found %llu hits", (unsigned long long)g_aob_hits.size());
        } else {
            Log("[error]  Failed to parse pattern");
        }
    }

    ImGui::Separator();

    if (!g_aob_hits.empty()) {
        ImGui::TextDisabled("%llu hits found", (unsigned long long)g_aob_hits.size());
        ImGui::Separator();

        ImGui::BeginChild("aob_hits", ImVec2(0, 0), false);
        
        ImGuiListClipper clipper;
        clipper.Begin((int)g_aob_hits.size());
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                size_t offset = g_aob_hits[i];
                ImGui::Text("0x%08llX", (unsigned long long)offset);
                
                // Show context bytes if setting is enabled
                if (g_settings.aob_context_bytes > 0) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("  ");
                    ImGui::SameLine();
                    
                    const int ctx = g_settings.aob_context_bytes;
                    const size_t start = (offset >= (size_t)ctx) ? offset - ctx : 0;
                    const size_t end = std::min(offset + (size_t)ctx + 1, g_file_a.size());
                    
                    std::string ctx_str;
                    for (size_t j = start; j < end; ++j) {
                        if (j == offset) {
                            ctx_str += "[";
                        }
                        char buf[8];
                        snprintf(buf, sizeof(buf), "%02X", g_file_a.data[j]);
                        ctx_str += buf;
                        if (j == offset) {
                            ctx_str += "]";
                        }
                        ctx_str += " ";
                    }
                    
                    ImGui::TextUnformatted(ctx_str.c_str());
                }
            }
        }
        clipper.End();
        
        ImGui::EndChild();
    } else {
        ImGui::TextDisabled("(no scan results)");
    }

    // Show signatures from diff (if any)
    if (!g_signatures.empty()) {
        ImGui::Separator();
        ImGui::TextDisabled("Signatures from diff (%llu)", (unsigned long long)g_signatures.size());
        
        ImGui::BeginChild("aob_signatures", ImVec2(0, 120), true);
        
        for (const auto& sig : g_signatures) {
            ImGui::Text("0x%08llX:", (unsigned long long)sig.offset);
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.6f, 0.8f, 1.0f, 1.0f), "%s", sig.ida_style.c_str());
            
            // Show CE-style pattern if setting enabled
            if (g_settings.aob_show_ce && !sig.ce_style.empty()) {
                ImGui::SameLine();
                ImGui::TextDisabled("[%s]", sig.ce_style.c_str());
            }
        }
        
        ImGui::EndChild();
    }

    ImGui::End();
}
