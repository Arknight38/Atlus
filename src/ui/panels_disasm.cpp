#include "gui_state.h"
#include "imgui.h"
#include <algorithm>
#include "core/analyzer.h"
#include "core/pe_parser.h"
#include "core/disassembler.h"

// Helper to get disassembler mode from settings
static atlus::Disassembler::Mode GetDisasmMode() {
    return (g_settings.disasm_mode == 0) 
        ? atlus::Disassembler::Mode::X86_64 
        : atlus::Disassembler::Mode::X86_32;
}

// ── Center: disassembly ───────────────────────────────────────────────────────
static atlus::Function* g_last_disasm_fn = nullptr;

void DrawDisasmPanel() {
    if (!g_show_disasm) return;
    if (!ImGui::Begin("Disassembly", &g_show_disasm)) { ImGui::End(); return; }

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

    if (g_diff_mode) {
        // Side-by-side diff view
        ImGui::TextDisabled("Function diff (side-by-side)");
        ImGui::Separator();
        
        ImGui::Text("Function: %s", g_selected_fn->name.c_str());
        ImGui::Text("Address: 0x%08llX - 0x%08llX", 
                   (unsigned long long)g_selected_fn->start_address,
                   (unsigned long long)g_selected_fn->end_address);
        ImGui::Separator();
        
        // Disassemble both versions if not already done
        if (g_disassembly.empty() || g_selected_fn != g_last_disasm_fn) {
            g_last_disasm_fn = g_selected_fn;
            g_disassembly.clear();
            
            uint32_t rva = (uint32_t)(g_selected_fn->start_address - g_pe_a.image_base);
            auto offset_opt = atlus::PEParser::rva_to_offset(g_pe_a, rva);
            if (offset_opt) {
                size_t offset = *offset_opt;
                
                if (offset < g_file_a.size()) {
                    atlus::Disassembler disasm(GetDisasmMode());
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
        
        if (g_disassembly_b.empty() && !g_functions_b.empty()) {
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
                        atlus::Disassembler disasm(GetDisasmMode());
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
                    }
                }
                
                ImGui::EndTable();
            }
        } else {
            ImGui::TextDisabled("(no disassembly available)");
        }
    } else {
        // Single file view
        ImGui::TextDisabled("Function disassembly");
        ImGui::Separator();
        
        ImGui::Text("Function: %s", g_selected_fn->name.c_str());
        ImGui::Text("Address: 0x%08llX - 0x%08llX", 
                   (unsigned long long)g_selected_fn->start_address,
                   (unsigned long long)g_selected_fn->end_address);
        ImGui::Separator();
        
        // Disassemble if not already done
        if (g_disassembly.empty() || g_selected_fn != g_last_disasm_fn) {
            g_last_disasm_fn = g_selected_fn;
            g_disassembly.clear();
            
            uint32_t rva = (uint32_t)(g_selected_fn->start_address - g_pe_a.image_base);
            auto offset_opt = atlus::PEParser::rva_to_offset(g_pe_a, rva);
            if (offset_opt) {
                size_t offset = *offset_opt;
                
                if (offset < g_file_a.size()) {
                    atlus::Disassembler disasm(GetDisasmMode());
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
                
                for (const auto& insn : g_disassembly) {
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
                
                ImGui::EndTable();
            }
        } else {
            ImGui::TextDisabled("(no disassembly available)");
        }
    }

    ImGui::End();
}

void ResetDisasmPanelCaches() {
    g_last_disasm_fn = nullptr;
}
