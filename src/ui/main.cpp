// Atlus GUI — Dear ImGui + Win32 + DirectX 11
// Layout: DockSpace fills the full window (Ghidra/IDA style).
// All panels are dockable — drag their title bars to reposition/split/tab them.

#include "gui_state.h"
#include "panels.h"
#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi.h>
#include <tchar.h>
#include <cstdio>
#include "core/analyzer.h"
#include "core/disassembler.h"
#include "core/diff_engine.h"
#include "core/pattern_scanner.h"
#include "core/ghidra_decompiler.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include "imgui_internal.h"         // DockBuilder API

// Helper to get disassembler mode from settings
static atlus::Disassembler::Mode GetDisasmMode() {
    return (g_settings.disasm_mode == 0) 
        ? atlus::Disassembler::Mode::X86_64 
        : atlus::Disassembler::Mode::X86_32;
}

// ── D3D11 globals ─────────────────────────────────────────────────────────────
static ID3D11Device*           g_pd3dDevice           = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext     = nullptr;
static IDXGISwapChain*         g_pSwapChain            = nullptr;
static bool                    g_SwapChainOccluded     = false;
static UINT                    g_ResizeWidth           = 0;
static UINT                    g_ResizeHeight          = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView  = nullptr;

// ── Forward declarations ───────────────────────────────────────────────────────
bool LoadFile(const std::string& path, atlus::BinaryFile& file, atlus::PEInfo& pe);
void BuildDefaultLayout(ImGuiID dockspace_id);
std::string OpenFileDialog(HWND owner, const wchar_t* title);

static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void CreateRenderTarget();
static void CleanupRenderTarget();
static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ─────────────────────────────────────────────────────────────────────────────
// Main application entry point
// ─────────────────────────────────────────────────────────────────────────────
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // Initialize COM for file dialogs
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE))) {
        return 1;
    }

    // Load settings
    LoadSettings();
    
    // Start decompiler subprocess if path is configured
    if (!g_settings.ghidra_path.empty()) {
        if (g_decompiler.start(g_settings.ghidra_path)) {
            Log("[info]  Decompiler started: %s", g_settings.ghidra_path.c_str());
        } else {
            Log("[warn]  Failed to start decompiler: %s", g_settings.ghidra_path.c_str());
        }
    }

    // Create application window
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"AtlusGUI", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Atlus", WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        CoUninitialize();
        return 1;
    }

    // Show the window
    ::ShowWindow(hwnd, nCmdShow);
    ::UpdateWindow(hwnd);
    
    // Set window handle for menu bar dialogs
    SetMenuBarHwnd(hwnd);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    // io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;  // Disabled - breaks docking and performance
    io.IniFilename = "atlus_layout.ini";

    // Setup Dear ImGui style
    if (g_settings.color_theme == 0) ImGui::StyleColorsDark();
    else if (g_settings.color_theme == 1) ImGui::StyleColorsLight();
    else ImGui::StyleColorsClassic();

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // Main loop
    bool done = false;
    while (!done) {
        // Poll and handle messages
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        // Handle window resize
        if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == S_OK) {
            g_SwapChainOccluded = false;
        }
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Main menu first so viewport WorkPos/WorkSize exclude the menu bar height.
        DrawMenuBar();

        // ── Main dockspace (full area below menu) ─────────────────────────────────
        {
            ImGuiViewport* vp = ImGui::GetMainViewport();
            ImGui::SetNextWindowPos(vp->WorkPos);
            ImGui::SetNextWindowSize(vp->WorkSize);
            ImGui::SetNextWindowViewport(vp->ID);

            constexpr ImGuiWindowFlags host_flags =
                ImGuiWindowFlags_NoTitleBar              |
                ImGuiWindowFlags_NoResize                |
                ImGuiWindowFlags_NoMove                  |
                ImGuiWindowFlags_NoScrollbar             |
                ImGuiWindowFlags_NoScrollWithMouse       |
                ImGuiWindowFlags_NoCollapse              |
                ImGuiWindowFlags_NoNav                   |
                ImGuiWindowFlags_NoBackground            |
                ImGuiWindowFlags_NoBringToFrontOnFocus   |
                ImGuiWindowFlags_NoNavFocus              |
                ImGuiWindowFlags_NoDocking;

            ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,   0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,    ImVec2(0, 0));
            ImGui::Begin("##DockspaceHost", nullptr, host_flags);
            ImGui::PopStyleVar(3);

            ImGuiID dockspace_id = ImGui::GetID("AtlusDockSpace");
            ImGui::DockSpace(dockspace_id, ImVec2(0, 0), ImGuiDockNodeFlags_None);
            BuildDefaultLayout(dockspace_id);

            ImGui::End();
        }

        // Handle keyboard shortcuts (only when not typing in text fields)
        ImGuiIO& keyboard_io = ImGui::GetIO();
        if (!keyboard_io.WantTextInput) {
            // File shortcuts
            if (ImGui::IsKeyPressed(ImGuiKey_O) && keyboard_io.KeyCtrl) {
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
            if (ImGui::IsKeyPressed(ImGuiKey_D) && keyboard_io.KeyCtrl) {
                std::string path_a = OpenFileDialog(g_hwnd, L"Select OLD / baseline file");
                if (!path_a.empty()) {
                    std::string path_b = OpenFileDialog(g_hwnd, L"Select NEW / patched file");
                    if (!path_b.empty()) {
                        g_diff_mode = true;
                        if (LoadFile(path_a, g_file_a, g_pe_a) && LoadFile(path_b, g_file_b, g_pe_b)) {
                            g_file_loaded = true;
                            ResetSessionAfterLoad(true);
                            AddRecentFile(path_a);
                            AddRecentFile(path_b);
                        }
                    }
                }
            }
            
            // Analysis shortcuts
            if (ImGui::IsKeyPressed(ImGuiKey_F) && !keyboard_io.KeyShift) {
                if (g_file_loaded && !g_diff_mode) {
                    const auto* text = g_pe_a.find_section(".text");
                    if (text) {
                        atlus::Analyzer analyzer(GetDisasmMode());
                        g_functions = analyzer.find_functions(*text, g_pe_a.image_base);
                        Log("[info]  Found %llu functions.", (unsigned long long)g_functions.size());
                    } else {
                        Log("[error] No .text section found.");
                    }
                }
            }
            if (ImGui::IsKeyPressed(ImGuiKey_B) && g_diff_mode) {
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
            if (ImGui::IsKeyPressed(ImGuiKey_S) && g_diff_mode) {
                g_diff_result.section_diffs = atlus::DiffEngine::section_diff(g_pe_a, g_pe_b);
                Log("[info]  Section diff: %llu sections compared", 
                    (unsigned long long)g_diff_result.section_diffs.size());
            }
            if (ImGui::IsKeyPressed(ImGuiKey_D) && keyboard_io.KeyShift && g_diff_mode && !g_functions.empty() && !g_functions_b.empty()) {
                g_function_diffs = atlus::DiffEngine::function_diff(g_functions, g_functions_b);
                Log("[info]  Function diff: %llu functions compared", 
                    (unsigned long long)g_function_diffs.size());
            }
            if (ImGui::IsKeyPressed(ImGuiKey_D) && keyboard_io.KeyCtrl && keyboard_io.KeyShift && g_diff_mode) {
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
            if (ImGui::IsKeyPressed(ImGuiKey_F) && keyboard_io.KeyShift && g_diff_mode) {
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
            if (ImGui::IsKeyPressed(ImGuiKey_A) && g_file_loaded) {
                // Trigger AOB scan - consume in DrawAobPanel
                extern bool g_aob_scan_trigger;
                g_aob_scan_trigger = true;
                g_show_aob = true;  // Ensure panel is visible
            }
        }

        // Draw dockable panels (menu bar already submitted above)
        DrawFunctionsPanel();
        DrawSectionsPanel();
        DrawImportsPanel();
        DrawHexPanel();
        DrawDisasmPanel();
        DrawAobPanel();
        DrawPseudocodePanel();
        DrawLogPanel();
        DrawSettingsModal();

        // Rendering
        ImGui::Render();
        const float cc[4] = {0.10f, 0.10f, 0.12f, 1.0f};
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, cc);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        const HRESULT hr = g_pSwapChain->Present(1, 0);
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    // Cleanup
    g_decompiler.stop();  // Stop decompiler subprocess
    SaveSettings();
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
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
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

    UINT createDeviceFlags = 0;
    #ifdef _DEBUG
    createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
    #endif

    D3D_FEATURE_LEVEL featureLevels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0 };
    D3D_FEATURE_LEVEL selectedLevel;

    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
        featureLevels, ARRAYSIZE(featureLevels),
        D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice,
        &selectedLevel, &g_pd3dDeviceContext);

    if (FAILED(res)) {
        res = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags,
            featureLevels, ARRAYSIZE(featureLevels),
            D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice,
            &selectedLevel, &g_pd3dDeviceContext);
    }

    if (FAILED(res)) return false;
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
