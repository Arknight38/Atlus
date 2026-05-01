#include "dialogs.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <array>
#include <string>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#include <shobjidl.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

static bool EnsureCOMInitialized() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    return SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
}
#else
#include <memory>
#endif

bool g_app_done = false;

// ============================================================================
// Windows: native COM file dialogs
// ============================================================================
#ifdef _WIN32

std::string OpenFileDialog(const char* title, const char* /*filter*/) {
    std::string result;
    if (!EnsureCOMInitialized()) return result;

    IFileOpenDialog* pfd = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr,
                                  CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pfd));
    if (FAILED(hr)) return result;

    COMDLG_FILTERSPEC filters[] = {
        { L"PE files (*.exe, *.dll, *.sys, *.bin)", L"*.exe;*.dll;*.sys;*.bin" },
        { L"All files (*.*)",                        L"*.*"                    },
    };
    pfd->SetFileTypes(ARRAYSIZE(filters), filters);
    pfd->SetFileTypeIndex(1);
    if (title) {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, title, -1, nullptr, 0);
        if (wlen > 0) {
            std::wstring wtitle(wlen - 1, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, title, -1, wtitle.data(), wlen);
            pfd->SetTitle(wtitle.c_str());
        }
    }

    hr = pfd->Show(nullptr);
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
    pfd->Release();
    return result;
}

std::string SaveFileDialog(const char* title, const char* default_name, const char* /*filter*/) {
    std::string result;
    if (!EnsureCOMInitialized()) return result;

    IFileSaveDialog* psd = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileSaveDialog, nullptr,
                                  CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&psd));
    if (FAILED(hr)) return result;

    COMDLG_FILTERSPEC filters[] = {
        { L"Atlus Session (*.atlus)", L"*.atlus" },
        { L"All files (*.*)",       L"*.*"    },
    };
    psd->SetFileTypes(ARRAYSIZE(filters), filters);
    psd->SetFileTypeIndex(1);
    if (title) {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, title, -1, nullptr, 0);
        if (wlen > 0) {
            std::wstring wtitle(wlen - 1, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, title, -1, wtitle.data(), wlen);
            psd->SetTitle(wtitle.c_str());
        }
    }
    if (default_name) {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, default_name, -1, nullptr, 0);
        if (wlen > 0) {
            std::wstring wname(wlen - 1, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, default_name, -1, wname.data(), wlen);
            psd->SetFileName(wname.c_str());
        }
    }

    hr = psd->Show(nullptr);
    if (SUCCEEDED(hr)) {
        IShellItem* psi = nullptr;
        if (SUCCEEDED(psd->GetResult(&psi))) {
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
    psd->Release();
    return result;
}

void RequestAppQuit() {
    g_app_done = true;
    // With GLFW on Windows we still rely on g_app_done in the main loop.
}

// ============================================================================
// macOS: osascript-based dialogs
// ============================================================================
#elif defined(__APPLE__)

static std::string exec(const char* cmd) {
    std::array<char, 4096> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) return "";
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    if (!result.empty() && result.back() == '\n') result.pop_back();
    return result;
}

std::string OpenFileDialog(const char* title, const char* /*filter*/) {
    std::string cmd = "osascript -e 'POSIX path of (choose file";
    if (title) {
        cmd += " with prompt \"";
        cmd += title;
        cmd += "\"";
    }
    cmd += ")'";
    return exec(cmd.c_str());
}

std::string SaveFileDialog(const char* title, const char* default_name, const char* /*filter*/) {
    std::string cmd = "osascript -e 'POSIX path of (choose file name";
    if (title) {
        cmd += " with prompt \"";
        cmd += title;
        cmd += "\"";
    }
    if (default_name) {
        cmd += " default name \"";
        cmd += default_name;
        cmd += "\"";
    }
    cmd += ")'";
    return exec(cmd.c_str());
}

void RequestAppQuit() {
    g_app_done = true;
}

// ============================================================================
// Linux: zenity / kdialog fallback
// ============================================================================
#else

static std::string exec(const char* cmd) {
    std::array<char, 4096> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) return "";
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    if (!result.empty() && result.back() == '\n') result.pop_back();
    return result;
}

std::string OpenFileDialog(const char* title, const char* /*filter*/) {
    std::string cmd = "zenity --file-selection";
    if (title) {
        cmd += " --title=\"";
        cmd += title;
        cmd += "\"";
    }
    std::string result = exec(cmd.c_str());
    if (result.empty()) {
        // Fallback to kdialog
        cmd = "kdialog --getopenfilename .";
        if (title) {
            cmd += " :\"";
            cmd += title;
            cmd += "\"";
        }
        result = exec(cmd.c_str());
    }
    return result;
}

std::string SaveFileDialog(const char* title, const char* default_name, const char* /*filter*/) {
    std::string cmd = "zenity --file-selection --save";
    if (title) {
        cmd += " --title=\"";
        cmd += title;
        cmd += "\"";
    }
    if (default_name) {
        cmd += " --filename=\"";
        cmd += default_name;
        cmd += "\"";
    }
    std::string result = exec(cmd.c_str());
    if (result.empty()) {
        cmd = "kdialog --getsavefilename .";
        if (title) {
            cmd += " :\"";
            cmd += title;
            cmd += "\"";
        }
        result = exec(cmd.c_str());
    }
    return result;
}

void RequestAppQuit() {
    g_app_done = true;
}

#endif
