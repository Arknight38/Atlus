#pragma once
#include <string>

// Cross-platform file dialog abstractions
std::string OpenFileDialog(const char* title, const char* filter = nullptr);
std::string SaveFileDialog(const char* title, const char* default_name = nullptr, const char* filter = nullptr);

// Signal that the application should exit (replaces PostQuitMessage / WM_QUIT)
extern bool g_app_done;
void RequestAppQuit();
