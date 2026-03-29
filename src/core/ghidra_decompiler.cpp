#include "core/ghidra_decompiler.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <thread>

namespace atlus {

// Global instance
GhidraDecompiler g_decompiler;
std::future<DecompileResult> g_decompile_future;
std::atomic<bool> g_decompile_pending{false};
std::atomic<uint64_t> g_decompile_target_addr{0};

// ============================================================================
// Constructor / Destructor
// ============================================================================

GhidraDecompiler::GhidraDecompiler() = default;

GhidraDecompiler::~GhidraDecompiler() {
    stop();
}

// ============================================================================
// Process Management
// ============================================================================

bool GhidraDecompiler::start(const std::string& decompiler_path) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    if (running_) {
        return true;  // Already running
    }
    
    decompiler_path_ = decompiler_path;
    
    // Create pipes for stdin/stdout
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;
    
    HANDLE h_stdin_read = nullptr;
    HANDLE h_stdout_write = nullptr;
    
    if (!CreatePipe(&h_stdin_read, &h_stdin_write_, &sa, 0)) {
        return false;
    }
    if (!CreatePipe(&h_stdout_read_, &h_stdout_write, &sa, 0)) {
        CloseHandle(h_stdin_read);
        CloseHandle(h_stdin_write_);
        h_stdin_write_ = nullptr;
        return false;
    }
    
    // Ensure write handles are not inherited by child
    SetHandleInformation(h_stdin_write_, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(h_stdout_read_, HANDLE_FLAG_INHERIT, 0);
    
    // Prepare process
    STARTUPINFOA si{};
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = h_stdin_read;
    si.hStdOutput = h_stdout_write;
    si.hStdError = h_stdout_write;  // Redirect stderr to stdout
    si.wShowWindow = SW_HIDE;
    
    // Build command line
    std::string cmd = "\"" + decompiler_path + "\"";
    
    char cmd_buffer[MAX_PATH * 2] = {};
    strncpy_s(cmd_buffer, cmd.c_str(), sizeof(cmd_buffer) - 1);
    
    BOOL created = CreateProcessA(
        nullptr,                    // Application name (use command line)
        cmd_buffer,                 // Command line
        nullptr,                    // Process security attributes
        nullptr,                    // Thread security attributes
        TRUE,                       // Inherit handles
        CREATE_NO_WINDOW,           // Creation flags
        nullptr,                    // Environment
        nullptr,                    // Current directory
        &si,
        &proc_info_
    );
    
    // Close our copies of child's ends
    CloseHandle(h_stdin_read);
    CloseHandle(h_stdout_write);
    
    if (!created) {
        CloseHandle(h_stdin_write_);
        CloseHandle(h_stdout_read_);
        h_stdin_write_ = nullptr;
        h_stdout_read_ = nullptr;
        return false;
    }
    
    h_process_ = proc_info_.hProcess;
    running_ = true;
    
    // Give process a moment to initialize
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    return true;
}

void GhidraDecompiler::stop() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    if (!running_) {
        return;
    }
    
    // Close pipes first to signal EOF to child
    if (h_stdin_write_) {
        CloseHandle(h_stdin_write_);
        h_stdin_write_ = nullptr;
    }
    if (h_stdout_read_) {
        CloseHandle(h_stdout_read_);
        h_stdout_read_ = nullptr;
    }
    
    // Gracefully terminate if still running
    if (h_process_) {
        // Wait up to 500ms for graceful exit
        if (WaitForSingleObject(h_process_, 500) == WAIT_TIMEOUT) {
            TerminateProcess(h_process_, 1);
        }
        CloseHandle(h_process_);
        CloseHandle(proc_info_.hThread);
        h_process_ = nullptr;
    }
    
    ZeroMemory(&proc_info_, sizeof(proc_info_));
    running_ = false;
}

bool GhidraDecompiler::is_running() const {
    if (!running_ || !h_process_) {
        return false;
    }
    
    DWORD exit_code = 0;
    if (!GetExitCodeProcess(h_process_, &exit_code)) {
        return false;
    }
    
    return exit_code == STILL_ACTIVE;
}

bool GhidraDecompiler::wait_for_process_exit(DWORD timeout_ms) {
    if (!h_process_) {
        return true;
    }
    return WaitForSingleObject(h_process_, timeout_ms) == WAIT_OBJECT_0;
}

// ============================================================================
// Communication
// ============================================================================

bool GhidraDecompiler::send_command(const std::string& xml_cmd) {
    if (!h_stdin_write_) {
        return false;
    }
    
    DWORD written = 0;
    DWORD to_write = static_cast<DWORD>(xml_cmd.size());
    
    BOOL result = WriteFile(h_stdin_write_, xml_cmd.c_str(), to_write, &written, nullptr);
    
    if (!result || written != to_write) {
        return false;
    }
    
    // Flush to ensure data is sent
    FlushFileBuffers(h_stdin_write_);
    
    return true;
}

std::string GhidraDecompiler::recv_response() {
    if (!h_stdout_read_) {
        return "";
    }
    
    std::string response;
    char buffer[4096];
    DWORD bytes_read = 0;
    
    // Read until we get </function> or timeout
    auto start_time = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::seconds(30);  // 30 second timeout
    
    while (true) {
        bytes_read = 0;
        BOOL result = ReadFile(h_stdout_read_, buffer, sizeof(buffer) - 1, &bytes_read, nullptr);
        
        if (!result) {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE) {
                break;
            }
            if (error == ERROR_NO_DATA || error == ERROR_PIPE_NOT_CONNECTED) {
                // No data available, check timeout
                auto elapsed = std::chrono::steady_clock::now() - start_time;
                if (elapsed > timeout) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            break;
        }
        
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            response.append(buffer, bytes_read);
            
            // Check if we have complete response
            if (response.find("</function>") != std::string::npos) {
                break;
            }
            if (response.find("</error>") != std::string::npos) {
                break;
            }
            
            // Reset timeout on progress
            start_time = std::chrono::steady_clock::now();
        } else {
            // No data, check timeout
            auto elapsed = std::chrono::steady_clock::now() - start_time;
            if (elapsed > timeout) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    return response;
}

// ============================================================================
// Decompilation
// ============================================================================

DecompileResult GhidraDecompiler::decompile(
    const std::string& binary_path,
    uint64_t func_addr,
    size_t /*func_size*/) {
    
    DecompileResult result;
    result.success = false;
    
    // Check cache first
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = cache_.find(func_addr);
        if (it != cache_.end()) {
            result.success = true;
            result.pseudocode = it->second;
            return result;
        }
    }
    
    if (!is_running()) {
        result.error = "Decompiler not running";
        return result;
    }
    
    // Build and send XML command
    std::string xml_cmd = build_decompile_xml(binary_path, func_addr);
    
    if (!send_command(xml_cmd)) {
        result.error = "Failed to send command to decompiler";
        return result;
    }
    
    // Receive response
    std::string response = recv_response();
    
    if (response.empty()) {
        result.error = "No response from decompiler (timeout)";
        return result;
    }
    
    // Extract C code from response
    result.pseudocode = extract_c_code(response);
    
    if (result.pseudocode.empty()) {
        result.error = "Failed to extract pseudocode from response";
        return result;
    }
    
    // Decode XML entities
    result.pseudocode = decode_xml_entities(result.pseudocode);
    result.success = true;
    
    // Cache result
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        cache_[func_addr] = result.pseudocode;
    }
    
    return result;
}

// ============================================================================
// Cache Management
// ============================================================================

void GhidraDecompiler::clear_cache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_.clear();
}

bool GhidraDecompiler::has_cached(uint64_t func_addr) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return cache_.find(func_addr) != cache_.end();
}

std::optional<std::string> GhidraDecompiler::get_cached(uint64_t func_addr) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = cache_.find(func_addr);
    if (it != cache_.end()) {
        return it->second;
    }
    return std::nullopt;
}

// ============================================================================
// XML Helpers
// ============================================================================

std::string GhidraDecompiler::build_decompile_xml(const std::string& binary_path, uint64_t addr) {
    std::ostringstream oss;
    oss << "<command name=\"decompileAt\">\n";
    oss << "  <file>" << binary_path << "</file>\n";
    oss << "  <address>0x" << std::hex << std::uppercase << addr << "</address>\n";
    oss << "</command>\n";
    return oss.str();
}

std::string GhidraDecompiler::extract_c_code(const std::string& xml_response) {
    // Find <c> tag content
    size_t start = xml_response.find("<c>");
    if (start == std::string::npos) {
        // Try <code> tag as alternative
        start = xml_response.find("<code>");
        if (start == std::string::npos) {
            return "";
        }
        start += 6;  // strlen("<code>")
    } else {
        start += 3;  // strlen("<c>")
    }
    
    size_t end = xml_response.find("</c>", start);
    if (end == std::string::npos) {
        end = xml_response.find("</code>", start);
        if (end == std::string::npos) {
            return "";
        }
    }
    
    return xml_response.substr(start, end - start);
}

std::string GhidraDecompiler::decode_xml_entities(const std::string& text) {
    std::string result;
    result.reserve(text.size());
    
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '&' && i + 1 < text.size()) {
            if (text.compare(i, 4, "&lt;") == 0) {
                result += '<';
                i += 3;
            } else if (text.compare(i, 4, "&gt;") == 0) {
                result += '>';
                i += 3;
            } else if (text.compare(i, 5, "&amp;") == 0) {
                result += '&';
                i += 4;
            } else if (text.compare(i, 6, "&quot;") == 0) {
                result += '"';
                i += 5;
            } else if (text.compare(i, 6, "&apos;") == 0) {
                result += '\'';
                i += 5;
            } else {
                result += text[i];
            }
        } else {
            result += text[i];
        }
    }
    
    return result;
}

} // namespace atlus
