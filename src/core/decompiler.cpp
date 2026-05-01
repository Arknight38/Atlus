#include "core/decompiler.h"
#include "../ui/gui_state.h"

#include <sstream>
#include <algorithm>
#include <array>
#include <memory>
#include <cstdio>
#include <filesystem>


namespace atlus {

// Global instance
RetDecDecompiler g_decompiler;
std::future<DecompileResult> g_decompile_future;
std::atomic<bool> g_decompile_pending{false};
std::atomic<uint64_t> g_decompile_target_addr{0};

// ============================================================================
// Helper: Execute subprocess and capture output
// ============================================================================

static std::pair<std::string, int> exec_subprocess(const std::string& cmd) {
#ifdef _WIN32
    std::array<char, 4096> buffer;
    std::string result;
    
    // Use _popen for Windows
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) {
        return {"", -1};
    }
    
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        result += buffer.data();
    }
    
    int exit_code = _pclose(pipe);
    return {result, exit_code};
#else
    std::array<char, 4096> buffer;
    std::string result;
    
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return {"", -1};
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    
    int exit_code = pclose(pipe);
    return {result, exit_code};
#endif
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

RetDecDecompiler::RetDecDecompiler() {
#ifdef _WIN32
    retdec_path_ = (std::filesystem::current_path() / "third_party" / "RetDec" / "retdec-decompiler.exe").string();
    if (!std::filesystem::exists(retdec_path_)) {
        retdec_path_ = "retdec-decompiler.exe";
    }
#else
    retdec_path_ = (std::filesystem::current_path() / "third_party" / "RetDec" / "retdec-decompiler").string();
    if (!std::filesystem::exists(retdec_path_)) {
        retdec_path_ = "retdec-decompiler";
    }
#endif
}

RetDecDecompiler::~RetDecDecompiler() {
    stop();
}

// ============================================================================
// Binary Management
// ============================================================================

bool RetDecDecompiler::start(const std::string& binary_path) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    if (running_ && loaded_binary_path_ == binary_path) {
        return true;  // Already loaded this binary
    }
    
    // If already running with different binary, close it first
    if (running_) {
        close_binary();
    }
    
    return load_binary(binary_path);
}

void RetDecDecompiler::stop() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    close_binary();
    cache_.clear();
}

bool RetDecDecompiler::is_running() const {
    return running_;
}

bool RetDecDecompiler::load_binary(const std::string& binary_path) {
    if (!std::filesystem::exists(binary_path)) {
        return false;
    }
    
    loaded_binary_path_ = binary_path;
    running_ = true;
    return true;
}

void RetDecDecompiler::close_binary() {
    loaded_binary_path_.clear();
    running_ = false;
}

// ============================================================================
// Decompilation
// ============================================================================

DecompileResult RetDecDecompiler::decompile(
    const std::string& binary_path,
    uint64_t func_addr,
    size_t func_size) {
    
    DecompileResult result;
    result.success = false;
    
    // Ensure we're loaded
    if (!running_ || loaded_binary_path_ != binary_path) {
        if (!start(binary_path)) {
            result.error = "Failed to load binary: " + binary_path;
            return result;
        }
    }
    
    // Check cache
    if (auto cached = get_cached(func_addr)) {
        result.success = true;
        result.pseudocode = *cached;
        return result;
    }
    
    // Run RetDec
    result = run_retdec(func_addr, func_size);
    
    // Cache successful results
    if (result.success) {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        cache_[func_addr] = result.pseudocode;
    }
    
    return result;
}

DecompileResult RetDecDecompiler::run_retdec(uint64_t addr, size_t size) {
    DecompileResult result;
    result.success = false;
    
    // Check if RetDec exists
    if (!std::filesystem::exists(retdec_path_)) {
        result.error = "RetDec not found at: " + retdec_path_;
        return result;
    }
    
    // Build command - decompile entire file then extract function
    // RetDec supports function-specific decompilation via --select-ranges
    std::ostringstream cmd;
    cmd << "\"" << retdec_path_ << "\"";
    cmd << " \"" << loaded_binary_path_ << "\"";
    cmd << " -o -";  // Output to stdout
    cmd << " --output-format c";
    cmd << " --select-ranges 0x" << std::hex << addr << "-0x" << (addr + size) << std::dec;
    cmd << " --cleanup";
    // Note: 2>&1 doesn't work with _popen, we only capture stdout
    
    std::string cmd_str = cmd.str();
    Log("[info]  Running RetDec: %s", cmd_str.c_str());
    
    auto [output, exit_code] = exec_subprocess(cmd_str);
    
    if (exit_code != 0) {
        result.error = "RetDec failed (exit code: " + std::to_string(exit_code) + ")";
        result.error += "\nCommand: " + cmd_str;
        if (!output.empty()) {
            result.error += "\nOutput: " + output;
        } else {
            result.error += "\n(No output captured)";
        }
        return result;
    }
    
    // Extract function from output
    std::string pseudocode = extract_function_from_output(output, addr);
    
    if (pseudocode.empty()) {
        result.error = "RetDec produced no output for function at 0x" + std::to_string(addr);
        return result;
    }
    
    result.success = true;
    result.pseudocode = pseudocode;
    return result;
}

std::string RetDecDecompiler::extract_function_from_output(const std::string& output, uint64_t addr) {
    // RetDec outputs full C file - return the whole output for now
    // Future: Parse and extract specific function
    (void)addr;
    return output;
}

// ============================================================================
// Cache Management
// ============================================================================

void RetDecDecompiler::clear_cache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_.clear();
}

bool RetDecDecompiler::has_cached(uint64_t func_addr) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return cache_.find(func_addr) != cache_.end();
}

std::optional<std::string> RetDecDecompiler::get_cached(uint64_t func_addr) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = cache_.find(func_addr);
    if (it != cache_.end()) {
        return it->second;
    }
    return std::nullopt;
}

// ============================================================================
// Function List
// ============================================================================

std::vector<std::pair<uint64_t, std::string>> RetDecDecompiler::get_functions() {
    // Return empty - function list comes from binary analysis, not decompiler
    return {};
}

// ============================================================================
// Configuration
// ============================================================================

void RetDecDecompiler::set_retdec_path(const std::string& path) {
    retdec_path_ = path;
}

std::string RetDecDecompiler::get_retdec_path() const {
    return retdec_path_;
}

} // namespace atlus
