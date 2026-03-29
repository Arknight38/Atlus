#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <future>
#include <mutex>
#include <unordered_map>
#include <optional>

namespace atlus {

// Result of a decompilation request
struct DecompileResult {
    bool success;
    std::string pseudocode;
    std::string error;
};

// Ghidra decompiler subprocess manager
// Communicates with Ghidra's decompile.exe via stdin/stdout using XML protocol
class GhidraDecompiler {
public:
    GhidraDecompiler();
    ~GhidraDecompiler();

    // Start the decompiler subprocess
    bool start(const std::string& decompiler_path);
    
    // Stop the subprocess and clean up resources
    void stop();
    
    // Check if subprocess is running
    bool is_running() const;
    
    // Decompile a function at given address
    // Returns DecompileResult with pseudocode from <c>...</c> tag
    DecompileResult decompile(
        const std::string& binary_path,
        uint64_t func_addr,
        size_t func_size
    );

    // Cache management
    void clear_cache();
    bool has_cached(uint64_t func_addr) const;
    std::optional<std::string> get_cached(uint64_t func_addr) const;

private:
    // Process handles
    HANDLE h_process_ = nullptr;
    HANDLE h_stdin_write_ = nullptr;
    HANDLE h_stdout_read_ = nullptr;
    
    // Process info
    PROCESS_INFORMATION proc_info_{};
    bool running_ = false;
    std::string decompiler_path_;
    
    // Cache for pseudocode results
    mutable std::mutex cache_mutex_;
    std::unordered_map<uint64_t, std::string> cache_;
    
    // Internal communication
    bool send_command(const std::string& xml_cmd);
    std::string recv_response();
    bool wait_for_process_exit(DWORD timeout_ms);
    
    // XML helpers
    std::string build_decompile_xml(const std::string& binary_path, uint64_t addr);
    std::string extract_c_code(const std::string& xml_response);
    std::string decode_xml_entities(const std::string& text);
};

// Global decompiler instance (optional convenience)
extern GhidraDecompiler g_decompiler;

// Future for background decompilation
extern std::future<DecompileResult> g_decompile_future;
extern std::atomic<bool> g_decompile_pending;
extern std::atomic<uint64_t> g_decompile_target_addr;

} // namespace atlus
