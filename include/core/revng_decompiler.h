#pragma once
#include <string>
#include <unordered_map>
#include <future>
#include <functional>
#include <filesystem>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace atlus {

struct DecompileResult {
    bool        success = false;
    std::string c_code;
    std::string error;
};

struct CFGResult {
    bool        success = false;
    std::string yaml;     // CFG as structured YAML
    std::string error;
};

struct CallGraphResult {
    bool        success = false;
    std::string svg;      // Call graph as SVG
    std::string error;
};

struct ABIInfo {
    bool        success = false;
    std::string abi_name;
    std::string calling_convention;
    std::string error;
};

enum class DecompilerState {
    Idle,            // No binary loaded
    Lifting,         // Background lift in progress
    ImportingBinary, // Step 1: import-binary
    DetectingABI,    // Step 2: detect-abi
    EmittingCFG,     // Step 3a: emit-cfg (optional)
    RenderingCallGraph, // Step 3b: render-svg-call-graph (optional)
    Ready,           // Lifted, accepting decompile requests
    Error            // Lift failed
};

enum class AnalysisStage {
    None,
    ImportBinary,
    DetectABI,
    EmitCFG,
    RenderCallGraph,
    Decompile,
    Done
};

enum class RevngBackend {
    Native,   // Linux / macOS native binary
    WSL,      // Windows: wsl /opt/revng/revng/revng
    Docker    // Windows: docker run revng/revng (fallback)
};

class RevngDecompiler {
public:
    /// Auto-detect backend and return a heap-allocated instance.
    static std::unique_ptr<RevngDecompiler> create();
    ~RevngDecompiler();

    // Kick off async lift — returns immediately, callback fires on completion
    void lift_async(
        const std::filesystem::path& binary,
        std::function<void(bool, std::string)> on_complete);

    // Synchronous decompile (assumes binary already lifted)
    DecompileResult decompile(uint64_t rva);

    // Async decompile — queues if still lifting, fires immediately if ready
    void decompile_async(uint64_t rva, std::function<void(DecompileResult)> callback);

    void clear_cache();

    // Optional per-line output callback — called for every line of stdout/stderr
    // during lift_async. Safe to call from any thread.
    void set_output_callback(std::function<void(const std::string&)> cb);

    // Progress callback for detailed analysis stages
    void set_progress_callback(std::function<void(AnalysisStage, const std::string&)> cb);

    // ── rev.ng Advanced Features ─────────────────────────────────────────────

    // Emit Control Flow Graph as YAML (emit-cfg)
    CFGResult emit_cfg(uint64_t rva);
    void emit_cfg_async(uint64_t rva, std::function<void(CFGResult)> callback);

    // Render Call Graph as SVG (render-svg-call-graph)
    CallGraphResult render_call_graph();
    void render_call_graph_async(std::function<void(CallGraphResult)> callback);

    // Get ABI information after lift
    ABIInfo get_abi_info() const;

    DecompilerState state() const { return m_state.load(); }
    RevngBackend    backend() const { return m_backend; }
    const std::string& error() const { return m_error; }
    const std::filesystem::path& binary() const { return m_binary; }

    /// On Native: change binary path. Ignored on WSL / Docker.
    void set_path(const std::filesystem::path& p) { m_revng_path = p; }
    std::filesystem::path get_path() const { return m_revng_path; }

private:
    RevngDecompiler(RevngBackend backend, std::filesystem::path revng_path);

    std::string run_process(const std::vector<std::string>& args,
                             const std::function<void(const std::string&)>& on_output = {});
    void flush_pending_queue();
    void launch_decompile_async(uint64_t rva, std::function<void(DecompileResult)> callback);

    std::string resolve_path(const std::filesystem::path& path) const;
    std::vector<std::string> build_args(
        const std::vector<std::string>& revng_args,
        const std::filesystem::path& binary = {}) const;

    struct PendingRequest {
        uint64_t                             rva;
        std::function<void(DecompileResult)> callback;
    };

    RevngBackend                               m_backend;
    std::filesystem::path                      m_revng_path;
    std::filesystem::path                      m_binary;
    std::filesystem::path                      m_resume_path;
    std::string                                m_wsl_resume_dir;
    std::atomic<DecompilerState>               m_state = DecompilerState::Idle;
    std::string                                m_error;
    std::atomic<uint64_t>                      m_lift_generation{0};

    std::unordered_map<uint64_t, std::string>  m_cache;
    mutable std::mutex                         m_cache_mutex;

    std::mutex                                 m_queue_mutex;
    std::vector<PendingRequest>                m_pending_queue;

    std::future<void>                          m_lift_future;

    mutable std::mutex                         m_futures_mutex;
    std::vector<std::future<void>>             m_decompile_futures;

    std::function<void(const std::string&)>    m_output_cb;
    std::function<void(AnalysisStage, const std::string&)> m_progress_cb;

    void cleanup_futures();
    void report_progress(AnalysisStage stage, const std::string& message);
};

} // namespace atlus
