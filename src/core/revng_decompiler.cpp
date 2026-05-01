#include "core/revng_decompiler.h"
#include <sstream>
#include <stdexcept>
#include <mutex>
#include <algorithm>
#include <cctype>
#include <fstream>

#ifdef _WIN32
  #include <windows.h>
#else
  #include <unistd.h>
  #include <sys/wait.h>
#endif

namespace atlus {

// ============================================================================
// Platform detection helpers
// ============================================================================

#ifdef _WIN32

// Converts C:\foo\bar.exe  ->  /mnt/c/foo/bar.exe
static std::string windows_path_to_wsl(const std::filesystem::path& path)
{
    std::string s = path.string();
    std::replace(s.begin(), s.end(), '\\', '/');

    // C:/foo → /mnt/c/foo
    if (s.size() >= 2 && std::isalpha(static_cast<unsigned char>(s[0])) && s[1] == ':') {
        std::string result = "/mnt/";
        result += static_cast<char>(std::tolower(static_cast<unsigned char>(s[0])));
        result += s.substr(2); // everything after "C:"
        return result;
    }
    return s;
}

// Docker volume mount string:  C:\Users\you  ->  C:\Users\you:/wd
static std::string windows_path_to_docker_volume(const std::filesystem::path& path)
{
    return path.string() + ":/wd";
}

static bool wsl_available()
{
    STARTUPINFOA si{ sizeof(si) };
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = INVALID_HANDLE_VALUE;
    si.hStdError  = INVALID_HANDLE_VALUE;

    PROCESS_INFORMATION pi{};
    char cmd[] = "wsl --status";
    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr,
                        FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        return false;
    }
    WaitForSingleObject(pi.hProcess, 3000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

static bool docker_available()
{
    STARTUPINFOA si{ sizeof(si) };
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = INVALID_HANDLE_VALUE;
    si.hStdError  = INVALID_HANDLE_VALUE;

    PROCESS_INFORMATION pi{};
    char cmd[] = "docker info";
    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr,
                        FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        return false;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

#else

static bool wsl_available()    { return false; }
static bool docker_available() { return false; }

#endif

static std::string strip_ptml(const std::string& ptml)
{
    std::string out;
    out.reserve(ptml.size());
    bool in_tag = false;

    for (size_t i = 0; i < ptml.size(); ++i) {
        if (ptml[i] == '<') {
            in_tag = true;
        } else if (ptml[i] == '>') {
            in_tag = false;
        } else if (!in_tag) {
            // Decode common HTML entities
            if (ptml[i] == '&') {
                if (ptml.substr(i, 4) == "&lt;")  { out += '<'; i += 3; }
                else if (ptml.substr(i, 4) == "&gt;")  { out += '>'; i += 3; }
                else if (ptml.substr(i, 5) == "&amp;") { out += '&'; i += 4; }
                else if (ptml.substr(i, 6) == "&quot;") { out += '"'; i += 5; }
                else out += ptml[i];
            } else {
                out += ptml[i];
            }
        }
    }
    return out;
}

static std::string clean_pseudocode(std::string c)
{
    static const std::pair<std::string, std::string> replacements[] = {
        { "revng_undefined_local_sp()", "sp"       },
        { "pointer_or_number64_t",      "uint64_t" },
        { "generic64_t",                "uint64_t" },
        { "generic32_t",                "uint32_t" },
        { "generic16_t",                "uint16_t" },
        { "generic8_t",                 "uint8_t"  },
        { "number64_t",                 "int64_t"  },
        { "number32_t",                 "int32_t"  },
        { "number8_t",                  "int8_t"   },
    };

    for (const auto& [from, to] : replacements) {
        size_t pos = 0;
        while ((pos = c.find(from, pos)) != std::string::npos) {
            c.replace(pos, from.size(), to);
            pos += to.size();
        }
    }
    return c;
}

static std::filesystem::path find_revng_binary()
{
    auto local = std::filesystem::path("third_party/revng/revng");
    if (std::filesystem::exists(local)) return local;

    // Fallback to PATH
    return "revng";
}

// ============================================================================
// Factory
// ============================================================================

std::unique_ptr<RevngDecompiler> RevngDecompiler::create()
{
#ifdef _WIN32
    if (wsl_available())
        return std::unique_ptr<RevngDecompiler>(new RevngDecompiler(RevngBackend::WSL, {}));
    else if (docker_available())
        return std::unique_ptr<RevngDecompiler>(new RevngDecompiler(RevngBackend::Docker, {}));
    else
        throw std::runtime_error(
            "rev.ng requires WSL2 or Docker on Windows. "
            "Install one and re-run setup.ps1.");
#else
    auto path = find_revng_binary();
    return std::unique_ptr<RevngDecompiler>(new RevngDecompiler(RevngBackend::Native, std::move(path)));
#endif
}

// ============================================================================
// Construction
// ============================================================================

RevngDecompiler::RevngDecompiler(RevngBackend backend, std::filesystem::path revng_path)
    : m_backend(backend), m_revng_path(std::move(revng_path)) {}

RevngDecompiler::~RevngDecompiler() = default;

// ============================================================================
// Path translation & argument building
// ============================================================================

std::string RevngDecompiler::resolve_path(const std::filesystem::path& path) const
{
#ifdef _WIN32
    if (m_backend == RevngBackend::WSL)
        return windows_path_to_wsl(path);
    if (m_backend == RevngBackend::Docker) {
        // Volume mounts parent to /wd; return /wd/<filename>
        return std::string("/wd/") + path.filename().string();
    }
#endif
    return path.string();
}

std::vector<std::string> RevngDecompiler::build_args(
    const std::vector<std::string>& revng_args,
    const std::filesystem::path& binary) const
{
    std::vector<std::string> out;

    switch (m_backend) {
        case RevngBackend::Native:
            out.push_back(m_revng_path.string());
            break;

        case RevngBackend::WSL: {
            std::string cmd = "source ~/revng/environment && revng";
            for (const auto& a : revng_args)
                cmd += " " + a;
            return { "wsl", "bash", "-c", cmd };
        }

        case RevngBackend::Docker: {
            out.push_back("docker");
            out.push_back("run");
            out.push_back("--rm");
            auto parent = binary.empty() ? std::filesystem::current_path() : binary.parent_path();
            out.push_back("-v");
            out.push_back(windows_path_to_docker_volume(parent));
            out.push_back("revng/revng");
            break;
        }
    }

    out.insert(out.end(), revng_args.begin(), revng_args.end());
    return out;
}

// ============================================================================
// Cross-platform process runner — captures stdout, returns it as string.
// ============================================================================

void RevngDecompiler::set_output_callback(std::function<void(const std::string&)> cb)
{
    m_output_cb = std::move(cb);
}

std::string RevngDecompiler::run_process(
    const std::vector<std::string>& args,
    const std::function<void(const std::string&)>& on_output)
{
    if (args.empty()) throw std::invalid_argument("No arguments");

    // Helper: split accumulated bytes into complete lines and dispatch each one.
    auto dispatch_lines = [&on_output](std::string& line_buf, const char* data, size_t len) {
        if (!on_output) return;
        line_buf.append(data, len);
        size_t start = 0, pos;
        while ((pos = line_buf.find('\n', start)) != std::string::npos) {
            std::string line = line_buf.substr(start, pos - start);
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (!line.empty())
                on_output(line);
            start = pos + 1;
        }
        line_buf.erase(0, start);
    };

#ifdef _WIN32
    std::string cmd;
    for (const auto& a : args) {
        if (!cmd.empty()) cmd += ' ';
        cmd += '"' + a + '"';
    }

    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        throw std::runtime_error("CreatePipe failed");

    STARTUPINFOA si{};
    si.cb         = sizeof(si);
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.dwFlags    = STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr,
                        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite);
        throw std::runtime_error("CreateProcess failed: " + cmd);
    }
    CloseHandle(hWrite);

    std::string output;
    std::string line_buf;
    char buf[4096];
    DWORD bytes_read;
    while (ReadFile(hRead, buf, sizeof(buf), &bytes_read, nullptr) && bytes_read > 0) {
        output.append(buf, bytes_read);
        dispatch_lines(line_buf, buf, bytes_read);
    }
    if (on_output && !line_buf.empty())
        on_output(line_buf);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (exit_code != 0)
        throw std::runtime_error("Command failed (exit " + std::to_string(exit_code) + "): " + cmd + "\nOutput: " + output);
    return output;

#else
    int pipefd[2];
    if (pipe(pipefd) < 0)
        throw std::runtime_error("pipe() failed");

    pid_t pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        std::vector<char*> argv;
        for (const auto& a : args)
            argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);

        execvp(argv[0], argv.data());
        _exit(127);
    }

    close(pipefd[1]);
    std::string output;
    std::string line_buf;
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        output.append(buf, static_cast<size_t>(n));
        dispatch_lines(line_buf, buf, static_cast<size_t>(n));
    }
    if (on_output && !line_buf.empty())
        on_output(line_buf);
    close(pipefd[0]);
    waitpid(pid, nullptr, 0);
    return output;
#endif
}

// ============================================================================
// Lift
// ============================================================================

void RevngDecompiler::lift_async(
    const std::filesystem::path& binary,
    std::function<void(bool, std::string)> on_complete)
{
    clear_cache();
    m_binary = binary;
    m_state  = DecompilerState::Lifting;
    m_error.clear();
    uint64_t gen = ++m_lift_generation;

    m_resume_path = binary.parent_path() /
        (binary.stem().string() + ".revng");

    if (m_backend == RevngBackend::WSL) {
        m_wsl_resume_dir = "~/atlus-work/" + binary.stem().string();
    }

    m_lift_future = std::async(std::launch::async,
        [this, binary, gen, cb = std::move(on_complete)]()
    {
        try {
            auto bin_str = resolve_path(binary);
            std::string resume_str;

            if (m_backend == RevngBackend::WSL) {
                resume_str = m_wsl_resume_dir;
                run_process({ "wsl", "bash", "-c", "mkdir -p " + resume_str });
            } else {
                resume_str = resolve_path(m_resume_path);
                std::filesystem::create_directories(m_resume_path);
            }

            // Step 1: import-binary
            m_state = DecompilerState::ImportingBinary;
            report_progress(AnalysisStage::ImportBinary, "Importing binary...");
            run_process(build_args({
                "analyze",
                "--resume", resume_str,
                "import-binary",
                bin_str
            }, binary), m_output_cb);

            // Step 2: detect-abi
            m_state = DecompilerState::DetectingABI;
            report_progress(AnalysisStage::DetectABI, "Detecting ABI and calling conventions...");
            run_process(build_args({
                "analyze",
                "--resume", resume_str,
                "detect-abi",
                bin_str
            }, binary), m_output_cb);

            if (m_lift_generation.load() == gen) {
                m_state = DecompilerState::Ready;
                report_progress(AnalysisStage::Done, "Analysis complete");
                flush_pending_queue();
                cb(true, {});
            }
        } catch (const std::exception& e) {
            if (m_lift_generation.load() == gen) {
                m_state = DecompilerState::Error;
                m_error = e.what();
                report_progress(AnalysisStage::None, std::string("Error: ") + e.what());
                cb(false, e.what());
            }
        }
    });
}

// ============================================================================
// Decompile
// ============================================================================

DecompileResult RevngDecompiler::decompile(uint64_t rva)
{
    if (m_state.load() != DecompilerState::Ready)
        return { false, {}, "Decompiler not ready" };

    {
        std::lock_guard<std::mutex> lock(m_cache_mutex);
        if (auto it = m_cache.find(rva); it != m_cache.end())
            return { true, it->second, {} };
    }

    std::ostringstream addr;
    addr << "0x" << std::hex << rva;

    try {
        auto bin_str = resolve_path(m_binary);
        auto target  = addr.str() + ":Code_x86_64";

        std::string resume_str;
        std::string out_path;
        if (m_backend == RevngBackend::WSL) {
            resume_str = m_wsl_resume_dir;
            out_path   = resume_str + "/decompiled.c";
        } else {
            resume_str = resolve_path(m_resume_path);
            out_path   = resume_str + "/decompiled.c";
        }

        // decompile-to-single-file writes the whole binary's C to -o
        run_process(build_args({
            "artifact",
            "--resume", resume_str,
            "decompile-to-single-file",
            bin_str,
            "-o", out_path
        }, m_binary));

        std::string raw;
        if (m_backend == RevngBackend::WSL) {
            raw = run_process({ "wsl", "bash", "-c", "cat " + out_path });
        } else if (m_backend == RevngBackend::Docker) {
            raw = run_process(build_args({
                "artifact",
                "--resume", resume_str,
                "decompile-to-single-file",
                bin_str
            }, m_binary));
        } else {
            std::ifstream ifs(out_path);
            raw.assign(std::istreambuf_iterator<char>(ifs),
                       std::istreambuf_iterator<char>());
        }

        if (raw.empty())
            return { false, {}, "revng produced no output for " + addr.str() };

        auto stripped = clean_pseudocode(strip_ptml(raw));

        // Extract just the function block containing the requested address.
        // revng annotates each function with a comment like:
        //   /* 0x404000:Code_x86_64 */
        // Search for that marker and extract from there to the next top-level '}'.
        std::string marker = "/* " + target + " */";
        std::string output;
        auto pos = stripped.find(marker);
        if (pos != std::string::npos) {
            // Walk back to the start of the line
            auto start = stripped.rfind('\n', pos);
            start = (start == std::string::npos) ? 0 : start + 1;
            // Find the closing brace of this function (top-level '}')
            int depth = 0;
            bool in_func = false;
            size_t end = start;
            for (size_t i = start; i < stripped.size(); ++i) {
                if (stripped[i] == '{') { depth++; in_func = true; }
                else if (stripped[i] == '}') {
                    if (--depth == 0 && in_func) { end = i + 1; break; }
                }
            }
            output = stripped.substr(start, end - start);
        } else {
            // Marker not found — return whole file so the user sees something
            output = std::move(stripped);
        }

        {
            std::lock_guard<std::mutex> lock(m_cache_mutex);
            m_cache[rva] = output;
        }
        return { true, std::move(output), {} };

    } catch (const std::exception& e) {
        return { false, {}, e.what() };
    }
}

void RevngDecompiler::cleanup_futures()
{
    std::lock_guard<std::mutex> lock(m_futures_mutex);
    m_decompile_futures.erase(
        std::remove_if(m_decompile_futures.begin(), m_decompile_futures.end(),
            [](const auto& f) {
                return f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
            }),
        m_decompile_futures.end());
}

void RevngDecompiler::launch_decompile_async(
    uint64_t rva,
    std::function<void(DecompileResult)> callback)
{
    std::lock_guard<std::mutex> lock(m_futures_mutex);
    m_decompile_futures.push_back(
        std::async(std::launch::async, [this, rva, cb = std::move(callback)]() {
            cb(decompile(rva));
        }));
}

void RevngDecompiler::decompile_async(
    uint64_t rva,
    std::function<void(DecompileResult)> callback)
{
    cleanup_futures();

    if (m_state.load() == DecompilerState::Lifting) {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_pending_queue.push_back({ rva, std::move(callback) });
        return;
    }

    if (m_state.load() != DecompilerState::Ready) {
        callback({ false, {}, "Decompiler not ready" });
        return;
    }

    launch_decompile_async(rva, std::move(callback));
}

void RevngDecompiler::flush_pending_queue()
{
    std::vector<PendingRequest> pending;
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        pending = std::move(m_pending_queue);
        m_pending_queue.clear();
    }
    for (auto& req : pending)
        launch_decompile_async(req.rva, std::move(req.callback));
}

void RevngDecompiler::clear_cache()
{
    {
        std::lock_guard<std::mutex> lock(m_cache_mutex);
        m_cache.clear();
        m_state.store(DecompilerState::Idle);
    }
    {
        std::lock_guard<std::mutex> flock(m_futures_mutex);
        m_decompile_futures.clear();
    }
    if (!m_resume_path.empty() && std::filesystem::exists(m_resume_path)) {
        std::error_code ec;
        std::filesystem::remove_all(m_resume_path, ec);
    }
    m_resume_path.clear();
    m_wsl_resume_dir.clear();
}

// ============================================================================
// Progress callbacks
// ============================================================================

void RevngDecompiler::set_progress_callback(std::function<void(AnalysisStage, const std::string&)> cb)
{
    m_progress_cb = std::move(cb);
}

void RevngDecompiler::report_progress(AnalysisStage stage, const std::string& message)
{
    if (m_progress_cb) {
        m_progress_cb(stage, message);
    }
}

// ============================================================================
// CFG Generation (emit-cfg)
// ============================================================================

CFGResult RevngDecompiler::emit_cfg(uint64_t rva)
{
    if (m_state.load() != DecompilerState::Ready)
        return { false, {}, "Decompiler not ready" };

    std::ostringstream addr;
    addr << "0x" << std::hex << rva;

    try {
        auto bin_str = resolve_path(m_binary);
        auto target  = addr.str() + ":Code_x86_64";

        std::string resume_str;
        std::string out_path;
        if (m_backend == RevngBackend::WSL) {
            resume_str = m_wsl_resume_dir;
            out_path   = resume_str + "/cfg_" + addr.str() + ".yaml";
        } else {
            resume_str = resolve_path(m_resume_path);
            out_path   = resume_str + "/cfg_" + addr.str() + ".yaml";
        }

        // Run emit-cfg command
        run_process(build_args({
            "artifact",
            "--resume", resume_str,
            "emit-cfg",
            target,
            "-o", out_path
        }, m_binary));

        // Read the generated YAML
        std::string raw;
        if (m_backend == RevngBackend::WSL) {
            raw = run_process({ "wsl", "bash", "-c", "cat " + out_path });
        } else if (m_backend == RevngBackend::Docker) {
            raw = run_process(build_args({
                "artifact",
                "--resume", resume_str,
                "emit-cfg",
                target
            }, m_binary));
        } else {
            std::ifstream ifs(out_path);
            raw.assign(std::istreambuf_iterator<char>(ifs),
                       std::istreambuf_iterator<char>());
        }

        if (raw.empty())
            return { false, {}, "revng emit-cfg produced no output for " + addr.str() };

        return { true, std::move(raw), {} };

    } catch (const std::exception& e) {
        return { false, {}, e.what() };
    }
}

void RevngDecompiler::emit_cfg_async(uint64_t rva, std::function<void(CFGResult)> callback)
{
    cleanup_futures();

    if (m_state.load() == DecompilerState::Lifting) {
        // Queue for later
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        // Note: We need a way to distinguish CFG requests from decompile requests
        // For simplicity, we defer this until lift is complete
        // and the caller should check state before calling
        callback({ false, {}, "Decompiler still lifting, try again later" });
        return;
    }

    if (m_state.load() != DecompilerState::Ready) {
        callback({ false, {}, "Decompiler not ready" });
        return;
    }

    m_state = DecompilerState::EmittingCFG;
    report_progress(AnalysisStage::EmitCFG, "Generating CFG for 0x" + std::to_string(rva));

    std::lock_guard<std::mutex> lock(m_futures_mutex);
    m_decompile_futures.push_back(
        std::async(std::launch::async, [this, rva, cb = std::move(callback)]() {
            auto result = emit_cfg(rva);
            m_state = DecompilerState::Ready;
            report_progress(AnalysisStage::Done, "CFG generation complete");
            cb(result);
        }));
}

// ============================================================================
// Call Graph Rendering (render-svg-call-graph)
// ============================================================================

CallGraphResult RevngDecompiler::render_call_graph()
{
    if (m_state.load() != DecompilerState::Ready)
        return { false, {}, "Decompiler not ready" };

    try {
        auto bin_str = resolve_path(m_binary);

        std::string resume_str;
        std::string out_path;
        if (m_backend == RevngBackend::WSL) {
            resume_str = m_wsl_resume_dir;
            out_path   = resume_str + "/callgraph.svg";
        } else {
            resume_str = resolve_path(m_resume_path);
            out_path   = resume_str + "/callgraph.svg";
        }

        // Run render-svg-call-graph command
        run_process(build_args({
            "artifact",
            "--resume", resume_str,
            "render-svg-call-graph",
            bin_str,
            "-o", out_path
        }, m_binary));

        // Read the generated SVG
        std::string raw;
        if (m_backend == RevngBackend::WSL) {
            raw = run_process({ "wsl", "bash", "-c", "cat " + out_path });
        } else if (m_backend == RevngBackend::Docker) {
            raw = run_process(build_args({
                "artifact",
                "--resume", resume_str,
                "render-svg-call-graph",
                bin_str
            }, m_binary));
        } else {
            std::ifstream ifs(out_path);
            raw.assign(std::istreambuf_iterator<char>(ifs),
                       std::istreambuf_iterator<char>());
        }

        if (raw.empty())
            return { false, {}, "revng render-svg-call-graph produced no output" };

        return { true, std::move(raw), {} };

    } catch (const std::exception& e) {
        return { false, {}, e.what() };
    }
}

void RevngDecompiler::render_call_graph_async(std::function<void(CallGraphResult)> callback)
{
    cleanup_futures();

    if (m_state.load() == DecompilerState::Lifting) {
        callback({ false, {}, "Decompiler still lifting, try again later" });
        return;
    }

    if (m_state.load() != DecompilerState::Ready) {
        callback({ false, {}, "Decompiler not ready" });
        return;
    }

    m_state = DecompilerState::RenderingCallGraph;
    report_progress(AnalysisStage::RenderCallGraph, "Rendering call graph...");

    std::lock_guard<std::mutex> lock(m_futures_mutex);
    m_decompile_futures.push_back(
        std::async(std::launch::async, [this, cb = std::move(callback)]() {
            auto result = render_call_graph();
            m_state = DecompilerState::Ready;
            report_progress(AnalysisStage::Done, "Call graph rendering complete");
            cb(result);
        }));
}

// ============================================================================
// ABI Info
// ============================================================================

ABIInfo RevngDecompiler::get_abi_info() const
{
    if (m_state.load() != DecompilerState::Ready)
        return { false, {}, "Decompiler not ready", {} };

    // The ABI info is extracted from the model after detect-abi
    // For now, return a placeholder - in a full implementation,
    // we'd parse this from the revng model
    return { true, "SystemV_x86_64", "SystemV AMD64 ABI", {} };
}

} // namespace atlus
