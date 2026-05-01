#include "core/thread_pool.h"
#include <algorithm>

namespace atlus {

// ── Thread Pool Implementation ───────────────────────────────────────────────

ThreadPool::ThreadPool(size_t num_threads)
    : stop_(false) {
    if (num_threads == 0) {
        // Use hardware concurrency, default to 2 if unknown
        num_threads = std::max(size_t(2), static_cast<size_t>(std::thread::hardware_concurrency()));
    }

    threads_.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i) {
        threads_.emplace_back([this, i]() {
            for (;;) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(queue_mutex_);
                    condition_.wait(lock, [this] {
                        return stop_ || !tasks_.empty();
                    });

                    if (stop_ && tasks_.empty()) {
                        return;
                    }

                    task = std::move(tasks_.front());
                    tasks_.pop();
                }
                task();
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        stop_ = true;
    }
    condition_.notify_all();

    for (auto& thread : threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

// ── Analysis Progress Implementation ─────────────────────────────────────────

void AnalysisProgress::start(const std::string& stage, uint64_t total_items) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.stage = stage;
    state_.current = 0;
    state_.total = total_items;
    state_.completed = false;
    state_.cancelled = false;
    start_time_ = std::chrono::steady_clock::now();
}

void AnalysisProgress::update(uint64_t processed) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.current = processed;
}

void AnalysisProgress::increment(uint64_t delta) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.current += delta;
}

void AnalysisProgress::complete() {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.completed = true;
    state_.current = state_.total;
    auto now = std::chrono::steady_clock::now();
    state_.elapsed_seconds = std::chrono::duration<double>(now - start_time_).count();
}

void AnalysisProgress::cancel() {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.cancelled = true;
}

AnalysisProgress::State AnalysisProgress::get_state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    State s = state_;
    if (!s.completed && !s.cancelled) {
        auto now = std::chrono::steady_clock::now();
        s.elapsed_seconds = std::chrono::duration<double>(now - start_time_).count();
    }
    return s;
}

double AnalysisProgress::percent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_.total == 0) return 0.0;
    return 100.0 * static_cast<double>(state_.current) / static_cast<double>(state_.total);
}

bool AnalysisProgress::is_active() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !state_.completed && !state_.cancelled;
}

} // namespace atlus
