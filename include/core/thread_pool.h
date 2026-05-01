#pragma once
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <future>
#include <atomic>

namespace atlus {

// ── Thread Pool for Parallel Analysis ───────────────────────────────────────

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads = 0);
    ~ThreadPool();

    // Disable copy/move
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    // Submit a task to the pool
    template<typename F, typename... Args>
    auto enqueue(F&& f, Args&&... args) -> std::future<decltype(f(args...))> {
        using return_type = decltype(f(args...));

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );

        std::future<return_type> result = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (stop_) {
                throw std::runtime_error("Cannot enqueue on stopped ThreadPool");
            }
            tasks_.emplace([task]() { (*task)(); });
        }
        condition_.notify_one();
        return result;
    }

    // Parallel for - execute work over a range in parallel
    // Range is divided into chunks and processed by worker threads
    template<typename Index, typename Func>
    void parallel_for(Index start, Index end, Func&& func, size_t min_chunk_size = 256) {
        const Index total = end - start;
        if (total == 0) return;

        const size_t num_threads = threads_.size();
        const Index chunk_size = std::max(static_cast<Index>(min_chunk_size),
                                          static_cast<Index>((total + num_threads - 1) / num_threads));

        std::vector<std::future<void>> futures;
        futures.reserve(num_threads);

        for (Index i = start; i < end; i += chunk_size) {
            Index chunk_end = std::min(i + chunk_size, end);
            futures.push_back(enqueue([func, i, chunk_end]() {
                for (Index j = i; j < chunk_end; ++j) {
                    func(j);
                }
            }));
        }

        // Wait for all chunks
        for (auto& f : futures) {
            f.wait();
        }
    }

    // Get number of worker threads
    size_t size() const { return threads_.size(); }

    // Check if running
    bool running() const { return !stop_; }

private:
    std::vector<std::thread> threads_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::atomic<bool> stop_;
};

// ── Progress Reporting for Async Analysis ────────────────────────────────────

class AnalysisProgress {
public:
    struct State {
        std::string stage;           // Current stage name
        uint64_t current = 0;        // Items processed
        uint64_t total = 0;          // Total items
        bool completed = false;
        bool cancelled = false;
        double elapsed_seconds = 0.0;
    };

    void start(const std::string& stage, uint64_t total_items);
    void update(uint64_t processed);
    void increment(uint64_t delta = 1);
    void complete();
    void cancel();

    State get_state() const;
    double percent() const;
    bool is_active() const;

private:
    mutable std::mutex mutex_;
    State state_;
    std::chrono::steady_clock::time_point start_time_;
};

// ── Parallel Algorithms ─────────────────────────────────────────────────────

namespace parallel {

// Parallel map - apply function to each element
// Returns vector of results in same order as input
template<typename T, typename Func>
auto map(const std::vector<T>& input, Func&& func, ThreadPool& pool) -> std::vector<decltype(func(input[0]))> {
    using ResultType = decltype(func(input[0]));
    std::vector<ResultType> results(input.size());

    pool.parallel_for(size_t(0), input.size(), [&](size_t i) {
        results[i] = func(input[i]);
    }, 64);

    return results;
}

// Parallel filter - keep elements matching predicate
template<typename T, typename Pred>
std::vector<T> filter(const std::vector<T>& input, Pred&& pred, ThreadPool& pool) {
    std::vector<std::vector<T>> thread_results(pool.size());

    pool.parallel_for(size_t(0), input.size(), [&](size_t i) {
        if (pred(input[i])) {
            size_t thread_idx = std::hash<std::thread::id>{}(std::this_thread::get_id()) % pool.size();
            thread_results[thread_idx].push_back(input[i]);
        }
    }, 128);

    // Merge results
    std::vector<T> result;
    for (auto& tr : thread_results) {
        result.insert(result.end(), tr.begin(), tr.end());
    }
    return result;
}

} // namespace parallel

} // namespace atlus
