#pragma once
#include <Windows.h>
#include <cstdint>
#include <mutex>

namespace startup {
enum class ProgressPhase { checking, indexing, loading, capturing, saving, complete, fallback };
struct ProgressSnapshot {
    ProgressPhase phase = ProgressPhase::checking;
    uint64_t started{}, elapsedMs{}, files{}, directories{}, completed{}, total{};
    bool terminal{};
    // This launch builds the cache (first launch or after source changes). Only
    // then is progress shown; validating and using a warm cache stays silent.
    bool building{};
};

// Independent of the cache lock: the UI must keep pumping while validation
// holds that lock. Updates are per directory/buffer, never per filename.
class ProgressState {
public:
    void phase(ProgressPhase value, uint64_t total = 0) noexcept {
        std::lock_guard lock(mutex_);
        if (value_.terminal) return;
        if (!value_.started) value_.started = GetTickCount64();
        value_.phase = value; value_.completed = 0; value_.total = total;
        if (value == ProgressPhase::indexing) value_.building = true;
    }
    void markBuilding() noexcept {
        std::lock_guard lock(mutex_);
        if (!value_.terminal) value_.building = true;
    }
    void scanned(uint64_t files, uint64_t directories) noexcept {
        std::lock_guard lock(mutex_);
        if (!value_.terminal) { value_.files = files; value_.directories = directories; }
    }
    void advance(uint64_t completed) noexcept {
        std::lock_guard lock(mutex_);
        if (!value_.terminal) value_.completed = completed;
    }
    void finish(bool success) noexcept {
        std::lock_guard lock(mutex_);
        if (value_.terminal) return;
        value_.phase = success ? ProgressPhase::complete : ProgressPhase::fallback;
        value_.terminal = true;
    }
    ProgressSnapshot snapshot() const noexcept {
        std::lock_guard lock(mutex_);
        auto result = value_;
        if (result.started) result.elapsedMs = GetTickCount64() - result.started;
        return result;
    }
private:
    mutable std::mutex mutex_;
    ProgressSnapshot value_;
};
}
