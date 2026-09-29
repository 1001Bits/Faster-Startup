#pragma once
#include <Windows.h>
#include "Persistence.h"
#include "VirtualView.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace startup {
struct FileApi {
    decltype(&FindFirstFileA) first = &FindFirstFileA;
    decltype(&FindNextFileA) next = &FindNextFileA;
    decltype(&FindClose) close = &FindClose;
    decltype(&FindFirstFileExA) firstEx = &FindFirstFileExA;
};
struct Options {
    bool enabled = true;
    bool largeFetch = true;
    bool virtualized = false;
    bool allowVirtualSnapshot = false;
    unsigned workers = 2;
    size_t maxBytes = 256 * 1024 * 1024;
    size_t maxDirectories = 8192;
    unsigned prefetchWindowMs = 20000;
    bool persistent = true;
    // One whole-MO2-view comparison admits replays for this long; 0 checks every replay.
    unsigned viewCheckMs = 1000;
    // After a successful save, re-validate and advance the saved journal cursor
    // this often while the game runs; 0 disables.
    unsigned checkpointMinutes = 10;
    std::shared_ptr<ProgressState> progress;
};
struct Statistics {
    uint64_t hits{}, misses{}, prefetched{}, nativeEntries{}, replayedEntries{};
    uint64_t invalidations{}, abandoned{}, nativeMicroseconds{}, prefetchMicroseconds{};
    uint64_t memoryBytes{}, cachedDirectories{}, learnedDirectories{};
    uint64_t persistentHits{};
    bool active{};
    size_t liveReplayHandles{};
    uint64_t viewChecks{}, viewMicroseconds{}, viewDumps{}, viewGuardBytes{};
    uint64_t polls{}, pollMicroseconds{}, initMicroseconds{}, checkpoints{};
    uint64_t infoServed{}, infoAbsent{}, infoMisses{};
    // Why single-file queries went to the engine; infoMisses sums the first four.
    uint64_t infoUnknown[6]{};
    // Paths of the 1st, 2nd, 4th, 8th, ... query of each kind, prefixed with the kind.
    std::vector<std::string> infoSamples;
    PersistenceMetrics persistence;
};
enum class FileInfoResult { unknown, found, absent };
enum class InfoUnknown { directory, nonAscii, capturing, unlisted, outside, unavailable };
inline const char* infoUnknownName(size_t kind) noexcept {
    static const char* names[] = {"directory", "non_ascii", "capturing", "unlisted", "outside", "unavailable"};
    return kind < std::size(names) ? names[kind] : "?";
}

// Only complete enumerations are published. Cross-launch results are admitted
// only after the source identity index passes NTFS journal validation.
class DirectoryCache {
public:
    DirectoryCache(std::string dataRoot, FileApi api, Options options);
    ~DirectoryCache(); // Test/tool lifetime only. The plugin owns this until process exit.
    DirectoryCache(const DirectoryCache&) = delete;
    DirectoryCache& operator=(const DirectoryCache&) = delete;
    HANDLE first(LPCSTR pattern, LPWIN32_FIND_DATAA result) noexcept;
    BOOL next(HANDLE handle, LPWIN32_FIND_DATAA result) noexcept;
    BOOL close(HANDLE handle) noexcept;
    // Metadata of one file from a validated listing: a published complete one
    // (found or absent) or one still being captured (found only). Directories,
    // runtime roots and unvalidated states return unknown.
    FileInfoResult fileInfo(const char* path, WIN32_FIND_DATAA& data) noexcept;
    void startPrefetch(const std::filesystem::path& plan);
    // Validation I/O runs without the cache lock; searches made meanwhile use
    // native results and are not captured. Results publish atomically at the end.
    bool initializePersistence(const std::filesystem::path& stateDirectory,
        const std::filesystem::path& preparedProof = {},
        const std::string& instance = "mod_organizer_instance") noexcept;
    void finishAndSave(std::function<void(bool)> completion = {}) noexcept;
    void waitForSave(); // Tools/tests only; game thread never waits for disk writes.
    std::string persistenceStatus() const;
    std::filesystem::path scopedPlanPath() const;
    void finish() noexcept;
    void savePlan(const std::filesystem::path& path) noexcept;
    void invalidate() noexcept;
    Statistics statistics() const;
    bool cacheAvailable() const noexcept { return cacheAvailable_.load(); }
    bool active() const noexcept { return active_.load(); }
    bool watcherAvailable() const noexcept { return watcher_ != INVALID_HANDLE_VALUE; }
    std::optional<std::string> normalize(const char* pattern) const;
    void waitForPrefetch(); // Used by the benchmark/tests, never the game thread.

private:
    struct Budget { std::atomic<size_t> bytes{0}; size_t limit{}; };
    struct Snapshot {
        explicit Snapshot(std::shared_ptr<Budget> b) : budget(std::move(b)) {}
        ~Snapshot();
        bool append(const WIN32_FIND_DATAA& data);
        void compact() noexcept; // Release growth slack before publishing.
        std::shared_ptr<Budget> budget;
        std::vector<WIN32_FIND_DATAA> entries;
        size_t charged{};
        bool persisted{};
        // Lower-case long and short names -> entry, built on first lookup under mutex_.
        mutable std::unordered_map<std::string, uint32_t> names;
        mutable bool asciiNames{}; // All long names ASCII: absence is exact under ASCII case folding.
    };
    struct Capture {
        std::string key;
        uint64_t generation{};
        std::shared_ptr<Snapshot> snapshot;
        bool complete{};
    };
    static std::string directoryKey(const std::string& pattern);
    void publishLocked(const std::string& key, std::shared_ptr<const Snapshot> snapshot);
    void clearCacheLocked() noexcept;
    FileInfoResult unknownInfoLocked(InfoUnknown kind, const char* path) noexcept;
    struct Cursor {
        std::shared_ptr<const Snapshot> snapshot;
        size_t position = 1;
        std::string directory;
        bool refreshParent{};
    };
    static bool replayData(const Cursor& cursor, size_t index, WIN32_FIND_DATAA& output) noexcept;
    void pollChangesLocked();
    void invalidateLocked();
    void releaseValidationLocked() noexcept;
    void learnLocked(const std::string& key);
    bool watchCoversLocked(const std::string& key);
    bool viewFreshLocked();
    void worker() noexcept;
    void prefetch(const std::string& key, uint64_t generation) noexcept;
    void startCheckpoints(std::unique_ptr<PersistentStore> store) noexcept;
    HANDLE nativeFirst(const char* pattern, WIN32_FIND_DATAA* result, bool eligible) noexcept;

    const FileApi api_;
    Options options_; // Mutable fields (virtualized) are guarded by mutex_.
    std::string root_;
    std::shared_ptr<Budget> budget_;
    HANDLE watcher_ = INVALID_HANDLE_VALUE;
    bool watcherFailed_{};
    std::atomic<bool> largeFetch_{false};
    std::atomic<bool> cacheAvailable_{false};
    std::atomic<bool> active_{true};
    std::atomic<size_t> replayHandles_{0};
    mutable std::mutex mutex_;
    std::condition_variable workAvailable_, idle_;
    uint64_t generation_ = 0;
    std::unordered_map<std::string, std::shared_ptr<const Snapshot>> cache_;
    // Lower-case directory path -> published listing, for single-file lookups.
    std::unordered_map<std::string, std::shared_ptr<const Snapshot>> directories_;
    std::unordered_map<HANDLE, Capture> captures_;
    std::unordered_map<HANDLE, Cursor> cursors_;
    std::unordered_set<std::string> learnedSet_;
    std::unordered_set<std::string> coveredDirectories_;
    std::vector<std::string> learned_;
    std::deque<std::string> work_;
    std::vector<std::thread> workers_;
    size_t working_ = 0;
    ULONGLONG deadline_ = 0;
    Statistics stats_;
    std::unique_ptr<PersistentStore> persistence_;
    std::shared_ptr<VirtualView> virtualView_;
    ULONGLONG lastViewCheck_ = 0;
    std::filesystem::path snapshotPath_;
    bool persistentGuard_{};
    bool initializing_{};
    std::string persistenceStatus_ = "Persistence not initialized";
    std::thread saver_;
    std::thread checkpointer_;
    std::condition_variable checkpointWake_;
    bool stopCheckpoints_{};
};
}
