#include "DirectoryCache.h"
#include "NativeScope.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <stdexcept>

namespace startup {
namespace {
using Clock = std::chrono::steady_clock;
// Background view checks wait this long for a busy MO2 mapping to settle.
constexpr unsigned viewSettleMs = 10000;
uint64_t microseconds(Clock::time_point start) {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
}
char ascii_tolower(char c) noexcept { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c; }
bool asciiText(const char* text) noexcept {
    for (; *text; ++text) if (static_cast<unsigned char>(*text) >= 0x80) return false;
    return true;
}
std::string fullPath(const char* path) {
    if (!path) return {};
    char buffer[32768];
    const DWORD n = GetFullPathNameA(path, static_cast<DWORD>(sizeof(buffer)), buffer, nullptr);
    if (!n || n >= sizeof(buffer)) return {};
    std::string result(buffer, n);
    std::replace(result.begin(), result.end(), '/', '\\');
    return result;
}
// Every MO2 profile/mapping change creates another view-<context> result and
// source index, often tens of megabytes. Keep the most recently written views
// (profile switching stays warm) and remove abandoned temporary files.
void pruneState(const std::filesystem::path& directory, size_t keep) noexcept {
    namespace fs = std::filesystem;
    try {
        std::error_code error;
        const auto now = fs::file_time_type::clock::now();
        std::map<std::string, fs::file_time_type> newest;
        std::vector<std::pair<fs::path, std::string>> owned;
        for (const auto& entry : fs::directory_iterator(directory, error)) {
            if (!entry.is_regular_file(error)) continue;
            const auto name = entry.path().filename().string();
            const auto written = entry.last_write_time(error);
            if (error) continue;
            if (name.ends_with(".tmp")) {
                if (now - written > std::chrono::hours(24)) fs::remove(entry.path(), error);
                continue;
            }
            std::string key;
            for (const std::string_view prefix : {"view-", "source-"})
                if (name.starts_with(prefix)) key = name.substr(prefix.size(), name.find('.') - prefix.size());
            if (key.size() != 64 || key.find_first_not_of("0123456789abcdef") != std::string::npos) continue;
            auto& time = newest[key]; time = std::max(time, written);
            owned.emplace_back(entry.path(), std::move(key));
        }
        if (newest.size() <= keep) return;
        std::vector<std::pair<fs::file_time_type, std::string>> order;
        for (const auto& [key, time] : newest) order.emplace_back(time, key);
        std::sort(order.begin(), order.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
        std::set<std::string> retained;
        for (size_t i = 0; i < keep; ++i) retained.insert(order[i].second);
        for (const auto& [path, key] : owned) if (!retained.contains(key)) fs::remove(path, error);
    } catch (...) { /* Cleanup is optional. */ }
}
}

DirectoryCache::Snapshot::~Snapshot() { budget->bytes.fetch_sub(charged); }
void DirectoryCache::Snapshot::compact() noexcept {
    // Most startup directories hold a handful of entries; growth slack would
    // otherwise dominate the memory budget.
    if (entries.size() == entries.capacity()) return;
    try {
        std::vector<WIN32_FIND_DATAA> exact(entries.begin(), entries.end());
        if (exact.capacity() >= entries.capacity()) return;
        const size_t released = (entries.capacity() - exact.capacity()) * sizeof(WIN32_FIND_DATAA);
        entries.swap(exact);
        charged -= released; budget->bytes.fetch_sub(released);
    } catch (...) { /* Keep the larger allocation; its charge is unchanged. */ }
}
bool DirectoryCache::Snapshot::append(const WIN32_FIND_DATAA& data) {
    if (entries.size() == entries.capacity()) {
        const size_t nextCapacity = std::max<size_t>(16, entries.capacity() * 2);
        const size_t delta = (nextCapacity - entries.capacity()) * sizeof(WIN32_FIND_DATAA);
        size_t used = budget->bytes.load();
        do {
            if (delta > budget->limit || used > budget->limit - delta) return false;
        } while (!budget->bytes.compare_exchange_weak(used, used + delta));
        try { entries.reserve(nextCapacity); }
        catch (...) { budget->bytes.fetch_sub(delta); return false; }
        charged += delta;
    }
    entries.push_back(data);
    return true;
}

DirectoryCache::DirectoryCache(std::string root, FileApi api, Options options) :
    api_(api), options_(options), root_(fullPath(root.c_str())), budget_(std::make_shared<Budget>()) {
    budget_->limit = options_.maxBytes;
    largeFetch_ = options_.largeFetch;
    while (!root_.empty() && root_.back() == '\\') root_.pop_back();
    if (root_.empty() || !options_.enabled) { active_ = false; return; }
    if (options_.virtualized) {
        // A watcher on physical Data cannot observe every source in a virtual tree.
        largeFetch_ = false;
        cacheAvailable_ = options_.allowVirtualSnapshot;
    } else {
        // A recursive watcher does not cover junction/symlink destinations.
        // Validate all root ancestors before enabling physical notifications.
        for (size_t pos = root_.find('\\', 3);; pos = root_.find('\\', pos + 1)) {
            const auto prefix = root_.substr(0, pos);
            const auto attributes = GetFileAttributesA(prefix.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return;
            if (pos == std::string::npos) break;
        }
        watcher_ = FindFirstChangeNotificationA(root_.c_str(), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_SECURITY);
        cacheAvailable_ = watcher_ != INVALID_HANDLE_VALUE;
    }
}
DirectoryCache::~DirectoryCache() {
    finish();
    waitForSave();
    { std::lock_guard lock(mutex_); stopCheckpoints_ = true; }
    checkpointWake_.notify_all();
    if (checkpointer_.joinable()) checkpointer_.join();
    for (auto& workerThread : workers_) if (workerThread.joinable()) workerThread.join();
    for (const auto& [handle, cursor] : cursors_) { (void)cursor; CloseHandle(handle); }
    if (watcher_ != INVALID_HANDLE_VALUE) FindCloseChangeNotification(watcher_);
}

std::optional<std::string> DirectoryCache::normalize(const char* pattern) const {
    if (!pattern || !*pattern || root_.empty()) return std::nullopt;
    std::string key = fullPath(pattern);
    if (key.size() <= root_.size() + 1 || _strnicmp(key.c_str(), root_.c_str(), root_.size()) != 0 ||
        key[root_.size()] != '\\') return std::nullopt;
    const size_t slash = key.find_last_of('\\');
    const std::string_view leaf(key.data() + slash + 1, key.size() - slash - 1);
    if (leaf != "*" && leaf != "*.*") return std::nullopt;
    if (key.find_first_of("*?") < slash) return std::nullopt;
    for (size_t begin = root_.size() + 1; begin < slash;) {
        const auto end = key.find('\\', begin);
        const std::string_view component(key.data() + begin, end - begin);
        // Runtime plugin data is outside the persisted asset scope. Reject Win32
        // aliases as well, so F4SE.\Plugins cannot bypass this boundary.
        if (component.empty() || component.back() == '.' || component.back() == ' ' ||
            component.find(':') != std::string_view::npos) return std::nullopt;
        if (begin == root_.size() + 1 && nativeRoot(component)) return std::nullopt;
        begin = end + 1;
    }
    // Preserve exact spelling and pattern: Win32 handles wildcard/8.3 matching.
    return key;
}

void DirectoryCache::invalidateLocked() {
    ++generation_;
    ++stats_.invalidations;
    clearCacheLocked();
    coveredDirectories_.clear();
    // Native handles remain live; only their speculative copies are discarded.
    captures_.clear();
    work_.clear();
    if (working_ == 0) idle_.notify_all();
}
void DirectoryCache::invalidate() noexcept {
    std::lock_guard lock(mutex_);
    invalidateLocked();
}
std::string DirectoryCache::directoryKey(const std::string& pattern) {
    std::string directory = pattern.substr(0, pattern.find_last_of('\\'));
    for (auto& c : directory) c = ascii_tolower(c);
    return directory;
}
void DirectoryCache::publishLocked(const std::string& key, std::shared_ptr<const Snapshot> snapshot) {
    directories_.insert_or_assign(directoryKey(key), snapshot);
    cache_.insert_or_assign(key, std::move(snapshot));
}
void DirectoryCache::clearCacheLocked() noexcept {
    cache_.clear();
    directories_.clear();
}
FileInfoResult DirectoryCache::unknownInfoLocked(InfoUnknown kind, const char* path) noexcept {
    const auto index = static_cast<size_t>(kind);
    const uint64_t count = ++stats_.infoUnknown[index];
    if (kind <= InfoUnknown::unlisted) ++stats_.infoMisses;
    // Power-of-two sampling spreads a bounded number of examples over the whole run.
    if ((count & (count - 1)) == 0) {
        try {
            char prefix[48];
            sprintf_s(prefix, "%s #%llu: ", infoUnknownName(index), static_cast<unsigned long long>(count));
            stats_.infoSamples.push_back(std::string(prefix) + (path ? path : ""));
        } catch (...) {}
    }
    return FileInfoResult::unknown;
}
FileInfoResult DirectoryCache::fileInfo(const char* path, WIN32_FIND_DATAA& data) noexcept {
    if (!active_.load() || !path) return FileInfoResult::unknown;
    try {
        const std::string full = fullPath(path);
        const auto supported = [&] {
            if (full.size() <= root_.size() + 1 || _strnicmp(full.c_str(), root_.c_str(), root_.size()) != 0 ||
                full[root_.size()] != '\\') return false;
            const size_t slash = full.find_last_of('\\');
            const std::string_view name(full.data() + slash + 1);
            // Win32 strips trailing dots/spaces; wildcards are not single files.
            if (name.empty() || name.back() == '.' || name.back() == ' ' || name.find_first_of("*?") != std::string_view::npos)
                return false;
            for (size_t begin = root_.size() + 1; begin < slash;) {
                const auto end = full.find('\\', begin);
                const std::string_view component(full.data() + begin, end - begin);
                if (component.empty() || component.back() == '.' || component.back() == ' ' ||
                    component.find(':') != std::string_view::npos) return false;
                if (begin == root_.size() + 1 && nativeRoot(component)) return false;
                begin = end + 1;
            }
            return !(slash == root_.size() && nativeRoot(name));
        };
        if (!supported()) {
            std::lock_guard lock(mutex_);
            return unknownInfoLocked(InfoUnknown::outside, path);
        }
        std::string name = full.substr(full.find_last_of('\\') + 1);
        // Absence is only claimed for names whose case folding is exact here.
        const bool ascii = asciiText(name.c_str());
        for (auto& c : name) c = ascii_tolower(c);
        const std::string directory = directoryKey(full);

        std::lock_guard lock(mutex_);
        pollChangesLocked();
        if (!active_ || !cacheAvailable_) return unknownInfoLocked(InfoUnknown::unavailable, path);
        if (virtualView_ && !viewFreshLocked()) {
            persistentGuard_ = false; cacheAvailable_ = false;
            persistenceStatus_ = "MO2 mapping changed; cached searches rejected";
            invalidateLocked();
            releaseValidationLocked();
            if (options_.progress) options_.progress->finish(false);
            return unknownInfoLocked(InfoUnknown::unavailable, path);
        }
        const auto matches = [](const WIN32_FIND_DATAA& entry, const std::string& wanted) {
            return _stricmp(entry.cFileName, wanted.c_str()) == 0 ||
                (entry.cAlternateFileName[0] && _stricmp(entry.cAlternateFileName, wanted.c_str()) == 0);
        };
        const auto answer = [&](const WIN32_FIND_DATAA& entry) {
            // Directories are not files the engine could open for information.
            if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return unknownInfoLocked(InfoUnknown::directory, path);
            data = entry; ++stats_.infoServed;
            return FileInfoResult::found;
        };
        const auto indexed = [](const Snapshot& snapshot) -> const Snapshot& {
            if (snapshot.names.empty()) {
                snapshot.names.reserve(snapshot.entries.size() * 2);
                snapshot.asciiNames = true;
                for (uint32_t i = 0; i < snapshot.entries.size(); ++i) {
                    snapshot.asciiNames = snapshot.asciiNames && asciiText(snapshot.entries[i].cFileName);
                    for (const char* alias : {snapshot.entries[i].cFileName, snapshot.entries[i].cAlternateFileName}) {
                        if (!*alias) continue;
                        std::string key(alias);
                        for (auto& c : key) c = ascii_tolower(c);
                        snapshot.names.try_emplace(std::move(key), i);
                    }
                }
            }
            return snapshot;
        };
        if (const auto listed = directories_.find(directory); listed != directories_.end()) {
            const auto& snapshot = indexed(*listed->second);
            if (const auto entry = snapshot.names.find(name); entry != snapshot.names.end()) {
                const auto& candidate = snapshot.entries[entry->second];
                if (matches(candidate, name)) return answer(candidate);
            }
            if (ascii && snapshot.asciiNames) {
                ++stats_.infoAbsent;
                return FileInfoResult::absent;
            }
            return unknownInfoLocked(InfoUnknown::nonAscii, path);
        }
        // The engine asks while enumerating: the entry was just captured. Such a
        // listing is incomplete, so it can confirm existence but never absence.
        bool capturing = false;
        for (const auto& [handle, capture] : captures_) {
            (void)handle;
            if (!capture.snapshot || capture.generation != generation_ || directoryKey(capture.key) != directory) continue;
            capturing = true;
            const auto& entries = capture.snapshot->entries;
            for (auto entry = entries.rbegin(); entry != entries.rend(); ++entry)
                if (matches(*entry, name)) return answer(*entry);
        }
        // A folder that does not exist has no listing of its own. Walk down from
        // the root through complete listings: once a folder is missing from its
        // parent's, nothing beneath it exists. (For each loose audio file the
        // engine also asks twice for a path with Data doubled, Data\DATA\SOUND\...)
        for (size_t parentEnd = root_.size(); !capturing && parentEnd < directory.size();) {
            const auto listed = directories_.find(directory.substr(0, parentEnd));
            if (listed == directories_.end()) break;
            const auto& parent = indexed(*listed->second);
            const size_t childEnd = std::min(directory.find('\\', parentEnd + 1), directory.size());
            const std::string child = directory.substr(parentEnd + 1, childEnd - parentEnd - 1);
            if (!parent.names.contains(child)) {
                if (!asciiText(child.c_str()) || !parent.asciiNames) break;
                ++stats_.infoAbsent;
                return FileInfoResult::absent;
            }
            parentEnd = childEnd;
        }
        return unknownInfoLocked(capturing ? InfoUnknown::capturing : InfoUnknown::unlisted, path);
    } catch (...) { return FileInfoResult::unknown; }
}
void DirectoryCache::releaseValidationLocked() noexcept {
    persistentGuard_ = false;
    try {
        if (persistence_) stats_.persistence = persistence_->metrics();
        if (virtualView_) {
            stats_.viewChecks = virtualView_->checks(); stats_.viewMicroseconds = virtualView_->microseconds();
            stats_.viewDumps = virtualView_->dumps(); stats_.viewGuardBytes = virtualView_->guardBytes();
        }
    } catch (...) { /* Diagnostic allocation failure must not retain the proof. */ }
    persistence_.reset(); virtualView_.reset();
}
void DirectoryCache::pollChangesLocked() {
    const auto begin = Clock::now();
    struct Timing {
        Statistics& stats; Clock::time_point begin;
        ~Timing() { ++stats.polls; stats.pollMicroseconds += microseconds(begin); }
    } timing{stats_, begin};
    bool notified = false, failed = false;
    if (watcher_ != INVALID_HANDLE_VALUE) {
        const DWORD state = WaitForSingleObject(watcher_, 0);
        notified = state != WAIT_TIMEOUT;
        if (notified) failed = state != WAIT_OBJECT_0 || !FindNextChangeNotification(watcher_);
        if (failed) watcherFailed_ = true;
    }
    if (persistentGuard_ && persistence_->pollChanged()) {
        persistentGuard_ = false;
        persistenceStatus_ = persistence_->status();
        invalidateLocked();
        // Physical watchers are also insufficient after proof rejection: writes
        // through a hard link outside Data can escape that weaker fallback.
        cacheAvailable_ = false;
        releaseValidationLocked();
        if (options_.progress) options_.progress->finish(false);
    }
    // A validated identity/journal proof can distinguish asset writes from
    // runtime-cache writes. Without it, retain conservative notification handling.
    if (notified && (!persistentGuard_ || failed)) invalidateLocked();
    if (failed) {
        // Keep the handle until destruction but stop publishing/replaying snapshots.
        persistentGuard_ = false; cacheAvailable_ = false;
        releaseValidationLocked();
        if (options_.progress) options_.progress->finish(false);
    }
}
void DirectoryCache::learnLocked(const std::string& key) {
    if (learned_.size() >= options_.maxDirectories || learnedSet_.contains(key)) return;
    learnedSet_.insert(key);
    learned_.push_back(key);
}
bool DirectoryCache::watchCoversLocked(const std::string& key) {
    if (persistentGuard_) return true; // The complete source tree was checked.
    if (options_.virtualized) return options_.allowVirtualSnapshot;
    const std::string directory = key.substr(0, key.find_last_of('\\'));
    if (coveredDirectories_.contains(directory)) return true;
    for (size_t pos = root_.size();; pos = directory.find('\\', pos + 1)) {
        const auto prefix = directory.substr(0, pos);
        const auto attributes = GetFileAttributesA(prefix.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            !(attributes & FILE_ATTRIBUTE_DIRECTORY)) return false;
        if (pos == std::string::npos || pos == directory.size()) break;
    }
    coveredDirectories_.insert(directory);
    return true;
}
bool DirectoryCache::replayData(const Cursor& cursor, size_t index, WIN32_FIND_DATAA& output) noexcept {
    output = cursor.snapshot->entries[index];
    if (!cursor.refreshParent) return true;
    // Data/.. is outside the asset proof, and the F4SE/Root boundaries and MO2
    // meta.ini files are deliberately unindexed: a runtime file created inside a
    // boundary changes its timestamps without a journal record for it. Never
    // replay their old metadata; names, order and presence remain proven.
    const std::string_view name(output.cFileName);
    const bool metadata = name.size() >= 8 && _strnicmp(output.cFileName, "meta.ini", 8) == 0;
    if (name != ".." && !nativeRoot(name) && !metadata) return true;
    try {
        WIN32_FILE_ATTRIBUTE_DATA current{};
        const auto path = cursor.directory + "\\" + output.cFileName;
        if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &current)) return false;
        output.dwFileAttributes = current.dwFileAttributes;
        output.ftCreationTime = current.ftCreationTime;
        output.ftLastAccessTime = current.ftLastAccessTime;
        output.ftLastWriteTime = current.ftLastWriteTime;
        output.nFileSizeHigh = current.nFileSizeHigh;
        output.nFileSizeLow = current.nFileSizeLow;
        return true;
    } catch (...) { return false; }
}
bool DirectoryCache::viewFreshLocked() {
    // A whole-view comparison costs ~5 ms on a large MO2 profile, more than the
    // average native search it would replace, so one successful check admits
    // replays for viewCheckMs. Asset writes made through the VFS are physical
    // changes that the journal poll reports before every replay. The interval
    // only bounds how long an MO2 remap performed mid-startup (for example by
    // launching another tool) goes unnoticed; native enumeration during such a
    // remap would itself mix the old and new views.
    const auto now = GetTickCount64();
    if (options_.viewCheckMs && lastViewCheck_ && now - lastViewCheck_ < options_.viewCheckMs) return true;
    if (!virtualView_->unchanged()) return false;
    lastViewCheck_ = GetTickCount64();
    return true;
}
HANDLE DirectoryCache::nativeFirst(const char* pattern, WIN32_FIND_DATAA* result, bool eligible) noexcept {
    if (eligible && largeFetch_.load() && api_.firstEx) {
        HANDLE handle = api_.firstEx(pattern, FindExInfoStandard, result, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (handle != INVALID_HANDLE_VALUE) return handle;
        // Unsupported flags, virtualizers, network filesystems, or other errors:
        // repeat using the exact original import and expose its error to the caller.
    }
    return api_.first(pattern, result);
}

HANDLE DirectoryCache::first(LPCSTR pattern, LPWIN32_FIND_DATAA result) noexcept {
    const DWORD entryError = GetLastError();
    if (!active_.load() || !result || !pattern) return api_.first(pattern, result);
    std::optional<std::string> key;
    uint64_t generation = 0;
    try {
        key = normalize(pattern);
        if (key) {
            std::lock_guard lock(mutex_);
            pollChangesLocked();
            learnLocked(*key);
            generation = generation_;
            const auto hit = cache_.find(*key);
            if (cacheAvailable_ && hit != cache_.end() && watchCoversLocked(*key)) {
                if (virtualView_ && !viewFreshLocked()) {
                    persistentGuard_ = false; cacheAvailable_ = false;
                    persistenceStatus_ = "MO2 mapping changed; cached searches rejected";
                    invalidateLocked();
                    releaseValidationLocked();
                    if (options_.progress) options_.progress->finish(false);
                } else {
                    const auto slash = key->find_last_of('\\');
                    Cursor cursor{hit->second, 1, key->substr(0, slash), slash == root_.size()};
                    WIN32_FIND_DATAA initial{};
                    if (!replayData(cursor, 0, initial)) throw std::runtime_error("Directory disappeared during replay");
                    HANDLE token = CreateEventW(nullptr, FALSE, FALSE, nullptr);
                    if (token) {
                        try { cursors_.emplace(token, std::move(cursor)); }
                        catch (...) { CloseHandle(token); throw; }
                        *result = initial;
                        ++stats_.hits;
                        if (hit->second->persisted) ++stats_.persistentHits;
                        ++replayHandles_;
                        ++stats_.replayedEntries;
                        SetLastError(entryError);
                        return token;
                    }
                }
            }
            ++stats_.misses;
        }
    } catch (...) { key.reset(); }

    SetLastError(entryError);
    const auto begin = Clock::now();
    const HANDLE handle = nativeFirst(pattern, result, key.has_value());
    const DWORD nativeError = GetLastError();
    const auto elapsed = microseconds(begin); // Excludes waiting for the cache lock.
    try {
        if (key) {
            std::lock_guard lock(mutex_);
            stats_.nativeMicroseconds += elapsed;
            if (handle != INVALID_HANDLE_VALUE) {
                ++stats_.nativeEntries;
                // A change during this enumeration is caught by the poll and
                // generation check made before close() publishes the capture.
                if (active_ && cacheAvailable_ && watchCoversLocked(*key) && generation == generation_ && captures_.size() < 1024 &&
                    cache_.size() < options_.maxDirectories) {
                    auto snapshot = std::make_shared<Snapshot>(budget_);
                    if (snapshot->append(*result))
                        captures_.emplace(handle, Capture{*key, generation, std::move(snapshot), false});
                    else ++stats_.abandoned;
                }
            }
        }
    } catch (...) { /* Native enumeration remains valid when allocation fails. */ }
    SetLastError(nativeError);
    return handle;
}

BOOL DirectoryCache::next(HANDLE handle, LPWIN32_FIND_DATAA result) noexcept {
    if (!active_ && replayHandles_.load() == 0) return api_.next(handle, result);
    const DWORD entryError = GetLastError();
    {
        std::lock_guard lock(mutex_);
        const auto it = cursors_.find(handle);
        if (it != cursors_.end()) {
            auto& cursor = it->second;
            if (!result) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
            if (cursor.position == cursor.snapshot->entries.size()) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
            // A previously opened cursor can drain its snapshot after a mutation.
            (void)replayData(cursor, cursor.position++, *result);
            ++stats_.replayedEntries;
            SetLastError(entryError);
            return TRUE;
        }
    }
    SetLastError(entryError);
    const auto begin = Clock::now();
    const BOOL success = api_.next(handle, result);
    const DWORD nativeError = GetLastError();
    const auto elapsed = microseconds(begin); // Excludes waiting for the cache lock.
    try {
        std::lock_guard lock(mutex_);
        auto it = captures_.find(handle);
        if (it != captures_.end()) {
            stats_.nativeMicroseconds += elapsed;
            if (success) {
                ++stats_.nativeEntries;
                if (it->second.snapshot && !it->second.snapshot->append(*result)) { captures_.erase(it); ++stats_.abandoned; }
            } else if (nativeError == ERROR_NO_MORE_FILES) it->second.complete = true;
            else { captures_.erase(it); ++stats_.abandoned; }
        }
    } catch (...) {
        std::lock_guard lock(mutex_);
        captures_.erase(handle);
    }
    SetLastError(nativeError);
    return success;
}

BOOL DirectoryCache::close(HANDLE handle) noexcept {
    if (!active_ && replayHandles_.load() == 0) return api_.close(handle);
    const DWORD entryError = GetLastError();
    std::optional<Capture> closedCapture;
    {
        std::lock_guard lock(mutex_);
        if (cursors_.erase(handle)) {
            --replayHandles_;
            const BOOL success = CloseHandle(handle);
            if (success) SetLastError(entryError);
            return success;
        }
        // Detach before the native close releases its handle value. Another
        // thread may immediately reuse that value for a different enumeration.
        const auto capture = captures_.find(handle);
        if (capture != captures_.end()) {
            closedCapture.emplace(std::move(capture->second));
            captures_.erase(capture);
        }
    }
    SetLastError(entryError);
    const BOOL success = api_.close(handle);
    const DWORD nativeError = GetLastError();
    // Only a captured enumeration can be published; any other close needs no
    // lock or journal poll.
    if (closedCapture && closedCapture->snapshot) {
        try {
            auto& capture = *closedCapture;
            // Still exclusively owned here; compact before other threads can replay it.
            if (success && capture.complete) capture.snapshot->compact();
            std::lock_guard lock(mutex_);
            pollChangesLocked();
            if (success && active_ && cacheAvailable_ && capture.complete && capture.generation == generation_ &&
                cache_.size() < options_.maxDirectories) publishLocked(capture.key, capture.snapshot);
            else ++stats_.abandoned;
        } catch (...) { /* Never erase a newer enumeration that reused this handle. */ }
    }
    SetLastError(nativeError);
    return success;
}

void DirectoryCache::prefetch(const std::string& key, uint64_t generation) noexcept {
    HANDLE handle = INVALID_HANDLE_VALUE;
    const auto begin = Clock::now();
    try {
        auto snapshot = std::make_shared<Snapshot>(budget_);
        WIN32_FIND_DATAA data{};
        handle = nativeFirst(key.c_str(), &data, true);
        if (handle == INVALID_HANDLE_VALUE) return; // Never cache a failed/missing search.
        bool complete = false;
        do {
            if (!active_ || GetTickCount64() > deadline_ || !snapshot->append(data)) break;
            if (!api_.next(handle, &data)) { complete = GetLastError() == ERROR_NO_MORE_FILES; break; }
        } while (true);
        const BOOL closed = api_.close(handle);
        handle = INVALID_HANDLE_VALUE;
        if (complete) snapshot->compact();
        std::lock_guard lock(mutex_);
        stats_.prefetchMicroseconds += microseconds(begin);
        pollChangesLocked();
        if (complete && closed && active_ && cacheAvailable_ && generation == generation_ &&
            cache_.size() < options_.maxDirectories && !cache_.contains(key)) {
            publishLocked(key, std::move(snapshot));
            ++stats_.prefetched;
        } else ++stats_.abandoned;
    } catch (...) {
        if (handle != INVALID_HANDLE_VALUE) api_.close(handle);
    }
}

void DirectoryCache::worker() noexcept {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    bool countedWork = false;
    try {
    for (;;) {
        std::string key;
        uint64_t generation;
        {
            std::unique_lock lock(mutex_);
            workAvailable_.wait(lock, [&] { return !active_ || !work_.empty(); });
            if (!active_) return;
            if (GetTickCount64() > deadline_) { work_.clear(); idle_.notify_all(); continue; }
            key = std::move(work_.front()); work_.pop_front();
            pollChangesLocked();
            if (!cacheAvailable_ || cache_.contains(key) || !watchCoversLocked(key)) {
                if (work_.empty() && !working_) idle_.notify_all(); continue;
            }
            generation = generation_;
            ++working_;
            countedWork = true;
        }
        prefetch(key, generation);
        {
            std::lock_guard lock(mutex_);
            --working_;
            countedWork = false;
            if (work_.empty() && !working_) idle_.notify_all();
        }
    }
    } catch (...) {
        std::lock_guard lock(mutex_);
        if (countedWork) --working_;
        active_ = false;
        invalidateLocked();
        idle_.notify_all(); workAvailable_.notify_all();
    }
}

void DirectoryCache::startPrefetch(const std::filesystem::path& plan) {
    std::lock_guard lock(mutex_);
    // An old path-only plan cannot predict which directories pass the automatic
    // MO2 admission threshold. Prefetching them can duplicate thousands of small
    // native searches after a rejected cache. Capture actual game searches only.
    if (!active_ || !cacheAvailable_ || virtualView_ || !workers_.empty() || options_.workers == 0) return;
    std::error_code error;
    if (std::filesystem::file_size(plan, error) > 4 * 1024 * 1024 || error) return;
    std::ifstream input(plan, std::ios::binary);
    std::string line;
    if (!std::getline(input, line) || line != "FasterStartup plan v1" || !std::getline(input, line) || line != root_) return;
    std::unordered_set<std::string> seen;
    while (work_.size() < options_.maxDirectories && std::getline(input, line)) {
        if (line.size() > 32760 || line.find('\0') != std::string::npos) continue;
        auto key = normalize(line.c_str());
        if (key && *key == line && !cache_.contains(*key) && seen.insert(line).second) work_.push_back(std::move(line));
    }
    if (work_.empty()) return;
    deadline_ = GetTickCount64() + options_.prefetchWindowMs;
    for (unsigned i = 0; i < std::min(options_.workers, 4u); ++i) workers_.emplace_back([this] { worker(); });
    workAvailable_.notify_all();
}
void DirectoryCache::waitForPrefetch() {
    std::unique_lock lock(mutex_);
    idle_.wait(lock, [&] { return (work_.empty() && working_ == 0) || !active_; });
}
bool DirectoryCache::initializePersistence(const std::filesystem::path& stateDirectory,
    const std::filesystem::path& preparedProof, const std::string& instance) noexcept {
    const auto began = Clock::now();
    bool virtualized = false;
    {
        std::lock_guard lock(mutex_);
        try {
            if (!options_.virtualized && GetModuleHandleW(L"usvfs_x64.dll")) {
                // Activation is deferred until the first search, after late MO2 injection.
                options_.virtualized = true; largeFetch_ = false;
                cacheAvailable_ = false; invalidateLocked();
                if (watcher_ != INVALID_HANDLE_VALUE) { FindCloseChangeNotification(watcher_); watcher_ = INVALID_HANDLE_VALUE; }
            }
            if (!active_ || !options_.persistent || persistence_ || initializing_) return false;
            // Searches made while validating stay native and are not captured:
            // nothing outside the proof may be published.
            initializing_ = true;
            cacheAvailable_ = false;
            if (!cache_.empty() || !captures_.empty() || !work_.empty() || working_) invalidateLocked();
            virtualized = options_.virtualized;
        } catch (...) { return false; }
    }
    // All validation I/O runs without the cache lock, so concurrent searches,
    // FindNextFile and FindClose calls on other threads never wait for it.
    // Declared before the publishing lock: they are destroyed after its release.
    std::unique_ptr<PersistentStore> store;
    std::shared_ptr<VirtualView> view;
    std::filesystem::path snapshotPath;
    std::unordered_map<std::string, std::shared_ptr<const Snapshot>> loaded;
    std::string failure;
    bool proven = false;
    try {
        if (stateDirectory.empty()) throw std::runtime_error("Cache state directory unavailable");
        if (options_.progress) options_.progress->phase(ProgressPhase::checking);
        std::filesystem::create_directories(stateDirectory);
        PersistenceLimits limits; limits.maxSnapshotBytes = options_.maxBytes; limits.maxDirectories = options_.maxDirectories;
        store = std::make_unique<PersistentStore>(limits, options_.progress);
        const auto wideRoot = std::filesystem::path(root_).wstring();
        bool prepared = false;
        if (virtualized && preparedProof.empty()) {
            view = VirtualView::attach(wideRoot, stateDirectory, instance);
            const auto& scope = view->scope();
            prepared = store->prepare(scope, stateDirectory / ("source-" + contextKey(scope.context) + ".index"));
            if (std::string problem; prepared && !view->settled(viewSettleMs, &problem))
                throw std::runtime_error("MO2 view not confirmed after source validation: " + problem);
        } else if (virtualized) {
            prepared = store->adoptPrepared(wideRoot, preparedProof);
        } else {
            prepared = store->prepare({wideRoot, {}, {wideRoot}}, stateDirectory / L"source.index");
        }
        if (!prepared || !store->startWatching()) throw std::runtime_error(store->status());
        snapshotPath = stateDirectory / ("view-" + contextKey(store->context()) + ".cache");
        // A rebuilt index has a new random generation that no earlier result
        // file can match; skip reading and hashing it.
        if (store->metrics().reusedProof) {
            const bool ok = store->load(snapshotPath, [&](PersistentRow&& row) {
                const auto key = normalize(row.pattern.c_str());
                if (!key || *key != row.pattern || loaded.contains(*key)) throw std::runtime_error("Invalid/duplicate cached search path");
                auto snapshot = std::make_shared<Snapshot>(budget_);
                const size_t charge = row.entries.capacity() * sizeof(WIN32_FIND_DATAA);
                size_t used = budget_->bytes.load();
                do {
                    if (charge > budget_->limit || used > budget_->limit - charge) return false;
                } while (!budget_->bytes.compare_exchange_weak(used, used + charge));
                snapshot->charged = charge; snapshot->entries = std::move(row.entries); snapshot->persisted = true;
                loaded.emplace(*key, std::move(snapshot));
                return true;
            });
            if (!ok) loaded.clear(); // Even a late validation/callback failure is atomic to readers.
        }
        if (std::string problem; view && !view->settled(viewSettleMs, &problem))
            throw std::runtime_error("MO2 view not confirmed after loading cache: " + problem);
        proven = true;
    } catch (const std::exception& e) { failure = e.what(); loaded.clear(); }
    catch (...) { failure = "Persistent cache initialization failed"; loaded.clear(); }

    std::lock_guard lock(mutex_);
    initializing_ = false;
    stats_.initMicroseconds = microseconds(began);
    try {
        if (store) stats_.persistence = store->metrics();
        if (view) {
            stats_.viewChecks = view->checks(); stats_.viewMicroseconds = view->microseconds();
            stats_.viewDumps = view->dumps(); stats_.viewGuardBytes = view->guardBytes();
        }
        if (!proven || !active_ || watcherFailed_) {
            persistenceStatus_ = !proven ? failure : (!active_ ? "Startup finished before cache validation completed" :
                "Change notification failed during cache validation");
            persistentGuard_ = false; cacheAvailable_ = false;
            if (options_.progress) options_.progress->finish(false);
            return false;
        }
        persistenceStatus_ = store->metrics().reusedProof ? store->status() : "Source index rebuilt; capturing current results";
        persistence_ = std::move(store); virtualView_ = std::move(view);
        snapshotPath_ = std::move(snapshotPath);
        lastViewCheck_ = GetTickCount64();
        if (!cache_.empty() || !captures_.empty()) invalidateLocked();
        for (auto& [key, snapshot] : loaded) publishLocked(key, std::move(snapshot));
        persistentGuard_ = true;
        cacheAvailable_ = true;
        pollChangesLocked();
        if (options_.progress && persistentGuard_) {
            // No reusable results: this launch captures the cache the next one uses.
            if (!persistence_->metrics().reusedProof || loaded.empty()) options_.progress->markBuilding();
            options_.progress->phase(ProgressPhase::capturing);
        }
        return persistentGuard_;
    } catch (...) {
        clearCacheLocked(); persistentGuard_ = false; cacheAvailable_ = false; releaseValidationLocked();
        if (options_.progress) options_.progress->finish(false);
        return false;
    }
}
void DirectoryCache::finishAndSave(std::function<void(bool)> completion) noexcept {
    std::unique_lock lock(mutex_);
    try {
        if (!active_) return;
        pollChangesLocked();
        active_ = false; cacheAvailable_ = false;
        work_.clear(); captures_.clear();
        workAvailable_.notify_all(); idle_.notify_all();
        if (!persistentGuard_ || !persistence_ || cache_.empty()) {
            clearCacheLocked(); releaseValidationLocked();
            if (options_.progress) options_.progress->finish(false);
            lock.unlock();
            if (completion) { try { completion(false); } catch (...) {} }
            return;
        }
        // Transfer immutable snapshots and the validator to a low-priority saver.
        // The GameDataReady callback does not serialize or flush files.
        persistentGuard_ = false;
        if (options_.progress) options_.progress->phase(ProgressPhase::saving, cache_.size());
        directories_.clear();
        saver_ = std::thread([this, snapshots = std::move(cache_), store = std::move(persistence_), view = virtualView_, path = snapshotPath_, completion = std::move(completion)]() mutable {
            if (!SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN))
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
            bool saved = false, viewMatched = true;
            std::string viewProblem;
            try {
                std::vector<PersistentRowView> rows; rows.reserve(snapshots.size());
                for (const auto& [key, snapshot] : snapshots) rows.push_back({key, snapshot->entries});
                // Unlike replays, persisting always performs a full view check. Other
                // plugins may still write through USVFS at GameDataReady; wait for that.
                viewMatched = !view || view->settled(viewSettleMs, &viewProblem);
                saved = viewMatched && store->save(path, rows);
            } catch (...) { /* A missed cache write cannot affect the game. */ }
            if (saved) pruneState(path.parent_path(), 4);
            try {
                std::lock_guard done(mutex_);
                stats_.persistence = store->metrics();
                persistenceStatus_ = saved ? "Persistent directory results saved" : !viewMatched ?
                    "MO2 view not confirmed at save time (" + viewProblem + "); results not saved" : store->status();
                if (view) {
                    stats_.viewChecks = view->checks(); stats_.viewMicroseconds = view->microseconds();
                    stats_.viewDumps = view->dumps(); stats_.viewGuardBytes = view->guardBytes();
                }
                virtualView_.reset(); // The background job owns the final reference.
            } catch (...) { /* Diagnostics must not terminate the saver thread. */ }
            view.reset(); // Release mapping guard/dump memory after startup saving.
            snapshots.clear();
            if (options_.progress) options_.progress->finish(saved);
            if (completion) { try { completion(saved); } catch (...) {} }
            if (saved && options_.checkpointMinutes) startCheckpoints(std::move(store));
            else store.reset();
        });
    } catch (...) {
        active_ = false; cacheAvailable_ = false; persistentGuard_ = false; clearCacheLocked(); captures_.clear(); work_.clear();
        releaseValidationLocked();
        if (options_.progress) options_.progress->finish(false);
        persistenceStatus_ = "Background cache save could not start";
        workAvailable_.notify_all(); idle_.notify_all();
    }
}
void DirectoryCache::startCheckpoints(std::unique_ptr<PersistentStore> store) noexcept {
    try {
        std::lock_guard lock(mutex_);
        if (stopCheckpoints_ || checkpointer_.joinable()) return;
        // The saved journal cursor otherwise stays at GameDataReady. A long play
        // session on a busy volume can wrap a default-sized journal before the
        // next launch, which forces a full rebuild.
        checkpointer_ = std::thread([this, store = std::move(store)]() mutable {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
            std::unique_lock lock(mutex_);
            const auto interval = std::chrono::minutes(options_.checkpointMinutes);
            while (!checkpointWake_.wait_for(lock, interval, [this] { return stopCheckpoints_; })) {
                lock.unlock();
                const bool ok = store->checkpoint();
                lock.lock();
                if (!ok) { persistenceStatus_ = "Journal checkpoints stopped: " + store->status(); break; }
                ++stats_.checkpoints;
            }
            lock.unlock();
            store.reset();
        });
    } catch (...) { /* Checkpointing is optional; the next launch validates as before. */ }
}
void DirectoryCache::waitForSave() { if (saver_.joinable()) saver_.join(); }
std::string DirectoryCache::persistenceStatus() const {
    std::lock_guard lock(mutex_); return persistenceStatus_;
}
std::filesystem::path DirectoryCache::scopedPlanPath() const {
    std::lock_guard lock(mutex_);
    auto path = snapshotPath_;
    if (!path.empty()) path.replace_extension(L".plan");
    return path;
}
void DirectoryCache::finish() noexcept {
    std::lock_guard lock(mutex_);
    active_ = false; cacheAvailable_ = false; persistentGuard_ = false;
    work_.clear(); clearCacheLocked(); captures_.clear();
    releaseValidationLocked();
    if (options_.progress) options_.progress->finish(false);
    workAvailable_.notify_all(); idle_.notify_all();
    // Existing replay handles retain immutable snapshots until the caller closes.
}
void DirectoryCache::savePlan(const std::filesystem::path& path) noexcept {
    try {
        std::vector<std::string> learned;
        { std::lock_guard lock(mutex_); learned = learned_; }
        if (learned.empty()) return;
        auto temporary = path;
        temporary += "." + std::to_string(GetCurrentProcessId()) + ".tmp";
        {
            std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
            output << "FasterStartup plan v1\n" << root_ << '\n';
            for (const auto& key : learned) output << key << '\n';
            output.flush();
            if (!output) { output.close(); DeleteFileW(temporary.c_str()); return; }
        }
        if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) DeleteFileW(temporary.c_str());
    } catch (...) { /* Training failure must never affect game startup. */ }
}
Statistics DirectoryCache::statistics() const {
    std::lock_guard lock(mutex_);
    auto result = stats_;
    result.active = active_.load(); result.liveReplayHandles = replayHandles_.load();
    if (persistence_) result.persistence = persistence_->metrics();
    if (virtualView_) {
        result.viewChecks = virtualView_->checks(); result.viewMicroseconds = virtualView_->microseconds();
        result.viewDumps = virtualView_->dumps(); result.viewGuardBytes = virtualView_->guardBytes();
    }
    result.memoryBytes = budget_->bytes.load();
    result.cachedDirectories = cache_.size();
    result.learnedDirectories = learned_.size();
    return result;
}
}
