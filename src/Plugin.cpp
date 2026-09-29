#include "DirectoryCache.h"
#include "EngineInfoHook.h"
#include "ExtenderAbi.h"
#include "ImportHooks.h"
#include "ProgressPanel.h"
#include <ShlObj.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <share.h>

namespace {
startup::DirectoryCache* cache = nullptr;
startup::ProgressPanel* progressPanel = nullptr;
startup::ImportHooks hooks;
startup::EngineInfoHook engineHook;
std::filesystem::path planPath; // Written only while loading, before any thread starts.
FILE* logFile = nullptr;
std::mutex logMutex; // The game thread, activation thread and saver all write reports.
ULONGLONG loadedAt = 0;
uint64_t processCreation = 0;
bool installed = false;
std::atomic<bool> virtualAtLoad{false};
std::atomic<bool> waitingForVirtualizer{false};
std::atomic<bool> lateVirtualizerStopped{false};
std::once_flag virtualActivation;
std::once_flag cacheInitialization;
std::atomic<bool> activationPending{false};
std::filesystem::path pendingPrepared;
std::mutex activationMutex;
std::condition_variable activationDone;
bool activationFinished = false;

struct LaunchTicket {
    std::filesystem::path claimed;
    ~LaunchTicket() { if (!claimed.empty()) DeleteFileW(claimed.c_str()); }
    bool take(const std::filesystem::path& source) {
        const auto stem = source.stem().wstring();
        if (source.extension() != L".context" || stem.size() != 39 || !stem.starts_with(L"launch-") ||
            stem.find_first_not_of(L"0123456789abcdef", 7) != std::wstring::npos) return false;
        WIN32_FILE_ATTRIBUTE_DATA info{}; FILETIME now{}; GetSystemTimeAsFileTime(&now);
        if (!GetFileAttributesExW(source.c_str(), GetFileExInfoStandard, &info)) return false;
        const auto stamp = (uint64_t(info.ftLastWriteTime.dwHighDateTime) << 32) | info.ftLastWriteTime.dwLowDateTime;
        const auto current = (uint64_t(now.dwHighDateTime) << 32) | now.dwLowDateTime;
        if (stamp > current || current - stamp > 300ULL * 10000000) return false;
        auto target = source; target += L"." + std::to_wstring(GetCurrentProcessId()) + L".claimed";
        // Atomic claim: an inherited stale environment variable cannot reuse a
        // launch ticket after any game process has consumed it.
        if (!MoveFileExW(source.c_str(), target.c_str(), 0)) return false;
        claimed = std::move(target); return true;
    }
};

void writeLine(const char* text) noexcept {
    std::fprintf(logFile, "[%llu ms] %s\n", GetTickCount64() - loadedAt, text); std::fflush(logFile);
}
void log(const char* text) noexcept {
    if (!logFile) return;
    try { std::lock_guard lock(logMutex); writeLine(text); } catch (...) {}
}
uint64_t fileTime(FILETIME value) { return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime; }
void report(const char* milestone) noexcept {
    if (!cache || !logFile) return;
    try {
        const auto s = cache->statistics();
        const auto status = cache->persistenceStatus();
        FILETIME now{}; GetSystemTimeAsFileTime(&now);
        std::lock_guard lock(logMutex); // Keep each multi-line report contiguous.
        std::fprintf(logFile,
            "%s process_age_ms=%llu plugin_age_ms=%llu hits=%llu misses=%llu prefetched=%llu "
            "native_entries=%llu replayed_entries=%llu invalidations=%llu abandoned=%llu "
            "native_api_us=%llu prefetch_api_us=%llu cache_bytes=%llu directories=%llu learned=%llu "
            "persistent_hits=%llu loaded=%llu saved=%llu identity_walk_dirs=%llu journal_records=%llu "
            "disk_load_us=%llu disk_save_us=%llu reused_index=%u view_checks=%llu view_us=%llu view_dumps=%llu view_guard_bytes=%llu "
            "init_ms=%llu polls=%llu poll_us=%llu checkpoints=%llu info_served=%llu info_absent=%llu info_misses=%llu "
            "active=%u live_replay_handles=%zu\n",
            milestone, processCreation ? (fileTime(now) - processCreation) / 10000 : 0, GetTickCount64() - loadedAt,
            s.hits, s.misses, s.prefetched, s.nativeEntries, s.replayedEntries, s.invalidations, s.abandoned,
            s.nativeMicroseconds, s.prefetchMicroseconds, s.memoryBytes, s.cachedDirectories, s.learnedDirectories,
            s.persistentHits, s.persistence.loadedDirectories, s.persistence.savedDirectories, s.persistence.scannedDirectories,
            s.persistence.journalRecords, s.persistence.loadMicroseconds, s.persistence.saveMicroseconds, unsigned(s.persistence.reusedProof),
            s.viewChecks, s.viewMicroseconds, s.viewDumps, s.viewGuardBytes,
            s.initMicroseconds / 1000, s.polls, s.pollMicroseconds, s.checkpoints, s.infoServed, s.infoAbsent, s.infoMisses,
            unsigned(s.active), s.liveReplayHandles);
        if (engineHook.installed) {
            std::fprintf(logFile, "Engine info to engine: engine_us=%llu unresolved=%llu",
                startup::engineInfoMicroseconds(), startup::unresolvedInfoQueries());
            for (size_t kind = 0; kind < std::size(s.infoUnknown); ++kind)
                std::fprintf(logFile, " %s=%llu", startup::infoUnknownName(kind), s.infoUnknown[kind]);
            std::fprintf(logFile, "\n");
            if (std::strncmp(milestone, "GameDataReady complete", 22) == 0) {
                for (const auto& sample : s.infoSamples) std::fprintf(logFile, "Engine info sample %s\n", sample.c_str());
                const auto verification = startup::engineInfoVerification();
                if (verification.checked) {
                    std::fprintf(logFile, "Engine info verification: checked=%llu mismatches=%llu\n",
                        verification.checked, verification.mismatches);
                    for (const auto& sample : verification.samples) std::fprintf(logFile, "Engine info mismatch %s\n", sample.c_str());
                }
            }
        }
        std::fprintf(logFile, "Persistence: %s\n", status.c_str());
        if (!s.persistence.sourceIndexStatus.empty()) std::fprintf(logFile, "Source index: %s\n", s.persistence.sourceIndexStatus.c_str());
        if (!s.persistence.sourceChange.empty()) std::fprintf(logFile, "Source change: %s\n", s.persistence.sourceChange.c_str());
        std::fflush(logFile);
    } catch (...) { log("Could not write statistics"); }
}
std::filesystem::path currentPlan() {
    const auto scoped = cache->scopedPlanPath();
    return scoped.empty() ? planPath : scoped;
}
void initializeCache(const std::filesystem::path& prepared) {
    if (planPath.empty()) { cache->finish(); return; }
    if (progressPanel) progressPanel->start();
    LaunchTicket ticket;
    if (!prepared.empty()) ticket.take(prepared);
    cache->initializePersistence(planPath.parent_path(), ticket.claimed);
    log(cache->persistenceStatus().c_str());
    const auto diagnostics = cache->statistics();
    if (!diagnostics.persistence.sourceIndexStatus.empty()) log(diagnostics.persistence.sourceIndexStatus.c_str());
    if (!diagnostics.persistence.sourceChange.empty()) log(diagnostics.persistence.sourceChange.c_str());
    char duration[160]{};
    sprintf_s(duration, "Startup cache initialization took %llu ms on a background thread", diagnostics.initMicroseconds / 1000);
    log(duration);
}
// The game keeps enumerating natively while the source index is validated or
// rebuilt. Doing this inside the game's first directory search would block it
// (and every FindNextFile/FindClose on other threads) until done.
void activate(std::filesystem::path prepared, const char* completed) noexcept {
    const auto finished = [] {
        { std::lock_guard lock(activationMutex); activationFinished = true; }
        activationDone.notify_all();
    };
    try {
        std::thread([prepared = std::move(prepared), completed, finished] {
            try {
                initializeCache(prepared);
                if (!planPath.empty()) cache->startPrefetch(currentPlan());
                log(completed);
            } catch (...) { cache->finish(); log("Startup cache initialization failed; using native enumeration"); }
            finished();
        }).detach();
    } catch (...) { cache->finish(); log("Startup cache thread unavailable; using native enumeration"); finished(); }
}
HANDLE WINAPI first(LPCSTR pattern, LPWIN32_FIND_DATAA result) {
    if (activationPending.load()) {
        try {
            // Physical launch, or MO2 injected USVFS after F4SE loaded plugins.
            // call_once publishes virtualAtLoad before any caller proceeds.
            std::call_once(cacheInitialization, [] {
                virtualAtLoad = virtualAtLoad.load() || GetModuleHandleW(L"usvfs_x64.dll") != nullptr;
                activationPending = false;
                activate({}, "Automatic startup cache initialization complete");
            });
        } catch (...) { cache->finish(); activationPending = false; }
    }
    if (waitingForVirtualizer.load()) {
        // MO2 can inject USVFS after F4SE has loaded its plugins. Physical
        // directory results must never seed the later virtual filesystem view.
        if (!GetModuleHandleW(L"usvfs_x64.dll")) return hooks.originals().first(pattern, result);
        try {
            std::call_once(virtualActivation, [] {
                waitingForVirtualizer = false;
                activate(pendingPrepared, "Prepared virtual filesystem activated after USVFS injection");
            });
        } catch (...) { cache->finish(); waitingForVirtualizer = false; }
    } else if (!virtualAtLoad && !lateVirtualizerStopped.load() && GetModuleHandleW(L"usvfs_x64.dll")) {
        // No bridge context was present. Stop before replaying physical results
        // into an unexpectedly virtualized view, including fresh prefetch rows.
        cache->finish();
        if (!lateVirtualizerStopped.exchange(true)) {
            log("Late USVFS injection without a prepared context; directory acceleration stopped");
        }
    }
    return cache->first(pattern, result);
}
BOOL WINAPI next(HANDLE handle, LPWIN32_FIND_DATAA result) { return cache->next(handle, result); }
// Replaces BSResource::LooseFileLocation::DoGetInfo (vtable slot 7) on verified builds.
uint32_t engineGetInfo(void* location, const char* path, startup::EngineFileInfo* info, void* traverser) {
    return startup::serveGetInfo(*cache, engineHook.original, location, path, info, traverser);
}
BOOL WINAPI close(HANDLE handle) { return cache->close(handle); }
void message(extender::Message* value) noexcept {
    if (!value || !cache) return;
    switch (value->type) {
    case 0:
    case 1:
        if (installed && !hooks.stillInstalled()) {
            log("Enumeration imports changed after installation; new snapshots disabled");
            cache->finish();
        }
        report(value->type == 0 ? "PostLoad" : "PostPostLoad");
        break;
    case 7: report("InputLoaded (before main-menu initialization)"); break;
    case 10:
        if (!value->data) { report("GameDataReady begin"); break; }
        report("GameDataReady complete");
        cache->finishAndSave([](bool saved) { report(saved ? "PersistentSave complete" : "PersistentSave skipped/failed"); });
        if (!planPath.empty()) cache->savePlan(currentPlan());
        log("Startup cache stopped; validated results save in the background if available; open searches can drain");
        break;
    case 2: report("PreLoadGame"); break;
    case 3: report(value->data ? "PostLoadGame success" : "PostLoadGame failure"); break;
    case 8: report("NewGame (not a world-ready timestamp)"); break;
    case 9: report("GameLoaded"); break;
    default: break;
    }
}
std::filesystem::path knownFolder(REFKNOWNFOLDERID id) {
#ifdef STARTUP_LIFECYCLE_TEST
    return std::filesystem::current_path() / (IsEqualGUID(id, FOLDERID_Documents) ? L"test-documents" : L"test-local");
#else
    PWSTR raw = nullptr;
    if (FAILED(SHGetKnownFolderPath(id, 0, nullptr, &raw))) return {};
    std::filesystem::path result(raw);
    CoTaskMemFree(raw);
    return result;
#endif
}
uint64_t pathHash(const std::wstring& path) {
    uint64_t result = 14695981039346656037ULL;
    for (const wchar_t c : path) { result ^= static_cast<uint16_t>(c); result *= 1099511628211ULL; }
    return result;
}
bool compatible(const extender::Interface* api) {
    if (!api || api->editor) return false;
    // Import hooking does not depend on game structures or Address Library IDs.
    // Restrict the game family here; installation still validates all imports.
    wchar_t name[MAX_PATH]{}; GetModuleFileNameW(nullptr, name, MAX_PATH);
    const auto leaf = std::filesystem::path(name).filename().wstring();
    return _wcsicmp(leaf.c_str(), L"Fallout4.exe") == 0 || _wcsicmp(leaf.c_str(), L"Fallout4VR.exe") == 0;
}
// Keep the previous launch's log: a warm launch is only diagnosable next to
// the cache-building launch before it.
FILE* openLog(const std::filesystem::path& directory) {
    const auto current = directory / L"FasterStartup.log", previous = directory / L"FasterStartup.previous.log";
    MoveFileExW(current.c_str(), previous.c_str(), MOVEFILE_REPLACE_EXISTING);
    return _wfsopen(current.c_str(), L"w", _SH_DENYNO);
}
[[maybe_unused]] bool waitForActivation() { // Test hosts only; the game never waits for activation.
    std::unique_lock lock(activationMutex);
    return activationDone.wait_for(lock, std::chrono::seconds(30), [] { return activationFinished; });
}
}

extern "C" __declspec(dllexport) constinit extender::Version F4SEPlugin_Version{
    1, extender::pack(1, 0, 0), "FasterStartup", "Asciimov", 0, 1,
    {extender::pack(1, 10, 980), extender::pack(1, 10, 984), extender::pack(1, 11, 137),
     extender::pack(1, 11, 191), extender::pack(1, 11, 221), extender::pack(1, 11, 240), 0}, 0, 0, 0, {}
};
extern "C" __declspec(dllexport) bool F4SEPlugin_Query(const extender::Interface* api, extender::Info* info) noexcept {
    if (!info) return false;
    *info = {1, "FasterStartup", extender::pack(1, 0, 0)};
    try { return compatible(api); } catch (...) { return false; }
}
extern "C" __declspec(dllexport) bool F4SEPlugin_Load(const extender::Interface* api) noexcept {
    // Once a callback/import points here, the DLL must remain loaded on any error.
    bool retained = false;
    try {
        if (!compatible(api) || !api->query || !api->pluginHandle) return false;
        loadedAt = GetTickCount64();
        FILETIME creation{}, exit{}, kernel{}, user{};
        if (GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) processCreation = fileTime(creation);
        wchar_t executable[32768]{};
        if (!GetModuleFileNameW(nullptr, executable, 32768)) return false;
        const auto game = std::filesystem::path(executable).parent_path();
        const bool vr = _wcsicmp(std::filesystem::path(executable).filename().c_str(), L"Fallout4VR.exe") == 0;
        auto documents = knownFolder(FOLDERID_Documents);
        if (!documents.empty()) {
            auto logs = documents / L"My Games" / (vr ? L"Fallout4VR" : L"Fallout4") / L"F4SE";
            std::error_code error; std::filesystem::create_directories(logs, error);
            logFile = openLog(logs);
        }
        log("Faster Startup 1.0.0; background validation; interval MO2 view checks; journal checkpoints; engine file information");
        const auto ini = game / L"Data/F4SE/Plugins/FasterStartup.ini";
        const auto setting = [&](const wchar_t* key, unsigned fallback) {
            return GetPrivateProfileIntW(L"Startup", key, fallback, ini.c_str());
        };
        startup::Options options;
        options.enabled = setting(L"Enabled", 1) != 0;
        wchar_t disabled[2]{};
        if (GetEnvironmentVariableW(L"FASTER_STARTUP_DISABLE", disabled, 2) == 1 && disabled[0] == L'1') {
            options.enabled = false;
            log("Disabled by FASTER_STARTUP_DISABLE=1 (native baseline)");
        }
        options.largeFetch = setting(L"LargeFetch", 1) != 0;
        options.workers = std::min(setting(L"PrefetchThreads", 2), 4u);
        options.maxBytes = static_cast<size_t>(std::clamp(setting(L"CacheMiB", 256), 1u, 512u)) * 1024 * 1024;
        options.maxDirectories = std::clamp(setting(L"MaxDirectories", 8192), 16u, 65536u);
        options.prefetchWindowMs = std::clamp(setting(L"PrefetchWindowMs", 20000), 100u, 120000u);
        options.allowVirtualSnapshot = setting(L"AllowVirtualSnapshot", 0) != 0;
        options.persistent = setting(L"PersistentCache", 1) != 0;
        options.viewCheckMs = std::min(setting(L"ViewCheckMs", 1000), 60000u);
        options.checkpointMinutes = std::min(setting(L"CheckpointMinutes", 10), 1440u);
        if (!options.enabled) { log("Startup acceleration disabled"); return true; }
        if (options.persistent && setting(L"ShowProgress", 1) != 0) {
            options.progress = std::make_shared<startup::ProgressState>();
            progressPanel = new startup::ProgressPanel(options.progress);
        }

        std::string error;
        if (!hooks.inspect(GetModuleHandleW(nullptr), error)) { log(error.c_str()); return false; }
        wchar_t prepared[32768]{};
        const DWORD length = GetEnvironmentVariableW(L"FASTER_STARTUP_CONTEXT", prepared, 32768);
        const bool hasPrepared = length > 0 && length < 32768;
        const bool virtualizerLoaded = GetModuleHandleW(L"usvfs_x64.dll") != nullptr;
        options.virtualized = virtualizerLoaded || hasPrepared || !hooks.originalsAreSystemApis();
        virtualAtLoad = options.virtualized;
        if (hasPrepared) pendingPrepared = prepared;
        waitingForVirtualizer = hasPrepared && !virtualizerLoaded;
        if (waitingForVirtualizer) log("Prepared context received before USVFS injection; deferring cache activation");
        if (options.virtualized) log("Virtual/hooked filesystem detected; automatic MO2 view validation enabled");

        auto local = knownFolder(FOLDERID_LocalAppData);
        if (!local.empty()) {
            std::wostringstream identity; identity << std::hex << pathHash(game.wstring());
            const auto state = local / L"FasterStartup" / identity.str();
            std::error_code createError; std::filesystem::create_directories(state, createError);
            if (!createError) planPath = state / L"startup.plan";
        }
        cache = new startup::DirectoryCache((game / L"Data").string(), hooks.originals(), options);
        // MO2 normally injects USVFS before F4SE loads plugins; validation can
        // then start now, overlapping the engine's own early startup. Otherwise
        // wait for the first search, so a late injection is still detected.
        const bool startNow = hasPrepared ? !waitingForVirtualizer : virtualizerLoaded;
        activationPending = !hasPrepared && !virtualizerLoaded;
        if (activationPending) log("Cache activation deferred until first directory search");
        const auto messaging = static_cast<extender::Messaging*>(api->query(1));
        if (!messaging || messaging->version < 1 || !messaging->listen ||
            !messaging->listen(api->pluginHandle(), "F4SE", &message)) {
            log("F4SE messaging unavailable; no hooks installed"); delete cache; cache = nullptr; return false;
        }
        retained = true;
        if (!hooks.install({reinterpret_cast<void*>(&first), reinterpret_cast<void*>(&next), reinterpret_cast<void*>(&close)}, error)) {
            activationPending = false; cache->finish(); log(error.c_str()); return true;
        }
        installed = true;
        log("Executable FindFirstFileA / FindNextFileA / FindClose imports installed");
        if (setting(L"EngineFileInfo", 1) != 0) {
            std::string engineError;
            if (engineHook.install(GetModuleHandleW(nullptr), &engineGetInfo, startup::EngineInfoHook::knownBuilds(), engineError)) {
                log((std::string("Loose-file information served from validated listings (engine hook, ") + engineHook.build + ")").c_str());
                // Diagnostic: every Nth answer is also asked of the engine, which costs its file opens again.
                if (const auto every = setting(L"EngineFileInfoVerify", 0)) {
                    startup::verifyEngineInfo(every);
                    log(("Engine answers compared for every " + std::to_string(every) + ". query (diagnostic; slower startup)").c_str());
                }
            } else log(("Loose-file information hook not installed: " + engineError).c_str());
        }
        if (startNow) {
            log("Cache validation started in the background; searches stay native until it completes");
            activate(pendingPrepared, hasPrepared ? "Prepared virtual filesystem activated" : "Automatic startup cache initialization complete");
        }
        report("PluginLoaded");
        return true;
    } catch (...) {
        activationPending = false;
        if (cache) cache->finish();
        log("Initialization failed; acceleration disabled");
        return retained;
    }
}
