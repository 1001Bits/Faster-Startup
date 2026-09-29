#pragma once
#include <Windows.h>
#include "Progress.h"
#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace startup {
using Digest = std::array<uint8_t, 32>;
struct PersistentRow {
    std::string pattern;
    std::vector<WIN32_FIND_DATAA> entries;
};
struct PersistentRowView {
    std::string_view pattern;
    std::span<const WIN32_FIND_DATAA> entries;
};
struct PersistenceMetrics {
    uint64_t scannedDirectories{}, journalRecords{}, loadedDirectories{}, savedDirectories{};
    uint64_t loadMicroseconds{}, saveMicroseconds{};
    bool reusedProof{};
    std::string sourceIndexStatus, sourceChange;
};
struct ScopeRequest {
    std::wstring virtualRoot;
    std::string context; // An authoritative view identifier; empty for physical Data.
    std::vector<std::wstring> sourceRoots;
};
struct PersistenceLimits {
    size_t maxSnapshotBytes = 256 * 1024 * 1024;
    size_t maxDirectories = 8192;
    size_t maxJournalBytes = 64 * 1024 * 1024;
    unsigned maxJournalMs = 2000;
    size_t maxSourceObjects = 16 * 1024 * 1024;
};

// Source identity uses physical volume paths even inside a virtualized process.
// Unprivileged NTFS journals validate the file-ID set, including hard links.
// Prepared proofs remain available for legacy tools; the plugin discovers MO2 automatically.
class PersistentStore {
public:
    explicit PersistentStore(PersistenceLimits limits = {}, std::shared_ptr<ProgressState> progress = {});
    ~PersistentStore();
    PersistentStore(const PersistentStore&) = delete;
    PersistentStore& operator=(const PersistentStore&) = delete;

    bool prepare(const ScopeRequest& request, const std::filesystem::path& proofFile) noexcept;
    bool adoptPrepared(const std::wstring& virtualRoot, const std::filesystem::path& proofFile) noexcept;
    bool writePrepared(const std::filesystem::path& proofFile) noexcept;
    bool startWatching() noexcept;
    bool pollChanged() noexcept;
    bool validate() noexcept;
    // Revalidates the journal tail and rewrites the source index with the new
    // cursor. After a successful save only; false once a tracked source changed.
    bool checkpoint() noexcept;
    bool load(const std::filesystem::path& cacheFile,
        const std::function<bool(PersistentRow&&)>& accept) noexcept;
    bool save(const std::filesystem::path& cacheFile, std::span<const PersistentRowView> rows) noexcept;
    const std::string& status() const noexcept;
    const PersistenceMetrics& metrics() const noexcept;
    const std::string& context() const noexcept;
    const Digest& generation() const noexcept;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

std::wstring decodeUtf8(std::string_view text);
std::string encodeUtf8(std::wstring_view text);
std::string digestHex(std::span<const uint8_t> bytes);
std::string contextKey(std::string_view text);
ScopeRequest readScopeRequest(const std::filesystem::path& file);
}
