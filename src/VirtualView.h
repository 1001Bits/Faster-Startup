#pragma once
#include "Persistence.h"
#include <atomic>

namespace startup {
// Parses the public USVFS diagnostic representation. Unknown/ambiguous paths fail closed.
ScopeRequest virtualScope(std::string_view dump, const std::wstring& dataRoot);

// Read-only byte guard for a named page-file-backed section. It deliberately
// understands no USVFS/Boost layout: any byte change requires full validation.
class MappingSnapshot {
public:
    explicit MappingSnapshot(const std::string& name);
    ~MappingSnapshot();
    MappingSnapshot(const MappingSnapshot&) = delete;
    MappingSnapshot& operator=(const MappingSnapshot&) = delete;
    void capture();
    bool unchanged() const noexcept;
    size_t bytes() const noexcept { return saved_.size(); }
private:
    HANDLE section_{};
    const void* view_{};
    std::vector<unsigned char> saved_;
    bool captured_{};
};

class VirtualView {
public:
    static std::shared_ptr<VirtualView> attach(const std::wstring& dataRoot,
        const std::filesystem::path& state, const std::string& instance = "mod_organizer_instance");
    ~VirtualView();
    const ScopeRequest& scope() const noexcept { return scope_; }
    // One validation (game thread): the mapping matches the scope and stayed
    // stable while it was read.
    bool unchanged() noexcept;
    // Background threads only: like unchanged(), but while the mapping matches
    // yet keeps changing during the read, or cannot be read, retry until it
    // settles or timeoutMs passes. A mapping that differs fails at once.
    // On failure, *problem says which of these happened.
    bool settled(unsigned timeoutMs, std::string* problem = nullptr) noexcept;
    uint64_t checks() const noexcept { return checks_; }
    uint64_t microseconds() const noexcept { return microseconds_; }
    uint64_t dumps() const noexcept;
    uint64_t guardBytes() const noexcept;
private:
    enum class Check { same, changed, busy, failed };
    Check check(std::string* error = nullptr) noexcept;
    struct Impl;
    VirtualView();
    std::unique_ptr<Impl> impl_;
    ScopeRequest scope_;
    std::atomic<uint64_t> checks_{0}, microseconds_{0};
};
}
