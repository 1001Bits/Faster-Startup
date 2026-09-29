#pragma once
#include <Windows.h>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace startup {
// Fallout 4 registers every loose audio file at startup through
// BSResource::LooseFileLocation::DoGetInfo, which opens each file only to read
// its write/create time and size. Under MO2's VFS (and on-access antivirus
// scanning) each open costs milliseconds. This replaces that one virtual slot
// so answers can come from validated directory listings instead.
//
// Only builds whose layout was checked in Ghidra are hooked: the executable's
// PE timestamp and image size select the vtable and original function, and the
// vtable's RTTI must name BSResource::LooseFileLocation.
struct EngineBuild {
    const char* name;
    uint32_t timestamp, sizeOfImage;
    uint32_t vtableRva, getInfoRva;
};
// Result layout written by the engine: modify time, create time, size.
struct EngineFileInfo {
    FILETIME modifyTime;
    FILETIME createTime;
    uint64_t fileSize;
};
static_assert(sizeof(EngineFileInfo) == 0x18);

class EngineInfoHook {
public:
    // (location, path, info, traverser) -> 0 on success, 1 when the file cannot be opened.
    using GetInfo = uint32_t (*)(void* location, const char* path, EngineFileInfo* info, void* traverser);
    static std::span<const EngineBuild> knownBuilds() noexcept;
    bool install(HMODULE game, GetInfo replacement, std::span<const EngineBuild> builds, std::string& error) noexcept;
    GetInfo original = nullptr;
    const char* build = nullptr;
    bool installed = false;
    static constexpr size_t getInfoSlot = 7;
};

// The location's path prefix (BSFixedString at +0x10). False on any unexpected
// layout or access fault; the caller then defers to the engine.
bool locationPrefix(const void* location, char* output, size_t capacity) noexcept;
// Calls the engine's LocationTraverser callback (vtable slot 1) as DoGetInfo does.
void notifyTraverser(void* traverser, const char* path, void* location) noexcept;

class DirectoryCache;
// Body of the replacement: prefix + path (separators as the engine translates
// them) looked up in validated listings. A found file fills the engine's info
// and notifies the traverser exactly as a successful open would (returns 0); a
// name absent from a complete listing returns 1 like a failed open; anything
// else calls the engine's original.
uint32_t serveGetInfo(DirectoryCache& cache, EngineInfoHook::GetInfo original,
    void* location, const char* path, EngineFileInfo* info, void* traverser) noexcept;
// Queries passed to the engine before reaching the cache (unreadable prefix, overlong path).
uint64_t unresolvedInfoQueries() noexcept;
// Time spent in the engine's own GetInfo for queries the cache could not answer.
uint64_t engineInfoMicroseconds() noexcept;
// Diagnostic: also ask the engine for every Nth answer (0 = off) and compare.
void verifyEngineInfo(uint32_t every) noexcept;
struct EngineInfoVerification { uint64_t checked{}, mismatches{}; std::vector<std::string> samples; };
EngineInfoVerification engineInfoVerification();
}
