#include "EngineInfoHook.h"
#include "DirectoryCache.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

namespace startup {
namespace {
constexpr char typeName[] = ".?AVLooseFileLocation@BSResource@@";
// Verified by disassembly of each executable: vtable of
// BSResource::LooseFileLocation and its slot-7 DoGetInfo(path, info, traverser).
constexpr EngineBuild builds[] = {
    {"OG 1.10.163", 0x5ddc40fa, 0x6cb9000, 0x2c5bbd8, 0x1b84690},
    {"NG 1.10.984", 0x6632e5c3, 0x4047000, 0x2285a28, 0x1592b40},
    {"AE 1.11.191", 0x693a1a4c, 0x4243000, 0x24714a8, 0x16ad6c0},
    {"AE 1.11.221", 0x69e2a744, 0x4244000, 0x24714a8, 0x16ad7e0},
    {"AE 1.11.240", 0x6a727fcc, 0x425a000, 0x2479508, 0x16adbe0},
    {"VR 1.2.72", 0x5aec0db0, 0x6e5f000, 0x2c92838, 0x1c03aa0},
};
template <class T> bool readValue(const unsigned char* base, size_t size, size_t rva, T& value) noexcept {
    if (rva > size || sizeof(T) > size - rva) return false;
    std::memcpy(&value, base + rva, sizeof(T));
    return true;
}
bool writablePointer(void** slot, void* expected, void* replacement, std::string& error) noexcept {
    MEMORY_BASIC_INFORMATION region{};
    if (VirtualQuery(slot, &region, sizeof(region)) != sizeof(region) || region.State != MEM_COMMIT ||
        (region.Protect & (PAGE_GUARD | PAGE_NOACCESS))) { error = "vtable page is not accessible"; return false; }
    constexpr DWORD writable = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    constexpr DWORD executable = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    DWORD old{}, ignored{};
    const bool change = !(region.Protect & writable);
    if (change && !VirtualProtect(slot, sizeof(void*), (region.Protect & executable) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &old)) {
        error = "vtable protection could not be changed"; return false;
    }
    const auto previous = InterlockedCompareExchangePointer(slot, replacement, expected);
    if (change) VirtualProtect(slot, sizeof(void*), old, &ignored);
    if (previous != expected) { error = "vtable slot changed concurrently"; return false; }
    return true;
}
// Plain data only: SEH guards the engine-layout reads.
std::atomic<uint64_t> unresolved{0}, engineTicks{0};
// Diagnostic (EngineFileInfoVerify): also ask the engine for every Nth answer and compare.
std::atomic<uint32_t> verifyEvery{0};
std::atomic<uint64_t> verifyCounter{0}, verifyChecked{0}, verifyMismatches{0};
std::mutex verifyMutex;
std::vector<std::string> verifySamples;
bool verifying() noexcept {
    const uint32_t every = verifyEvery.load(std::memory_order_relaxed);
    return every && verifyCounter.fetch_add(1, std::memory_order_relaxed) % every == 0;
}
// served == nullptr: the cache answered "absent". The traverser is not passed,
// so the engine's own call records nothing.
void verify(EngineInfoHook::GetInfo original, void* location, const char* path, const EngineFileInfo* served) noexcept {
    EngineFileInfo engine{};
    const uint32_t result = original(location, path, &engine, nullptr);
    const bool same = served ? result == 0 && std::memcmp(&engine, served, sizeof(engine)) == 0 : result != 0;
    verifyChecked.fetch_add(1, std::memory_order_relaxed);
    if (same) return;
    verifyMismatches.fetch_add(1, std::memory_order_relaxed);
    try {
        char text[3 * MAX_PATH];
        const auto time = [](FILETIME value) { return (uint64_t(value.dwHighDateTime) << 32) | value.dwLowDateTime; };
        if (served) {
            sprintf_s(text, "found %s: served write=%llu create=%llu size=%llu; engine result=%u write=%llu create=%llu size=%llu",
                path, time(served->modifyTime), time(served->createTime), served->fileSize,
                result, time(engine.modifyTime), time(engine.createTime), engine.fileSize);
        } else {
            sprintf_s(text, "absent %s: engine result=%u size=%llu", path, result, engine.fileSize);
        }
        std::lock_guard lock(verifyMutex);
        if (verifySamples.size() < 20) verifySamples.emplace_back(text);
    } catch (...) {}
}
uint32_t timedOriginal(EngineInfoHook::GetInfo original, void* location, const char* path,
    EngineFileInfo* info, void* traverser) noexcept {
    LARGE_INTEGER begin{}, end{};
    QueryPerformanceCounter(&begin);
    const uint32_t result = original(location, path, info, traverser);
    QueryPerformanceCounter(&end);
    engineTicks.fetch_add(static_cast<uint64_t>(end.QuadPart - begin.QuadPart), std::memory_order_relaxed);
    return result;
}
bool readPrefix(const unsigned char* location, char* output, size_t capacity) noexcept {
    __try {
        // BSFixedString -> BSStringPool entry: flags at +8 (bit 14: shallow copy of
        // the entry at +0x10), inline text at +0x18. Mirrors BSFixedString::QString.
        auto entry = *reinterpret_cast<const unsigned char* const*>(location + 0x10);
        for (int depth = 0; entry && depth < 4; ++depth) {
            if (*reinterpret_cast<const uint32_t*>(entry + 8) & (1u << 14)) {
                entry = *reinterpret_cast<const unsigned char* const*>(entry + 0x10);
                continue;
            }
            const char* text = reinterpret_cast<const char*>(entry + 0x18);
            size_t length = 0;
            while (length < capacity && text[length]) ++length;
            if (!length || length >= capacity) return false;
            std::memcpy(output, text, length + 1);
            return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
}

std::span<const EngineBuild> EngineInfoHook::knownBuilds() noexcept { return builds; }

bool EngineInfoHook::install(HMODULE game, GetInfo replacement, std::span<const EngineBuild> table, std::string& error) noexcept {
    if (!game || !replacement) { error = "No game image or replacement"; return false; }
    const auto base = reinterpret_cast<const unsigned char*>(game);
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 4096) { error = "Invalid DOS header"; return false; }
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { error = "Unsupported PE image"; return false; }
    const size_t size = nt->OptionalHeader.SizeOfImage;
    const EngineBuild* match = nullptr;
    for (const auto& candidate : table)
        if (candidate.timestamp == nt->FileHeader.TimeDateStamp && candidate.sizeOfImage == size) match = &candidate;
    if (!match) { error = "Game build not verified for the engine GetInfo hook"; return false; }
    // The vtable's complete object locator must describe BSResource::LooseFileLocation.
    uint64_t locator{};
    uint32_t signature{}, offset{}, descriptorRva{}, selfRva{};
    if (!readValue(base, size, match->vtableRva - 8, locator) || locator < reinterpret_cast<uint64_t>(base) ||
        locator - reinterpret_cast<uint64_t>(base) >= size) { error = "vtable locator outside image"; return false; }
    const size_t locatorRva = static_cast<size_t>(locator - reinterpret_cast<uint64_t>(base));
    if (!readValue(base, size, locatorRva, signature) || !readValue(base, size, locatorRva + 4, offset) ||
        !readValue(base, size, locatorRva + 12, descriptorRva) || !readValue(base, size, locatorRva + 20, selfRva) ||
        signature != 1 || offset != 0 || selfRva != locatorRva || descriptorRva + 16 + sizeof(typeName) > size ||
        std::memcmp(base + descriptorRva + 16, typeName, sizeof(typeName)) != 0) {
        error = "vtable RTTI is not BSResource::LooseFileLocation"; return false;
    }
    const auto slot = reinterpret_cast<void**>(const_cast<unsigned char*>(base) + match->vtableRva) + getInfoSlot;
    const auto current = reinterpret_cast<uintptr_t>(*slot);
    if (current != reinterpret_cast<uintptr_t>(base) + match->getInfoRva) {
        error = "GetInfo slot already replaced or unexpected"; return false;
    }
    original = reinterpret_cast<GetInfo>(current);
    if (!writablePointer(slot, reinterpret_cast<void*>(current), reinterpret_cast<void*>(replacement), error)) {
        original = nullptr; return false;
    }
    build = match->name; installed = true;
    return true;
}

bool locationPrefix(const void* location, char* output, size_t capacity) noexcept {
    return location && output && capacity > 1 && readPrefix(static_cast<const unsigned char*>(location), output, capacity);
}
void notifyTraverser(void* traverser, const char* path, void* location) noexcept {
    using Found = void (*)(void*, const char*, void*);
    (*reinterpret_cast<Found* const*>(traverser))[1](traverser, path, location);
}
uint32_t serveGetInfo(DirectoryCache& cache, EngineInfoHook::GetInfo original,
    void* location, const char* path, EngineFileInfo* info, void* traverser) noexcept {
    if (cache.active() && path && info) {
        char full[2 * MAX_PATH];
        if (locationPrefix(location, full, MAX_PATH)) {
            size_t length = std::strlen(full);
            for (const char* c = path; *c && length + 1 < sizeof(full); ++c) full[length++] = *c == '/' ? '\\' : *c;
            if (length + 1 < sizeof(full)) {
                full[length] = 0;
                WIN32_FIND_DATAA data{};
                switch (cache.fileInfo(full, data)) {
                case FileInfoResult::found:
                    info->modifyTime = data.ftLastWriteTime;
                    info->createTime = data.ftCreationTime;
                    info->fileSize = (uint64_t(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
                    if (verifying()) verify(original, location, path, info);
                    if (traverser) notifyTraverser(traverser, path, location);
                    return 0;
                case FileInfoResult::absent:
                    if (verifying()) verify(original, location, path, nullptr);
                    return 1;
                case FileInfoResult::unknown:
                    return timedOriginal(original, location, path, info, traverser);
                }
            }
        }
        unresolved.fetch_add(1, std::memory_order_relaxed);
        return timedOriginal(original, location, path, info, traverser);
    }
    return original(location, path, info, traverser);
}
uint64_t unresolvedInfoQueries() noexcept { return unresolved.load(std::memory_order_relaxed); }
void verifyEngineInfo(uint32_t every) noexcept { verifyEvery.store(every, std::memory_order_relaxed); }
EngineInfoVerification engineInfoVerification() {
    std::lock_guard lock(verifyMutex);
    return {verifyChecked.load(), verifyMismatches.load(), verifySamples};
}
uint64_t engineInfoMicroseconds() noexcept {
    LARGE_INTEGER frequency{}; QueryPerformanceFrequency(&frequency);
    return frequency.QuadPart ? engineTicks.load(std::memory_order_relaxed) * 1000000 / frequency.QuadPart : 0;
}
}
