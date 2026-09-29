#include "VirtualView.h"
#include "NativeScope.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <set>
#include <stdexcept>

namespace startup {
namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::wstring normalized(std::wstring path) {
    std::replace(path.begin(), path.end(), L'/', L'\\');
    while (path.size() > 3 && path.back() == L'\\') path.pop_back();
    require(path.size() >= 3 && path[1] == L':' && path[2] == L'\\' &&
        path.find_first_of(L"*?\r\n") == std::wstring::npos, "Unsupported USVFS source path");
    return path;
}
bool equal(std::wstring_view a, std::wstring_view b) {
    return a.size() == b.size() && CompareStringOrdinal(a.data(), static_cast<int>(a.size()),
        b.data(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}
std::string fileHash(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    require(bool(input), "Cannot read installed USVFS module");
    const auto size = input.tellg();
    require(size > 0 && size < 64 * 1024 * 1024, "USVFS module size unsupported");
    std::string bytes(static_cast<size_t>(size), '\0'); input.seekg(0);
    require(bool(input.read(bytes.data(), size)), "USVFS module read incomplete");
    return contextKey(bytes);
}
std::set<std::string> mappedNames() {
    // USVFS uses page-file-backed named sections, not mapped disk files.
    // Inspect only handles already owned by this process; no other process is opened.
    struct HandleEntry { HANDLE handle; uintptr_t handles, pointers; ULONG access, type, attributes, reserved; };
    struct Snapshot { uintptr_t count, reserved; HandleEntry entries[1]; };
    struct Text { USHORT length, maximum; wchar_t* data; };
    static_assert(sizeof(HandleEntry) == 40 && offsetof(Snapshot, entries) == 16);
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    auto queryProcess = reinterpret_cast<LONG (NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*)>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
    auto queryObject = reinterpret_cast<LONG (NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*)>(GetProcAddress(ntdll, "NtQueryObject"));
    require(queryProcess && queryObject, "Process section-query API unavailable");
    std::vector<uint8_t> storage(65536), object(65536);
    bool complete = false;
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        ULONG needed{};
        const LONG status = queryProcess(GetCurrentProcess(), 51, storage.data(), static_cast<ULONG>(storage.size()), &needed);
        if (status >= 0) { complete = true; break; }
        require((status == static_cast<LONG>(0xc0000004) || status == static_cast<LONG>(0xc0000023)) &&
            needed < 16 * 1024 * 1024, "Cannot inspect this process's section handles");
        storage.resize(std::max<size_t>(needed + 4096, storage.size() * 2));
    }
    require(complete, "Process handle snapshot did not stabilize");
    const auto snapshot = reinterpret_cast<const Snapshot*>(storage.data());
    require(snapshot->count <= (storage.size() - offsetof(Snapshot, entries)) / sizeof(HandleEntry), "Invalid process handle snapshot");
    std::set<std::string> names;
    const auto text = [&]() -> std::wstring_view {
        const auto value = reinterpret_cast<const Text*>(object.data());
        if (!value->length) return {};
        const auto begin = reinterpret_cast<uintptr_t>(value->data), base = reinterpret_cast<uintptr_t>(object.data());
        require(value->length % 2 == 0 && begin >= base && begin <= base + object.size() &&
            value->length <= base + object.size() - begin, "Invalid section name response");
        return {value->data, value->length / sizeof(wchar_t)};
    };
    for (uintptr_t i = 0; i < snapshot->count; ++i) {
        HANDLE handle{};
        if (!DuplicateHandle(GetCurrentProcess(), snapshot->entries[i].handle, GetCurrentProcess(), &handle, 0, FALSE, DUPLICATE_SAME_ACCESS)) continue;
        try {
            ULONG needed{};
            if (queryObject(handle, 2, object.data(), static_cast<ULONG>(object.size()), &needed) >= 0 && text() == L"Section" &&
                queryObject(handle, 1, object.data(), static_cast<ULONG>(object.size()), &needed) >= 0) {
                const auto value = text();
                if (!value.empty()) names.insert(encodeUtf8(std::filesystem::path(value).filename().wstring()));
            }
        } catch (...) { CloseHandle(handle); throw; }
        CloseHandle(handle);
    }
    return names;
}
// Extract only the Data subtree; F4SE/Root contents always enumerate natively.
// Keep boundary mappings themselves because Data/* can return them.
struct Relevant { std::string bytes; std::vector<std::pair<std::wstring, std::wstring>> rows; };
Relevant relevant(std::string_view dump, const std::wstring& dataRoot, bool collect) {
    require(dump.size() <= 256ULL * 1024 * 1024, "USVFS mapping exceeds budget");
    const auto root = normalized(dataRoot);
    std::vector<std::wstring> stack;
    Relevant result;
    size_t rootDepth = SIZE_MAX, skipDepth = SIZE_MAX;
    bool found = false;
    for (size_t offset = 0; offset < dump.size();) {
        const auto end = dump.find('\n', offset);
        require(end != std::string_view::npos, "Truncated USVFS mapping line");
        const auto line = dump.substr(offset, end - offset); offset = end + 1;
        if (line == " -> ") { stack.clear(); continue; }
        const auto depth = line.find_first_not_of(' ');
        require(depth != std::string_view::npos && depth < 256, "Invalid USVFS mapping depth");
        if (found && depth <= rootDepth) break;
        if (skipDepth != SIZE_MAX) {
            if (depth > skipDepth) continue;
            skipDepth = SIZE_MAX;
        }
        const auto separator = line.find(" -> ", depth);
        require(separator != std::string_view::npos && line.find(" -> ", separator + 4) == std::string_view::npos,
            "Ambiguous USVFS mapping line");
        if (found && !collect) {
            result.bytes.append(line); result.bytes.push_back('\n');
            const auto name = line.substr(depth, separator - depth);
            if (depth == rootDepth + 1 && nativeRoot(name)) skipDepth = depth;
            continue;
        }
        require(depth > 0 && depth <= stack.size() + 1, "Invalid USVFS mapping hierarchy");
        const auto name = decodeUtf8(line.substr(depth, separator - depth));
        require(!name.empty() && name.front() != L' ' && name.back() != L' ' &&
            name != L"." && name != L".." && name.find_first_of(L"\\/\r\n") == std::wstring::npos,
            "Unsupported USVFS virtual name");
        stack.resize(depth - 1); stack.push_back(name);
        if (!found) {
            std::wstring path;
            for (const auto& part : stack) { if (!path.empty()) path += L'\\'; path += part; }
            if (!equal(path, root)) continue;
            found = true; rootDepth = depth;
        }
        result.bytes.append(line); result.bytes.push_back('\n');
        std::wstring relative;
        for (size_t i = rootDepth; i < stack.size(); ++i) {
            if (!relative.empty()) relative += L'\\'; relative += stack[i];
        }
        if (depth == rootDepth + 1 && nativeRoot(std::wstring_view(name))) { skipDepth = depth; continue; }
        if (collect) {
            const auto sourceText = line.substr(separator + 4);
            require(!sourceText.empty(), "USVFS asset mapping has no source");
            result.rows.emplace_back(std::move(relative), normalized(decodeUtf8(sourceText)));
        }
    }
    require(found && !result.bytes.empty(), "Current USVFS view has no matching game Data root");
    return result;
}
}

MappingSnapshot::MappingSnapshot(const std::string& name) {
    try {
        section_ = OpenFileMappingA(FILE_MAP_READ, FALSE, name.c_str());
        require(section_ != nullptr, "Cannot open existing MO2 mapping section");
        view_ = MapViewOfFile(section_, FILE_MAP_READ, 0, 0, 0);
        require(view_ != nullptr, "Cannot map MO2 section read-only");
        MEMORY_BASIC_INFORMATION region{}, following{};
        require(VirtualQuery(view_, &region, sizeof(region)) == sizeof(region) &&
            region.BaseAddress == view_ && region.AllocationBase == view_ &&
            region.State == MEM_COMMIT && region.Type == MEM_MAPPED &&
            region.Protect == PAGE_READONLY && region.RegionSize >= 4096 &&
            region.RegionSize <= 512ULL * 1024 * 1024,
            "MO2 mapping section is outside the guard budget");
        require(VirtualQuery(static_cast<const char*>(view_) + region.RegionSize, &following, sizeof(following)) == sizeof(following) &&
            following.AllocationBase != view_, "MO2 section has unsupported multiple regions");
        saved_.resize(region.RegionSize);
    } catch (...) {
        if (view_) UnmapViewOfFile(view_);
        if (section_) CloseHandle(section_);
        throw;
    }
}
MappingSnapshot::~MappingSnapshot() {
    if (view_) UnmapViewOfFile(view_);
    if (section_) CloseHandle(section_);
}
void MappingSnapshot::capture() {
    std::memcpy(saved_.data(), view_, saved_.size());
    captured_ = true;
}
bool MappingSnapshot::unchanged() const noexcept {
    return captured_ && std::memcmp(saved_.data(), view_, saved_.size()) == 0;
}

ScopeRequest virtualScope(std::string_view dump, const std::wstring& dataRoot) {
    auto parsed = relevant(dump, dataRoot, true);
    ScopeRequest scope{normalized(dataRoot), "usvfs-auto-v1:" + contextKey(parsed.bytes), {normalized(dataRoot)}};
    std::set<std::wstring> roots;
    for (const auto& [relative, source] : parsed.rows) {
        if (relative.empty()) { roots.insert(source); continue; }
        // Ordinary MO2 mod roots preserve Data-relative paths. Reject custom
        // renaming mappings until their source boundaries can be validated.
        require(source.size() > relative.size() && source[source.size() - relative.size() - 1] == L'\\' &&
            equal(std::wstring_view(source).substr(source.size() - relative.size()), relative),
            "USVFS mapping does not preserve its Data-relative source path");
        roots.insert(source.substr(0, source.size() - relative.size() - 1));
    }
    require(roots.size() < 2048, "Too many automatic MO2 source roots");
    scope.sourceRoots.insert(scope.sourceRoots.end(), roots.begin(), roots.end());
    return scope;
}

struct VirtualView::Impl {
    HMODULE module{};
    using Dump = BOOL (WINAPI*)(LPSTR, size_t*);
    Dump dump{};
    void (WINAPI* disconnect)(){};
    void (WINAPI* currentName)(char*, size_t){};
    bool connected{};
    std::vector<char> buffer;
    std::unique_ptr<MappingSnapshot> guard;
    std::string guardName;
    bool guardValidated{};
    std::atomic<uint64_t> dumps{0}, guardBytes{0};
    ~Impl() {
        guard.reset();
        if (connected && disconnect) disconnect();
        if (module) FreeLibrary(module);
    }
    std::string_view read() {
        if (buffer.empty()) buffer.resize(1024 * 1024);
        for (unsigned attempt = 0; attempt < 3; ++attempt) {
            size_t size = buffer.size();
            ++dumps;
            const bool ok = dump(buffer.data(), &size) != FALSE;
            require(size < 256ULL * 1024 * 1024, "USVFS mapping exceeds memory budget");
            if (ok && size < buffer.size() && buffer[size] == '\0') return {buffer.data(), size};
            buffer.resize(size + 1);
        }
        throw std::runtime_error("USVFS mapping changed while reading");
    }
    std::string name() {
        char value[256]{};
        currentName(value, sizeof(value));
        require(value[0] && value[sizeof(value) - 1] == '\0', "Invalid current MO2 section name");
        return value;
    }
};
VirtualView::VirtualView() : impl_(std::make_unique<Impl>()) {}
VirtualView::~VirtualView() = default;
std::shared_ptr<VirtualView> VirtualView::attach(const std::wstring& dataRoot, const std::filesystem::path& state,
    const std::string& instance) {
    auto view = std::shared_ptr<VirtualView>(new VirtualView);
    const auto injected = GetModuleHandleW(L"usvfs_x64.dll");
    require(injected != nullptr, "USVFS not active yet");
    const auto names = mappedNames();
    require(names.contains(instance), "Unrecognized MO2 shared-memory session");
    wchar_t path[32768]{};
    require(GetModuleFileNameW(injected, path, 32768) != 0, "Cannot locate installed USVFS");
    const auto hash = fileHash(path);
    const auto readerPath = state / ("usvfs-reader-" + hash + ".dll");
    if (!CopyFileW(path, readerPath.c_str(), TRUE))
        require(GetLastError() == ERROR_FILE_EXISTS && fileHash(readerPath) == hash, "Cannot prepare in-process USVFS reader");
    auto& reader = *view->impl_;
    reader.module = LoadLibraryExW(readerPath.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    require(reader.module && reader.module != injected, "Cannot load in-process USVFS reader");
    auto create = reinterpret_cast<void* (*)()>(GetProcAddress(reader.module, "usvfsCreateParameters"));
    auto setName = reinterpret_cast<void (*)(void*, const char*)>(GetProcAddress(reader.module, "usvfsSetInstanceName"));
    auto freeParams = reinterpret_cast<void (*)(void*)>(GetProcAddress(reader.module, "usvfsFreeParameters"));
    auto connect = reinterpret_cast<BOOL (WINAPI*)(const void*)>(GetProcAddress(reader.module, "usvfsConnectVFS"));
    auto processes = reinterpret_cast<BOOL (WINAPI*)(size_t*, LPDWORD)>(GetProcAddress(reader.module, "usvfsGetVFSProcessList"));
    reader.currentName = reinterpret_cast<void (WINAPI*)(char*, size_t)>(GetProcAddress(reader.module, "usvfsGetCurrentVFSName"));
    reader.dump = reinterpret_cast<Impl::Dump>(GetProcAddress(reader.module, "usvfsCreateVFSDump"));
    reader.disconnect = reinterpret_cast<void (WINAPI*)()>(GetProcAddress(reader.module, "usvfsDisconnectVFS"));
    require(create && setName && freeParams && connect && processes && reader.currentName && reader.dump && reader.disconnect,
        "Installed USVFS controller API is unsupported");
    void* params = create(); require(params != nullptr, "USVFS parameter allocation failed");
    setName(params, instance.c_str());
    reader.connected = connect(params) != FALSE; freeParams(params);
    require(reader.connected, "Cannot attach to existing MO2 session");
    require(names.contains(reader.name()), "Controller view differs from this process's mapped VFS");
    size_t count = 4096; std::vector<DWORD> pids(count);
    require(processes(&count, pids.data()) && count <= pids.size() &&
        std::find(pids.begin(), pids.begin() + count, GetCurrentProcessId()) != pids.begin() + count,
        "Game is not registered in this MO2 session");
    view->scope_ = virtualScope(reader.read(), dataRoot);
    return view;
}
VirtualView::Check VirtualView::check(std::string* error) noexcept {
    const auto start = std::chrono::steady_clock::now();
    Check result = Check::changed;
    try {
        auto& reader = *impl_;
        const auto name = reader.name();
        if (reader.guardValidated && reader.guard && name == reader.guardName && reader.guard->unchanged()) {
            // No hashing, parsing, dump creation, or allocations proportional to
            // asset count. Includes every byte, even opaque allocator metadata.
            result = reader.name() == name ? Check::same : Check::busy;
        } else {
            reader.guardValidated = false;
            result = Check::busy;
            // A changed section can be an asset remap, a process attachment, or
            // runtime F4SE output. Only a full mapping check can distinguish them.
            for (unsigned attempt = 0; attempt < 2; ++attempt) {
                const auto current = reader.name();
                if (!reader.guard || reader.guardName != current) {
                    reader.guard.reset(); reader.guardBytes = 0;
                    reader.guard = std::make_unique<MappingSnapshot>(current);
                    reader.guardName = current; reader.guardBytes = reader.guard->bytes();
                }
                reader.guard->capture();
                if (scope_.context != "usvfs-auto-v1:" + contextKey(relevant(reader.read(), scope_.virtualRoot, false).bytes)) {
                    result = Check::changed;
                    break;
                }
                // Capture BEFORE validation and admit it only if the whole
                // section stayed unchanged through validation, including resize.
                if (reader.name() == current && reader.guard->unchanged()) { reader.guardValidated = true; result = Check::same; break; }
            }
        }
    } catch (const std::exception& e) {
        // A failed read (e.g. no memory for the dump) is not evidence of a change.
        result = Check::failed;
        if (error) try { *error = e.what(); } catch (...) {}
    } catch (...) {
        result = Check::failed;
        if (error) try { *error = "unknown error"; } catch (...) {}
    }
    ++checks_;
    microseconds_ += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - start).count());
    return result;
}
bool VirtualView::unchanged() noexcept { return check() == Check::same; }
bool VirtualView::settled(unsigned timeoutMs, std::string* problem) noexcept {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    for (;;) {
        std::string error;
        const Check result = check(&error);
        if (result == Check::same) return true;
        if (result == Check::changed) {
            if (problem) try { *problem = "the mapping differs from the validated view"; } catch (...) {}
            return false;
        }
        // The mapping matched but kept changing while it was read (a process
        // writing through USVFS right now), or could not be read. Retry until
        // it settles or the time is up; the answer stays "not confirmed".
        if (GetTickCount64() >= deadline) {
            if (problem) try {
                *problem = result == Check::busy ? "the mapping kept changing for " + std::to_string(timeoutMs / 1000) + " s"
                                                 : "the mapping could not be read: " + error;
            } catch (...) {}
            return false;
        }
        Sleep(250);
    }
}
uint64_t VirtualView::dumps() const noexcept { return impl_->dumps; }
uint64_t VirtualView::guardBytes() const noexcept { return impl_->guardBytes; }
}
