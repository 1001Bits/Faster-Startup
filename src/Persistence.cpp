#include "Persistence.h"
#include "NativeScope.h"
#include <bcrypt.h>
#include <winioctl.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <unordered_set>

namespace startup {
namespace {
using Clock = std::chrono::steady_clock;
constexpr size_t maxProofBytes = 256 * 1024 * 1024;
constexpr uint32_t maxObjects = 16 * 1024 * 1024;
constexpr uint32_t maxRoots = 2048;
constexpr uint32_t maxVolumes = 32;
constexpr DWORD shareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
constexpr size_t dirBufferBytes = 64 * 1024;

void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
uint64_t micros(Clock::time_point start) {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
}
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(Handle&& other) noexcept : value(other.value) { other.value = INVALID_HANDLE_VALUE; }
    Handle& operator=(Handle&& other) noexcept {
        if (value != INVALID_HANDLE_VALUE) CloseHandle(value);
        value = other.value; other.value = INVALID_HANDLE_VALUE; return *this;
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
Digest hash(std::span<const uint8_t> bytes) {
    Digest digest{};
    check(bytes.size() <= std::numeric_limits<ULONG>::max(), "Hash input too large");
    check(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, const_cast<PUCHAR>(bytes.data()),
        static_cast<ULONG>(bytes.size()), digest.data(), static_cast<ULONG>(digest.size())) >= 0, "SHA-256 unavailable");
    return digest;
}
struct Writer {
    std::vector<uint8_t> bytes;
    void u32(uint32_t value) { for (unsigned i = 0; i < 4; ++i) bytes.push_back(static_cast<uint8_t>(value >> (8 * i))); }
    void u64(uint64_t value) { for (unsigned i = 0; i < 8; ++i) bytes.push_back(static_cast<uint8_t>(value >> (8 * i))); }
    void raw(std::span<const uint8_t> data) { bytes.insert(bytes.end(), data.begin(), data.end()); }
    void text(std::string_view value) {
        check(value.size() <= 128 * 1024, "String too long");
        u32(static_cast<uint32_t>(value.size()));
        raw({reinterpret_cast<const uint8_t*>(value.data()), value.size()});
    }
    void wide(std::wstring_view value) { text(encodeUtf8(value)); }
};
struct Reader {
    std::span<const uint8_t> bytes;
    size_t pos{};
    std::span<const uint8_t> raw(size_t n) {
        check(pos <= bytes.size() && n <= bytes.size() - pos, "Truncated cache");
        auto result = bytes.subspan(pos, n); pos += n; return result;
    }
    uint32_t u32() { auto v = raw(4); uint32_t n = 0; for (unsigned i = 0; i < 4; ++i) n |= uint32_t(v[i]) << (8 * i); return n; }
    uint64_t u64() { auto v = raw(8); uint64_t n = 0; for (unsigned i = 0; i < 8; ++i) n |= uint64_t(v[i]) << (8 * i); return n; }
    std::string_view view(size_t limit = 128 * 1024) {
        auto n = u32(); check(n <= limit, "Oversized cache string");
        auto value = raw(n); check(std::find(value.begin(), value.end(), 0) == value.end(), "Embedded null in cache string");
        return {reinterpret_cast<const char*>(value.data()), value.size()};
    }
    std::string text(size_t limit = 128 * 1024) { return std::string(view(limit)); }
    std::wstring wide() { return decodeUtf8(text()); }
    Digest digest() { Digest result{}; auto v = raw(result.size()); std::copy(v.begin(), v.end(), result.begin()); return result; }
    void end() { check(pos == bytes.size(), "Trailing cache data"); }
};
std::vector<uint8_t> readEnvelope(const std::filesystem::path& path, std::string_view magic, size_t limit,
    std::span<const uint8_t> expectedPrefix = {}) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    check(static_cast<bool>(file), "Cache file absent or unreadable");
    const auto size = file.tellg();
    check(size >= 52 && static_cast<uint64_t>(size) <= limit, "Cache file size outside limits");
    file.seekg(0);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    check(static_cast<bool>(file.read(reinterpret_cast<char*>(bytes.data()), size)), "Cache file read failed");
    Reader reader{bytes};
    auto m = reader.raw(8);
    check(magic.size() == 8 && std::memcmp(m.data(), magic.data(), 8) == 0 && reader.u32() == 1, "Cache format mismatch");
    const auto bodySize = reader.u64(); const auto expected = reader.digest();
    check(bodySize == bytes.size() - reader.pos, "Cache length mismatch");
    // The body is re-checked after hashing; this only avoids hashing a mismatch.
    check(bodySize >= expectedPrefix.size() &&
        std::equal(expectedPrefix.begin(), expectedPrefix.end(), bytes.begin() + static_cast<ptrdiff_t>(reader.pos)),
        "Persistent snapshot belongs to another source generation/view");
    check(hash(reader.bytes.subspan(reader.pos)) == expected, "Cache checksum mismatch");
    bytes.erase(bytes.begin(), bytes.begin() + static_cast<ptrdiff_t>(reader.pos));
    return bytes;
}
void writeEnvelope(const std::filesystem::path& path, std::string_view magic, std::span<const uint8_t> body) {
    check(!path.empty(), "Cache path absent");
    Writer output;
    output.raw({reinterpret_cast<const uint8_t*>(magic.data()), magic.size()}); output.u32(1);
    output.u64(body.size()); output.raw(hash(body));
    Digest nonce{};
    check(BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "Random generation failed");
    auto temporary = path; temporary += L"." + decodeUtf8(digestHex(nonce).substr(0, 16)) + L".tmp";
    bool published = false;
    try {
        {
            Handle file(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
            check(file.value != INVALID_HANDLE_VALUE, "Cannot create temporary cache");
            for (auto part : {std::span<const uint8_t>(output.bytes), body}) {
                while (!part.empty()) {
                    DWORD n{}; const DWORD request = static_cast<DWORD>(std::min<size_t>(part.size(), 4 * 1024 * 1024));
                    check(WriteFile(file.value, part.data(), request, &n, nullptr) && n == request, "Cache write failed");
                    part = part.subspan(n);
                }
            }
            check(FlushFileBuffers(file.value) != FALSE, "Cache flush failed");
        }
        check(MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE,
            "Atomic cache publication failed");
        published = true;
    } catch (...) { if (!published) DeleteFileW(temporary.c_str()); throw; }
}
std::wstring canonical(std::wstring_view path) {
    check(!path.empty() && path.size() < 32760, "Invalid source path");
    std::wstring value(path);
    check(value.find_first_of(L"*?\r\n") == std::wstring::npos && value.find(L'\0') == std::wstring::npos, "Unsupported source path");
    std::vector<wchar_t> buffer(32768);
    DWORD n = GetFullPathNameW(value.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    check(n > 0 && n < buffer.size(), "Cannot resolve source path");
    value.assign(buffer.data(), n);
    std::replace(value.begin(), value.end(), L'/', L'\\');
    check(value.size() >= 3 && value[1] == L':' && value[2] == L'\\', "Only local drive-letter source paths are supported");
    while (value.size() > 3 && value.back() == L'\\') value.pop_back();
    return value;
}
uint64_t fileId(const BY_HANDLE_FILE_INFORMATION& info) {
    return (static_cast<uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
}
uint64_t timeValue(FILETIME time) { return (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime; }
FILETIME fileTime(uint64_t n) { return {static_cast<DWORD>(n), static_cast<DWORD>(n >> 32)}; }
struct Identity { uint64_t id{}, creation{}; uint32_t serial{}; };
std::wstring driveRoot(const std::wstring& path) {
    check(path.size() >= 3 && path[1] == L':' && path[2] == L'\\', "Only local drive-letter source paths are supported");
    return {static_cast<wchar_t>(towupper(path[0])), L':', L'\\'};
}
std::wstring physicalPath(const std::wstring& path) {
    // A volume-GUID path addresses physical sources even in a USVFS process.
    // Resolving it costs ~0.6 ms per call, and every source shares a few drive
    // roots, so each drive is resolved once per process. A later folder mount or
    // junction above a source cannot hide behind this: identities compare the
    // volume serial and file ID of the object actually opened, and ancestors are
    // checked for reparse points when the index is built.
    static std::mutex lock;
    static std::map<wchar_t, std::wstring> volumes;
    const auto mount = driveRoot(path);
    std::wstring volume;
    {
        std::lock_guard guard(lock);
        if (const auto found = volumes.find(mount[0]); found != volumes.end()) volume = found->second;
    }
    if (volume.empty()) {
        wchar_t name[128]{};
        check(GetVolumeNameForVolumeMountPointW(mount.c_str(), name, 128) != FALSE, "Physical source volume unavailable");
        volume = name;
        std::lock_guard guard(lock);
        volumes.emplace(mount[0], volume);
    }
    return volume + path.substr(3);
}
Identity identityOf(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    check(GetFileInformationByHandle(handle, &info) != FALSE, "Source identity unavailable");
    check((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
        "Source reparse points are not supported by persistent validation");
    check(fileId(info) != 0, "Filesystem returned a zero file identity");
    return {fileId(info), timeValue(info.ftCreationTime), info.dwVolumeSerialNumber};
}
Identity identity(const std::wstring& path) {
    Handle handle(CreateFileW(physicalPath(path).c_str(), FILE_READ_ATTRIBUTES, shareAll, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    check(handle.value != INVALID_HANDLE_VALUE, "Source identity unavailable");
    return identityOf(handle.value);
}
// MO2 rewrites each mod's metadata file (and QSaveFile/QLockFile companions
// named meta.ini.*) outside the game. Those names are not assets.
bool modMetadata(std::wstring_view name) noexcept {
    return name.size() >= 8 && CompareStringOrdinal(name.data(), 8, L"meta.ini", 8, TRUE) == CSTR_EQUAL;
}
// For an unindexed object directly inside a mod root. The unprivileged journal
// omits names, so resolve the object's current name. An object created after
// indexing that no longer exists (a replaced meta.ini, a QSaveFile temporary)
// is absent from every current listing. Anything else unresolvable is a change.
bool metadataOnly(HANDLE volume, uint64_t fileId, std::wstring_view recordName) {
    if (!recordName.empty()) return modMetadata(recordName);
    FILE_ID_DESCRIPTOR descriptor{}; descriptor.dwSize = sizeof(descriptor);
    descriptor.Type = FileIdType; descriptor.FileId.QuadPart = static_cast<LONGLONG>(fileId);
    Handle object(OpenFileById(volume, &descriptor, FILE_READ_ATTRIBUTES, shareAll, nullptr,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT));
    if (object.value == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        return error == ERROR_INVALID_PARAMETER || error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    std::vector<uint8_t> buffer(sizeof(FILE_NAME_INFO) + 32768 * sizeof(wchar_t));
    if (!GetFileInformationByHandleEx(object.value, FileNameInfo, buffer.data(), static_cast<DWORD>(buffer.size()))) return false;
    const auto info = reinterpret_cast<const FILE_NAME_INFO*>(buffer.data());
    const std::wstring_view path(info->FileName, std::min<size_t>(info->FileNameLength / sizeof(wchar_t), 32768));
    const auto slash = path.find_last_of(L'\\');
    return modMetadata(slash == std::wstring_view::npos ? path : path.substr(slash + 1));
}
struct Volume {
    std::wstring mount;
    uint32_t serial{};
    uint64_t journal{}, cursor{};
    std::vector<uint64_t> ids;
    // Sorted directory IDs of MO2 mod roots on this volume. Derived from the
    // request on every build/decode; never serialized.
    std::vector<uint64_t> metadataParents;
    Handle handle;
    USN_JOURNAL_DATA_V2 query() {
        USN_JOURNAL_DATA_V2 data{}; DWORD n{};
        check(DeviceIoControl(handle.value, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &data, sizeof(data), &n, nullptr) &&
            n >= sizeof(USN_JOURNAL_DATA_V0), "NTFS journal is unavailable");
        check(data.NextUsn >= 0 && data.FirstUsn >= 0 && data.LowestValidUsn >= 0, "Invalid journal bounds");
        return data;
    }
    void open() {
        wchar_t fs[32]{}; DWORD currentSerial{};
        check(GetVolumeInformationW(mount.c_str(), nullptr, 0, &currentSerial, nullptr, nullptr, fs, 32) &&
            _wcsicmp(fs, L"NTFS") == 0 && currentSerial == serial, "NTFS volume identity changed or unsupported filesystem");
        // A directory handle to the volume root permits the public unprivileged
        // journal operation. No raw volume read access or administrator token.
        handle = Handle(CreateFileW(mount.c_str(), FILE_READ_ATTRIBUTES, shareAll, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        check(handle.value != INVALID_HANDLE_VALUE, "Cannot open volume root for journal validation");
    }
    bool unchanged(PersistenceLimits limits, PersistenceMetrics& metrics) {
        const auto start = Clock::now();
        const auto state = query();
        check(state.UsnJournalID == journal && cursor >= static_cast<uint64_t>(std::max(state.FirstUsn, state.LowestValidUsn)) &&
            cursor <= static_cast<uint64_t>(state.NextUsn), "Journal reset, wrap, or discontinuity: rebuild required");
        const auto target = static_cast<uint64_t>(state.NextUsn);
        auto position = cursor; size_t bytesRead = 0;
        if (position >= target) return true; // Polled on every search: no records, no buffer.
        alignas(8) std::array<uint8_t, 64 * 1024> buffer; // Only the returned `size` bytes are read.
        while (position < target) {
            check(bytesRead < limits.maxJournalBytes && micros(start) / 1000 < limits.maxJournalMs,
                "Journal validation exceeded its work budget");
            READ_USN_JOURNAL_DATA_V1 request{};
            request.StartUsn = static_cast<USN>(position); request.ReasonMask = 0xffffffff;
            request.UsnJournalID = journal; request.MinMajorVersion = 2; request.MaxMajorVersion = 2;
            DWORD size{};
            check(DeviceIoControl(handle.value, FSCTL_READ_UNPRIVILEGED_USN_JOURNAL, &request, sizeof(request),
                buffer.data(), static_cast<DWORD>(buffer.size()), &size, nullptr) && size >= sizeof(USN), "Unprivileged journal read failed");
            bytesRead += size;
            USN next{}; std::memcpy(&next, buffer.data(), sizeof(next));
            check(next >= 0 && static_cast<uint64_t>(next) > position, "Journal did not advance to the validation boundary");
            for (size_t offset = sizeof(USN); offset < size;) {
                constexpr size_t minimum = offsetof(USN_RECORD_V2, FileName);
                check(size - offset >= minimum, "Truncated journal record");
                const auto record = reinterpret_cast<const USN_RECORD_V2*>(buffer.data() + offset);
                check(record->MajorVersion == 2 && record->RecordLength >= minimum && record->RecordLength <= size - offset &&
                    record->RecordLength % 8 == 0 && record->Usn >= 0, "Unsupported or malformed journal record");
                check(record->FileNameOffset <= record->RecordLength && record->FileNameLength <= record->RecordLength - record->FileNameOffset,
                    "Malformed journal filename bounds");
                check(record->FileNameOffset % sizeof(wchar_t) == 0 && record->FileNameLength % sizeof(wchar_t) == 0,
                    "Malformed journal filename alignment");
                const auto usn = static_cast<uint64_t>(record->Usn);
                check(usn >= position, "Journal record preceded requested cursor");
                if (usn < target) {
                    ++metrics.journalRecords;
                    const auto name = reinterpret_cast<const wchar_t*>(buffer.data() + offset + record->FileNameOffset);
                    const std::wstring_view recordName(name, record->FileNameLength / sizeof(wchar_t));
                    const bool trackedFile = std::binary_search(ids.begin(), ids.end(), record->FileReferenceNumber);
                    // MO2 metadata beside a mod's assets. Its own ID is never
                    // indexed, so a hard link to an asset still matches trackedFile.
                    const bool metadata = !trackedFile &&
                        std::binary_search(metadataParents.begin(), metadataParents.end(), record->ParentFileReferenceNumber) &&
                        metadataOnly(handle.value, record->FileReferenceNumber, recordName);
                    if (!metadata && (trackedFile ||
                        std::binary_search(ids.begin(), ids.end(), record->ParentFileReferenceNumber))) {
                        // Preserve the first rejected journal record for diagnosis.
                        // Later rebuilding/loading must not hide why reuse failed.
                        auto filename = encodeUtf8(recordName);
                        // The unprivileged journal can omit names. Resolve the
                        // rejected physical identity when its object still exists;
                        // failure affects diagnostics only, never validation.
                        if (filename.empty()) {
                            FILE_ID_DESCRIPTOR descriptor{}; descriptor.dwSize = sizeof(descriptor);
                            descriptor.Type = FileIdType; descriptor.FileId.QuadPart = static_cast<LONGLONG>(record->FileReferenceNumber);
                            Handle changed(OpenFileById(handle.value, &descriptor, FILE_READ_ATTRIBUTES, shareAll, nullptr,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT));
                            if (changed.value != INVALID_HANDLE_VALUE) {
                                wchar_t path[32768]{};
                                const auto n = GetFinalPathNameByHandleW(changed.value, path, 32768, VOLUME_NAME_GUID);
                                if (n && n < 32768) filename = encodeUtf8({path, n});
                            }
                        }
                        for (auto& c : filename) if (static_cast<unsigned char>(c) < 32) c = ' ';
                        metrics.sourceChange = "name=" + filename + " file_id=" + std::to_string(record->FileReferenceNumber) +
                            " parent_id=" + std::to_string(record->ParentFileReferenceNumber) + " reason=" + std::to_string(record->Reason);
                        return false;
                    }
                }
                offset += record->RecordLength;
            }
            position = static_cast<uint64_t>(next);
        }
        cursor = target;
        return true;
    }
};
struct Root { std::wstring path; uint32_t volume{}; Identity identity; };
struct Proof {
    ScopeRequest request;
    Digest generation{};
    uint32_t codePage{};
    std::vector<Root> roots;
    std::vector<Volume> volumes;
};
bool isMetadataRoot(const Proof& proof, const Root& root) {
    // Physical Data (the virtual root itself) has no MO2 mod metadata.
    return !proof.request.context.empty() &&
        CompareStringOrdinal(root.path.c_str(), -1, proof.request.virtualRoot.c_str(), -1, TRUE) != CSTR_EQUAL;
}
void assignMetadataParents(Proof& proof) {
    for (auto& volume : proof.volumes) volume.metadataParents.clear();
    for (const auto& root : proof.roots)
        if (isMetadataRoot(proof, root)) proof.volumes[root.volume].metadataParents.push_back(root.identity.id);
    for (auto& volume : proof.volumes) std::sort(volume.metadataParents.begin(), volume.metadataParents.end());
}
ScopeRequest normalizeRequest(ScopeRequest request) {
    request.virtualRoot = canonical(request.virtualRoot);
    check(request.context.size() <= 4096 && request.context.find('\0') == std::string::npos, "Invalid context identity");
    check(!request.sourceRoots.empty() && request.sourceRoots.size() <= maxRoots, "Invalid source root count");
    for (auto& root : request.sourceRoots) root = canonical(root);
    std::sort(request.sourceRoots.begin(), request.sourceRoots.end());
    request.sourceRoots.erase(std::unique(request.sourceRoots.begin(), request.sourceRoots.end()), request.sourceRoots.end());
    return request;
}
bool sameRequest(const ScopeRequest& a, const ScopeRequest& b) {
    return a.virtualRoot == b.virtualRoot && a.context == b.context && a.sourceRoots == b.sourceRoots;
}
void writeRequest(Writer& writer, const ScopeRequest& request) {
    writer.wide(request.virtualRoot); writer.text(request.context); writer.u32(static_cast<uint32_t>(request.sourceRoots.size()));
    for (const auto& root : request.sourceRoots) writer.wide(root);
}
ScopeRequest readRequest(Reader& reader) {
    ScopeRequest request; request.virtualRoot = reader.wide(); request.context = reader.text(4096);
    auto n = reader.u32(); check(n > 0 && n <= maxRoots, "Invalid persisted source root count");
    for (uint32_t i = 0; i < n; ++i) request.sourceRoots.push_back(reader.wide());
    return normalizeRequest(std::move(request));
}
Writer encodeProof(const Proof& proof) {
    Writer writer; writeRequest(writer, proof.request); writer.raw(proof.generation); writer.u32(proof.codePage);
    writer.u32(static_cast<uint32_t>(proof.volumes.size()));
    for (const auto& volume : proof.volumes) {
        writer.wide(volume.mount); writer.u32(volume.serial); writer.u64(volume.journal); writer.u64(volume.cursor);
        writer.u32(static_cast<uint32_t>(volume.ids.size()));
        for (auto id : volume.ids) writer.u64(id);
    }
    writer.u32(static_cast<uint32_t>(proof.roots.size()));
    for (const auto& root : proof.roots) {
        writer.wide(root.path); writer.u32(root.volume); writer.u64(root.identity.id); writer.u64(root.identity.creation); writer.u32(root.identity.serial);
    }
    return writer;
}
Proof decodeProof(const std::filesystem::path& path) {
    auto bytes = readEnvelope(path, "FSTPRF03", maxProofBytes); Reader reader{bytes};
    Proof proof; proof.request = readRequest(reader); proof.generation = reader.digest(); proof.codePage = reader.u32();
    check(proof.codePage == GetACP(), "ANSI code page changed");
    auto n = reader.u32(); check(n > 0 && n <= maxVolumes, "Invalid persisted volume count");
    size_t totalIds{};
    for (uint32_t i = 0; i < n; ++i) {
        Volume volume; volume.mount = reader.wide(); volume.serial = reader.u32(); volume.journal = reader.u64(); volume.cursor = reader.u64();
        auto count = reader.u32(); totalIds += count;
        check(count > 0 && totalIds <= maxObjects && count <= (bytes.size() - reader.pos) / 8, "Invalid persisted identity count");
        volume.ids.reserve(count);
        for (uint32_t j = 0; j < count; ++j) volume.ids.push_back(reader.u64());
        check(volume.ids.front() != 0 && std::is_sorted(volume.ids.begin(), volume.ids.end()) &&
            std::adjacent_find(volume.ids.begin(), volume.ids.end()) == volume.ids.end(), "Invalid identity ordering");
        volume.open(); proof.volumes.push_back(std::move(volume));
    }
    n = reader.u32(); check(n == proof.request.sourceRoots.size(), "Source root count mismatch");
    for (uint32_t i = 0; i < n; ++i) {
        Root root; root.path = reader.wide(); root.volume = reader.u32(); root.identity.id = reader.u64();
        root.identity.creation = reader.u64(); root.identity.serial = reader.u32();
        check(root.path == proof.request.sourceRoots[i] && root.volume < proof.volumes.size() && root.identity.id != 0 &&
            root.identity.serial == proof.volumes[root.volume].serial &&
            std::binary_search(proof.volumes[root.volume].ids.begin(), proof.volumes[root.volume].ids.end(), root.identity.id), "Invalid root identity");
        proof.roots.push_back(std::move(root));
    }
    reader.end(); assignMetadataParents(proof); return proof;
}
void verifyRoots(const Proof& proof) {
    for (const auto& root : proof.roots) {
        const auto current = identity(root.path);
        check(current.id == root.identity.id && current.serial == root.identity.serial && current.creation == root.identity.creation,
            "A source root was moved, replaced, or remapped");
    }
}
void scanTree(Proof& proof, Root& root, PersistenceMetrics& metrics, size_t& collected,
    uint64_t& files, size_t limit, ProgressState* progress) {
    auto& volume = proof.volumes[root.volume];
    const bool metadataRoot = isMetadataRoot(proof, root);
    const auto addIdentity = [&](uint64_t id) {
        // Bound allocations while collecting, across all roots and volumes.
        // Waiting until deduplication could exceed the budget by several volumes.
        check(collected < limit, "Source scope exceeds the identity budget");
        volume.ids.push_back(id); ++collected;
    };
    std::vector<std::wstring> pending{root.path};
    std::unordered_set<uint64_t> visited;
    alignas(8) std::array<uint8_t, dirBufferBytes> buffer{};
    while (!pending.empty()) {
        auto path = std::move(pending.back()); pending.pop_back();
        // One open per directory supplies both its identity and its listing.
        Handle directory(CreateFileW(physicalPath(path).c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, shareAll, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        check(directory.value != INVALID_HANDLE_VALUE, "Cannot enumerate source directory identities");
        const auto current = identityOf(directory.value);
        check(current.serial == volume.serial, "Cross-volume directory found");
        if (!visited.insert(current.id).second) continue;
        addIdentity(current.id);
        ++metrics.scannedDirectories;
        bool first = true;
        for (;;) {
            const BOOL ok = GetFileInformationByHandleEx(directory.value,
                first ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo, buffer.data(), static_cast<DWORD>(buffer.size()));
            first = false;
            if (!ok) { check(GetLastError() == ERROR_NO_MORE_FILES, "File-identity enumeration failed"); break; }
            for (size_t offset = 0;;) {
                constexpr auto minimum = offsetof(FILE_ID_BOTH_DIR_INFO, FileName);
                check(offset <= buffer.size() - minimum, "Invalid identity directory buffer");
                const auto item = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(buffer.data() + offset);
                check(item->FileNameLength % sizeof(wchar_t) == 0 && item->FileNameLength <= buffer.size() - offset - minimum,
                    "Invalid identity directory name");
                const auto id = static_cast<uint64_t>(item->FileId.QuadPart);
                check(id != 0, "Filesystem did not supply stable file identities");
                const std::wstring_view name(item->FileName, item->FileNameLength / sizeof(wchar_t));
                if (name != L"." && name != L"..") {
                    check(!(item->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "Reparse entries require a fresh scan; persistent scope declined");
                    const bool runtimeBoundary = path == root.path && nativeRoot(name) &&
                        (item->FileAttributes & FILE_ATTRIBUTE_DIRECTORY);
                    // The indexed parent protects this boundary's metadata,
                    // rename and removal. Do not index the directory ID itself:
                    // it would admit journal events for every direct child log.
                    // Files retain their IDs, including hard links to assets.
                    const bool metadata = metadataRoot && path == root.path && modMetadata(name) &&
                        !(item->FileAttributes & FILE_ATTRIBUTE_DIRECTORY);
                    if (!runtimeBoundary && !metadata) addIdentity(id);
                    if (!(item->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) ++files;
                    if ((item->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !runtimeBoundary)
                        pending.push_back(path + L"\\" + std::wstring(name));
                }
                if (!item->NextEntryOffset) break;
                check(item->NextEntryOffset >= minimum && item->NextEntryOffset <= buffer.size() - offset && item->NextEntryOffset % 8 == 0,
                    "Invalid identity directory offset");
                offset += item->NextEntryOffset;
            }
            if (progress) progress->scanned(files, metrics.scannedDirectories);
        }
        if (progress) progress->scanned(files, metrics.scannedDirectories);
    }
}
Proof buildProof(const ScopeRequest& request, PersistenceMetrics& metrics, PersistenceLimits limits, ProgressState* progress) {
    Proof proof; proof.request = request; proof.codePage = GetACP();
    check(BCryptGenRandom(nullptr, proof.generation.data(), static_cast<ULONG>(proof.generation.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
        "Cannot create cache generation");
    for (const auto& path : request.sourceRoots) {
        Root root; root.path = path; root.identity = identity(path);
        // Folder mount points are reparse points, rejected on the root and
        // every ancestor below. The drive root is therefore the volume mount.
        const auto mount = driveRoot(path);
        size_t index = 0;
        for (; index < proof.volumes.size(); ++index) if (proof.volumes[index].mount == mount) break;
        if (index == proof.volumes.size()) {
            check(index < maxVolumes, "Too many source volumes");
            Volume volume; volume.mount = mount; volume.serial = root.identity.serial; volume.open();
            const auto state = volume.query(); volume.journal = state.UsnJournalID; volume.cursor = static_cast<uint64_t>(state.NextUsn);
            proof.volumes.push_back(std::move(volume));
        }
        root.volume = static_cast<uint32_t>(index); proof.roots.push_back(std::move(root));
    }
    assignMetadataParents(proof);
    size_t collected{}; uint64_t files{};
    const auto objectLimit = std::min<size_t>(maxObjects, limits.maxSourceObjects);
    if (progress) progress->phase(ProgressPhase::indexing);
    // Thousands of MO2 mods share the same few ancestors; check each once.
    std::map<std::wstring, uint32_t> ancestorSerials;
    // All journal checkpoints precede all identity scans: no scan/checkpoint gap.
    for (auto& root : proof.roots) {
        std::filesystem::path ancestor(root.path);
        while (!ancestor.empty()) {
            const auto key = ancestor.wstring();
            auto found = ancestorSerials.find(key);
            if (found == ancestorSerials.end()) found = ancestorSerials.emplace(key, identity(key).serial).first;
            check(found->second == root.identity.serial, "Mounted/reparse ancestor unsupported");
            // Ancestors are checked for reparse points, but are not asset scope:
            // unrelated siblings (including our cache files) must not dirty it.
            const auto parent = ancestor.parent_path(); if (parent == ancestor) break; ancestor = parent;
        }
        scanTree(proof, root, metrics, collected, files, objectLimit, progress);
    }
    size_t total{};
    for (auto& volume : proof.volumes) {
        std::sort(volume.ids.begin(), volume.ids.end()); volume.ids.erase(std::unique(volume.ids.begin(), volume.ids.end()), volume.ids.end());
        total += volume.ids.size(); check(total <= maxObjects, "Source scope exceeds the identity budget");
        check(volume.unchanged(limits, metrics), "Sources changed while building their identity index; retry next launch");
    }
    verifyRoots(proof); return proof;
}
void encodeData(Writer& writer, const WIN32_FIND_DATAA& data) {
    writer.u32(data.dwFileAttributes); writer.u64(timeValue(data.ftCreationTime)); writer.u64(timeValue(data.ftLastAccessTime));
    writer.u64(timeValue(data.ftLastWriteTime)); writer.u64((uint64_t(data.nFileSizeHigh) << 32) | data.nFileSizeLow);
    writer.u32(data.dwReserved0); writer.u32(data.dwReserved1);
    const auto nameSize = strnlen_s(data.cFileName, MAX_PATH), shortSize = strnlen_s(data.cAlternateFileName, 14);
    check(nameSize > 0 && nameSize < MAX_PATH && shortSize < 14, "Invalid filename in snapshot");
    writer.text({data.cFileName, nameSize}); writer.text({data.cAlternateFileName, shortSize});
}
WIN32_FIND_DATAA decodeData(Reader& reader) {
    WIN32_FIND_DATAA data{}; data.dwFileAttributes = reader.u32(); data.ftCreationTime = fileTime(reader.u64());
    data.ftLastAccessTime = fileTime(reader.u64()); data.ftLastWriteTime = fileTime(reader.u64()); const auto size = reader.u64();
    data.nFileSizeHigh = static_cast<DWORD>(size >> 32); data.nFileSizeLow = static_cast<DWORD>(size);
    data.dwReserved0 = reader.u32(); data.dwReserved1 = reader.u32();
    auto name = reader.view(MAX_PATH - 1), shortName = reader.view(13);
    check(!name.empty() && name.find_first_of("\\/:") == std::string::npos && shortName.find_first_of("\\/:") == std::string::npos,
        "Invalid stored filename");
    std::copy(name.begin(), name.end(), data.cFileName); std::copy(shortName.begin(), shortName.end(), data.cAlternateFileName);
    return data;
}
}

std::wstring decodeUtf8(std::string_view text) {
    if (text.empty()) return {};
    check(text.size() <= 128 * 1024, "UTF-8 input too large");
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    check(n > 0, "Invalid UTF-8 input"); std::wstring output(n, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), output.data(), n); return output;
}
std::string encodeUtf8(std::wstring_view text) {
    if (text.empty()) return {};
    check(text.size() <= 32768, "UTF-16 input too large");
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    check(n > 0, "Invalid UTF-16 input"); std::string output(n, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), output.data(), n, nullptr, nullptr); return output;
}
std::string digestHex(std::span<const uint8_t> bytes) {
    constexpr char alphabet[] = "0123456789abcdef"; std::string out; out.reserve(bytes.size() * 2);
    for (auto byte : bytes) { out.push_back(alphabet[byte >> 4]); out.push_back(alphabet[byte & 15]); } return out;
}
std::string contextKey(std::string_view text) {
    return digestHex(hash({reinterpret_cast<const uint8_t*>(text.data()), text.size()}));
}
ScopeRequest readScopeRequest(const std::filesystem::path& file) {
    std::ifstream input(file, std::ios::binary | std::ios::ate);
    check(input && input.tellg() >= 0 && input.tellg() <= 1024 * 1024, "Invalid bridge request size"); input.seekg(0);
    std::string line; check(std::getline(input, line) && line == "FasterStartup scope v1", "Invalid bridge request header");
    ScopeRequest request;
    check(static_cast<bool>(std::getline(input, line)), "Missing virtual root"); request.virtualRoot = decodeUtf8(line);
    check(static_cast<bool>(std::getline(input, request.context)) && !request.context.empty(), "Missing virtual context");
    while (std::getline(input, line)) { check(!line.empty() && request.sourceRoots.size() < maxRoots, "Invalid bridge source roots"); request.sourceRoots.push_back(decodeUtf8(line)); }
    return normalizeRequest(std::move(request));
}

struct PersistentStore::Impl {
    PersistenceLimits limits;
    std::shared_ptr<ProgressState> progress;
    PersistenceMetrics metrics;
    Proof proof;
    std::filesystem::path checkpointFile;
    std::string status = "Persistence has not been initialized";
    bool ready = false;
    std::vector<HANDLE> watchers;
    explicit Impl(PersistenceLimits value, std::shared_ptr<ProgressState> state) : limits(value), progress(std::move(state)) {}
    ~Impl() { for (auto watcher : watchers) FindCloseChangeNotification(watcher); }
    void journal(const char* failure) {
        for (auto& volume : proof.volumes) check(volume.unchanged(limits, metrics), failure);
    }
    // Everything beneath a root is covered by the journal: file and parent IDs,
    // including a rename or deletion of the root itself. A root path can only be
    // re-pointed without such a record by renaming a directory ABOVE it, which
    // the non-recursive ancestor watchers report. Rearms before validation.
    bool ancestorsNotified() {
        bool notified = false;
        for (size_t i = 0; i < watchers.size(); i += MAXIMUM_WAIT_OBJECTS) {
            const auto n = static_cast<DWORD>(std::min<size_t>(MAXIMUM_WAIT_OBJECTS, watchers.size() - i));
            const DWORD state = WaitForMultipleObjects(n, watchers.data() + i, FALSE, 0);
            if (state == WAIT_TIMEOUT) continue;
            check(state < WAIT_OBJECT_0 + n, "Source notification failed");
            for (size_t j = i; j < i + n; ++j) {
                const DWORD single = WaitForSingleObject(watchers[j], 0);
                if (single == WAIT_TIMEOUT) continue;
                check(single == WAIT_OBJECT_0 && FindNextChangeNotification(watchers[j]), "Cannot rearm source notification");
                notified = true;
            }
        }
        return notified;
    }
    bool validate() {
        check(ready, "Persistence is unavailable"); verifyRoots(proof);
        journal("Asset sources changed; persistent results rejected");
        return true;
    }
    // Cheap revalidation once watchers are armed: journal tail, plus the root
    // identities only if an ancestor changed. Without watchers, validate fully.
    bool refresh(const char* failure = "Asset sources changed; persistent results rejected") {
        check(ready, "Persistence is unavailable");
        if (watchers.empty() || ancestorsNotified()) verifyRoots(proof);
        journal(failure);
        return true;
    }
};
PersistentStore::PersistentStore(PersistenceLimits limits, std::shared_ptr<ProgressState> progress) :
    impl_(std::make_unique<Impl>(limits, std::move(progress))) {}
PersistentStore::~PersistentStore() = default;
bool PersistentStore::prepare(const ScopeRequest& raw, const std::filesystem::path& proofFile) noexcept {
    try {
        if (impl_->progress) impl_->progress->phase(ProgressPhase::checking);
        impl_->checkpointFile = proofFile;
        impl_->metrics.reusedProof = false;
        auto request = normalizeRequest(raw);
        try {
            impl_->proof = decodeProof(proofFile); impl_->ready = true;
            check(sameRequest(request, impl_->proof.request), "Source context changed");
            impl_->validate(); impl_->metrics.reusedProof = true;
            impl_->status = "Source index reused after journal validation";
            impl_->metrics.sourceIndexStatus = impl_->status;
        } catch (const std::exception& e) {
            impl_->ready = false;
            impl_->metrics.sourceIndexStatus = std::string("Rebuilt because: ") + e.what();
        } catch (...) {
            impl_->ready = false;
            impl_->metrics.sourceIndexStatus = "Rebuilt because: source index could not be loaded or validated";
        }
        if (!impl_->ready) {
            impl_->proof = buildProof(request, impl_->metrics, impl_->limits, impl_->progress.get()); impl_->ready = true;
            impl_->status = "New source identity index built";
        }
        // A warm launch must not wait on rewriting and flushing an unchanged
        // multi-megabyte identity set. Checkpoint it with the background save.
        if (!impl_->metrics.reusedProof) {
            auto writer = encodeProof(impl_->proof); writeEnvelope(proofFile, "FSTPRF03", writer.bytes);
        }
        return true;
    } catch (const std::exception& e) { impl_->ready = false; impl_->status = e.what(); return false; }
    catch (...) { impl_->ready = false; impl_->status = "Source validation allocation failure"; return false; }
}
bool PersistentStore::adoptPrepared(const std::wstring& virtualRoot, const std::filesystem::path& proofFile) noexcept {
    try {
        impl_->proof = decodeProof(proofFile);
        const auto actualRoot = canonical(virtualRoot);
        const auto& preparedRoot = impl_->proof.request.virtualRoot;
        check(CompareStringOrdinal(preparedRoot.c_str(), -1, actualRoot.c_str(), -1, TRUE) == CSTR_EQUAL &&
            !impl_->proof.request.context.empty(), "Prepared virtual context does not match this game");
        // MO2 reports "data" while the plugin uses "Data". Admit spelling
        // differences only when both names resolve to the same directory object;
        // case-sensitive directories must not merge distinct physical roots.
        const auto expectedIdentity = identity(preparedRoot), actualIdentity = identity(actualRoot);
        check(expectedIdentity.id == actualIdentity.id && expectedIdentity.serial == actualIdentity.serial &&
            expectedIdentity.creation == actualIdentity.creation, "Prepared virtual root resolves to a different directory");
        impl_->ready = true; impl_->validate(); impl_->metrics.reusedProof = true;
        impl_->status = "Prepared virtual source index validated";
        impl_->metrics.sourceIndexStatus = impl_->status; return true;
    } catch (const std::exception& e) { impl_->ready = false; impl_->status = e.what(); return false; }
    catch (...) { impl_->ready = false; impl_->status = "Prepared scope load failed"; return false; }
}
bool PersistentStore::writePrepared(const std::filesystem::path& file) noexcept {
    try {
        impl_->validate(); auto writer = encodeProof(impl_->proof); writeEnvelope(file, "FSTPRF03", writer.bytes);
        // The bridge has no later source-index save inside its unvirtualized host.
        if (impl_->metrics.reusedProof && !impl_->checkpointFile.empty()) writeEnvelope(impl_->checkpointFile, "FSTPRF03", writer.bytes);
        return true;
    }
    catch (const std::exception& e) { impl_->status = e.what(); return false; }
    catch (...) { impl_->status = "Prepared scope write failed"; return false; }
}
bool PersistentStore::startWatching() noexcept {
    try {
        check(impl_->ready, "Persistence unavailable");
        // Content changes, including runtime logs, are the journal's job. Only a
        // directory rename/replacement above a root can re-point it silently, so
        // watch every proper ancestor non-recursively for directory-name changes.
        // A recursive watch here fired on every overwrite/log write and forced a
        // full root check under the cache lock.
        std::set<std::wstring> ancestors;
        for (const auto& root : impl_->proof.roots) {
            for (auto ancestor = std::filesystem::path(root.path).parent_path(); !ancestor.empty();) {
                ancestors.insert(ancestor.wstring());
                auto next = ancestor.parent_path(); if (next == ancestor) break; ancestor = next;
            }
        }
        for (const auto& path : ancestors) {
            HANDLE watcher = FindFirstChangeNotificationW(physicalPath(path).c_str(), FALSE, FILE_NOTIFY_CHANGE_DIR_NAME);
            check(watcher != INVALID_HANDLE_VALUE, "Cannot monitor an asset source"); impl_->watchers.push_back(watcher);
        }
        // Install watchers before the final journal validation to close the gap.
        impl_->validate(); return true;
    } catch (const std::exception& e) { impl_->status = e.what(); impl_->ready = false; return false; }
    catch (...) { impl_->status = "Source watcher initialization failed"; impl_->ready = false; return false; }
}
bool PersistentStore::pollChanged() noexcept {
    if (!impl_->ready) return true;
    try {
        // A write through a hard link outside the watched paths can still change
        // cached metadata. Check the volume tail before opening each cached search.
        impl_->refresh("Asset identity changed during startup");
    } catch (const std::exception& e) { impl_->ready = false; impl_->status = e.what(); return true; }
    catch (...) { impl_->ready = false; impl_->status = "Journal polling failed"; return true; }
    return false;
}
bool PersistentStore::checkpoint() noexcept {
    try {
        // Advancing the saved journal cursor while the game runs keeps the next
        // launch's gap short, so a small or busy journal is less likely to wrap.
        // Saved results stay valid only if nothing tracked changed since saving.
        check(!impl_->checkpointFile.empty(), "No source index to checkpoint");
        impl_->refresh();
        const auto writer = encodeProof(impl_->proof); writeEnvelope(impl_->checkpointFile, "FSTPRF03", writer.bytes);
        impl_->status = "Source index checkpointed"; return true;
    } catch (const std::exception& e) { impl_->ready = false; impl_->status = e.what(); return false; }
    catch (...) { impl_->ready = false; impl_->status = "Source index checkpoint failed"; return false; }
}
bool PersistentStore::validate() noexcept {
    try { return impl_->validate(); }
    catch (const std::exception& e) { impl_->ready = false; impl_->status = e.what(); return false; }
    catch (...) { impl_->ready = false; impl_->status = "Journal validation failed"; return false; }
}
bool PersistentStore::load(const std::filesystem::path& file, const std::function<bool(PersistentRow&&)>& accept) noexcept {
    const auto start = Clock::now();
    try {
        impl_->refresh();
        // Reject another generation before hashing a file that cannot match.
        auto bytes = readEnvelope(file, "FSTDIR02", impl_->limits.maxSnapshotBytes + 16 * 1024 * 1024, impl_->proof.generation);
        Reader reader{bytes};
        check(reader.digest() == impl_->proof.generation && reader.wide() == impl_->proof.request.virtualRoot &&
            reader.text(4096) == impl_->proof.request.context && reader.u32() == GetACP(), "Persistent snapshot belongs to another source generation/view");
        auto count = reader.u32(); check(count <= impl_->limits.maxDirectories, "Snapshot directory count exceeds limit");
        if (impl_->progress) impl_->progress->phase(ProgressPhase::loading, count);
        size_t decodedBytes = 0;
        // Decode once, then validate before publishing any rows. Vectors move to
        // the cache without a second metadata allocation or parsing pass.
        std::vector<PersistentRow> rows; rows.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            PersistentRow row; row.pattern = reader.text(32767); const auto entries = reader.u32();
            check(entries > 0 && entries <= impl_->limits.maxSnapshotBytes / sizeof(WIN32_FIND_DATAA), "Invalid entry count");
            decodedBytes += static_cast<size_t>(entries) * sizeof(WIN32_FIND_DATAA);
            check(decodedBytes <= impl_->limits.maxSnapshotBytes, "Snapshot exceeds memory budget");
            row.entries.reserve(entries);
            for (uint32_t j = 0; j < entries; ++j) row.entries.push_back(decodeData(reader));
            rows.push_back(std::move(row));
            if (impl_->progress) impl_->progress->advance(i + 1);
        }
        reader.end(); impl_->refresh();
        for (auto& row : rows) {
            if (accept(std::move(row))) ++impl_->metrics.loadedDirectories;
        }
        impl_->refresh();
        impl_->metrics.loadMicroseconds += micros(start); impl_->status = "Persistent directory results loaded"; return true;
    } catch (const std::exception& e) { impl_->status = e.what(); impl_->metrics.loadedDirectories = 0; impl_->metrics.loadMicroseconds += micros(start); return false; }
    catch (...) { impl_->status = "Snapshot load failed"; impl_->metrics.loadedDirectories = 0; impl_->metrics.loadMicroseconds += micros(start); return false; }
}
bool PersistentStore::save(const std::filesystem::path& file, std::span<const PersistentRowView> rows) noexcept {
    const auto start = Clock::now();
    try {
        if (impl_->progress) impl_->progress->phase(ProgressPhase::saving, rows.size());
        impl_->refresh(); check(rows.size() <= impl_->limits.maxDirectories, "Too many snapshot rows");
        Writer writer; writer.raw(impl_->proof.generation); writer.wide(impl_->proof.request.virtualRoot);
        writer.text(impl_->proof.request.context); writer.u32(GetACP()); writer.u32(static_cast<uint32_t>(rows.size()));
        size_t total{}, completed{};
        for (const auto& row : rows) {
            check(!row.entries.empty(), "Empty snapshots cannot be published"); total += row.entries.size() * sizeof(WIN32_FIND_DATAA);
            check(total <= impl_->limits.maxSnapshotBytes, "Snapshot exceeds memory budget");
            writer.text(row.pattern); writer.u32(static_cast<uint32_t>(row.entries.size()));
            for (const auto& entry : row.entries) encodeData(writer, entry);
            if (impl_->progress) impl_->progress->advance(++completed);
        }
        impl_->refresh(); writeEnvelope(file, "FSTDIR02", writer.bytes);
        if (!impl_->checkpointFile.empty()) {
            const auto checkpoint = encodeProof(impl_->proof); writeEnvelope(impl_->checkpointFile, "FSTPRF03", checkpoint.bytes);
        }
        impl_->metrics.savedDirectories = rows.size(); impl_->metrics.saveMicroseconds += micros(start);
        impl_->status = "Persistent directory results saved"; return true;
    } catch (const std::exception& e) { impl_->status = e.what(); impl_->metrics.saveMicroseconds += micros(start); return false; }
    catch (...) { impl_->status = "Snapshot write failed"; impl_->metrics.saveMicroseconds += micros(start); return false; }
}
const std::string& PersistentStore::status() const noexcept { return impl_->status; }
const PersistenceMetrics& PersistentStore::metrics() const noexcept { return impl_->metrics; }
const std::string& PersistentStore::context() const noexcept { return impl_->proof.request.context; }
const Digest& PersistentStore::generation() const noexcept { return impl_->proof.generation; }
}
