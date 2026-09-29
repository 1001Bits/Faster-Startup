#include "ImportHooks.h"
#include <cstring>

namespace startup {
bool ImportHooks::inspect(HMODULE module, std::string& error) {
    slots_ = {};
    if (!module) { error = "Executable module not found"; return false; }
    auto base = reinterpret_cast<unsigned char*>(module);
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 1024 * 1024) {
        error = "Invalid DOS header"; return false;
    }
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        error = "Expected a 64-bit PE executable"; return false;
    }
    const size_t size = nt->OptionalHeader.SizeOfImage;
    const auto inside = [size](size_t rva, size_t bytes) { return rva < size && bytes <= size - rva; };
    const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!directory.VirtualAddress || !inside(directory.VirtualAddress, directory.Size)) {
        error = "No valid import directory"; return false;
    }
    constexpr std::array names{"FindFirstFileA", "FindNextFileA", "FindClose"};
    for (size_t offset = 0; offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= directory.Size; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        const auto desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + directory.VirtualAddress + offset);
        if (!desc->Name) break;
        if (!desc->OriginalFirstThunk || !desc->FirstThunk) continue;
        for (size_t index = 0;; ++index) {
            const size_t nameRva = desc->OriginalFirstThunk + index * sizeof(IMAGE_THUNK_DATA64);
            const size_t slotRva = desc->FirstThunk + index * sizeof(IMAGE_THUNK_DATA64);
            if (!inside(nameRva, 8) || !inside(slotRva, 8)) { error = "Import thunk outside executable"; return false; }
            const auto name = reinterpret_cast<const IMAGE_THUNK_DATA64*>(base + nameRva)->u1.AddressOfData;
            if (!name) break;
            if (IMAGE_SNAP_BY_ORDINAL64(name)) continue;
            if (!inside(name, 3)) { error = "Invalid import name"; return false; }
            const char* text = reinterpret_cast<const char*>(base + name + 2);
            if (!std::memchr(text, 0, size - static_cast<size_t>(name) - 2)) { error = "Unterminated import name"; return false; }
            for (size_t i = 0; i < names.size(); ++i) {
                if (std::strcmp(text, names[i]) != 0) continue;
                if (slots_[i].address) { error = "Duplicate enumeration import; declining ambiguous hook"; return false; }
                auto address = reinterpret_cast<void**>(base + slotRva);
                if (reinterpret_cast<uintptr_t>(address) % alignof(void*) || !*address) {
                    error = "Unaligned or unresolved import"; return false;
                }
                slots_[i] = {address, *address, nullptr};
            }
        }
    }
    for (const auto& slot : slots_) if (!slot.address) { error = "Required ANSI enumeration import absent"; return false; }
    return true;
}
bool ImportHooks::install(std::array<void*, 3> replacements, std::string& error) {
    // Open all pages before changing any pointer, then atomically compare/exchange.
    // Usually all slots occupy one page; save each distinct page's original mode.
    struct Page { void* address; DWORD protection; };
    std::array<Page, 3> pages{};
    size_t pageCount = 0;
    SYSTEM_INFO system{}; GetSystemInfo(&system);
    const auto restore = [&] {
        for (size_t i = 0; i < pageCount; ++i) {
            DWORD ignored{}; VirtualProtect(pages[i].address, system.dwPageSize, pages[i].protection, &ignored);
        }
    };
    for (size_t i = 0; i < slots_.size(); ++i) {
        if (!slots_[i].address || !replacements[i]) { error = "Hook not prepared"; restore(); return false; }
        auto page = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(slots_[i].address) &
            ~(static_cast<uintptr_t>(system.dwPageSize) - 1));
        bool existing = false;
        for (size_t j = 0; j < pageCount; ++j) if (pages[j].address == page) existing = true;
        if (!existing) {
            MEMORY_BASIC_INFORMATION region{};
            if (VirtualQuery(page, &region, sizeof(region)) != sizeof(region) || region.State != MEM_COMMIT) {
                error = "Import page is not committed"; restore(); return false;
            }
            constexpr DWORD writable = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
            if (region.Protect & writable) continue; // Already writable: nothing to change or restore.
            // Never drop execute permission from a page other threads may be running.
            constexpr DWORD executable = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
            DWORD old{};
            if (!VirtualProtect(page, system.dwPageSize, (region.Protect & executable) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &old)) {
                error = "Cannot make import page writable"; restore(); return false;
            }
            pages[pageCount++] = {page, old};
        }
    }
    // Install next/close before first: no synthetic handle is issued without both.
    constexpr std::array<size_t, 3> order{1, 2, 0};
    size_t installed = 0;
    for (const size_t i : order) {
        auto& slot = slots_[i];
        if (InterlockedCompareExchangePointer(slot.address, replacements[i], slot.original) != slot.original) {
            for (size_t j = 0; j < installed; ++j) {
                auto& prior = slots_[order[j]];
                InterlockedCompareExchangePointer(prior.address, prior.original, prior.replacement);
                prior.replacement = nullptr;
            }
            error = "Another component changed the imports during installation";
            restore(); return false;
        }
        slot.replacement = replacements[i];
        ++installed;
    }
    restore();
    return true;
}
bool ImportHooks::stillInstalled() const noexcept {
    for (const auto& slot : slots_) if (!slot.address || *slot.address != slot.replacement) return false;
    return true;
}
FileApi ImportHooks::originals() const noexcept {
    return {reinterpret_cast<decltype(&FindFirstFileA)>(slots_[0].original),
        reinterpret_cast<decltype(&FindNextFileA)>(slots_[1].original),
        reinterpret_cast<decltype(&FindClose)>(slots_[2].original), &FindFirstFileExA};
}
bool ImportHooks::originalsAreSystemApis() const noexcept {
    for (const auto& slot : slots_) {
        HMODULE owner{};
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(slot.original), &owner)) return false;
        if (owner != GetModuleHandleW(L"kernel32.dll") && owner != GetModuleHandleW(L"KernelBase.dll")) return false;
    }
    return true;
}
}
