#pragma once
#include <Windows.h>
#include <array>
#include <string>
#include "DirectoryCache.h"

namespace startup {
// Patch only named imports in the executable. No game offsets or trampolines.
// The captured pointers retain any already-installed virtual filesystem hooks.
class ImportHooks {
public:
    bool inspect(HMODULE executable, std::string& error);
    bool install(std::array<void*, 3> replacements, std::string& error);
    bool stillInstalled() const noexcept;
    FileApi originals() const noexcept;
    bool originalsAreSystemApis() const noexcept;
private:
    struct Slot { void** address{}; void* original{}; void* replacement{}; };
    std::array<Slot, 3> slots_{};
};
}
