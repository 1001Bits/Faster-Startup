#pragma once
#include <Windows.h>
#include <string_view>

namespace startup {
// Runtime/plugin output and MO2 Root Builder payloads always enumerate live.
// Apply only at the first Data-relative component, never to nested asset names.
inline bool nativeRoot(std::wstring_view name) noexcept {
    return name.size() == 4 && (CompareStringOrdinal(name.data(), 4, L"F4SE", 4, TRUE) == CSTR_EQUAL ||
        CompareStringOrdinal(name.data(), 4, L"Root", 4, TRUE) == CSTR_EQUAL);
}
inline bool nativeRoot(std::string_view name) noexcept {
    return name.size() == 4 && (_strnicmp(name.data(), "F4SE", 4) == 0 || _strnicmp(name.data(), "Root", 4) == 0);
}
}
