#pragma once
#include <cstddef>
#include <cstdint>

// Independently declared, minimal binary interface to F4SE. No SDK implementation
// or game structures are compiled into this project.
namespace extender {
struct Info { uint32_t format; const char* name; uint32_t version; };
struct Interface {
    uint32_t extenderVersion, runtimeVersion, editorVersion, editor;
    void* (*query)(uint32_t);
    uint32_t (*pluginHandle)();
    uint32_t (*releaseIndex)();
};
struct Message { const char* sender; uint32_t type, size; void* data; };
struct Messaging {
    uint32_t version;
    bool (*listen)(uint32_t, const char*, void (*)(Message*));
};
struct Version {
    uint32_t format, pluginVersion;
    char name[256], author[256];
    uint32_t addressFlags, structureFlags, runtimes[16], minimumExtender;
    uint32_t reservedNonBreaking, reservedBreaking;
    uint8_t reserved[512];
};
static_assert(offsetof(Version, addressFlags) == 520);
static_assert(sizeof(Version) == 1116);
static_assert(sizeof(Interface) == 40); // F4SEVR exposes only this original prefix.
static_assert(offsetof(Interface, query) == 16);
static_assert(offsetof(Messaging, listen) == 8);
static_assert(sizeof(Message) == 24);
constexpr uint32_t pack(uint32_t major, uint32_t minor, uint32_t build) {
    return (major << 24) | (minor << 16) | (build << 4);
}
}
