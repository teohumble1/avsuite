#pragma once

#include <string>

namespace avcore {

std::string ToLowerAscii(const std::string& s);
std::string Basename(const std::string& path);

// True if `path` falls under one of the well-known user-writable/drop
// locations (%TEMP%, %TMP%, %APPDATA%, %LOCALAPPDATA%, %USERPROFILE%\Downloads).
// Shared by the behavior engine, registry scanner, and PE analyzer so the
// notion of "suspicious drop location" stays consistent across modules.
bool IsUnderUserWritableDir(const std::string& path);

} // namespace avcore
