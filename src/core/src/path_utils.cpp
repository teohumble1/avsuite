#include "avcore/path_utils.hpp"

#include <algorithm>
#include <array>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace avcore {

std::string ToLowerAscii(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string Basename(const std::string& path) {
    const auto pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

namespace {

std::string ExpandEnv(const std::string& templated) {
    char buffer[MAX_PATH] = {};
    const DWORD len = ExpandEnvironmentStringsA(templated.c_str(), buffer, MAX_PATH);
    if (len == 0 || len > MAX_PATH) return std::string();
    return std::string(buffer);
}

} // namespace

bool IsUnderUserWritableDir(const std::string& path) {
    static const std::array<const char*, 5> kTemplates = {
        "%TEMP%", "%TMP%", "%APPDATA%", "%LOCALAPPDATA%", "%USERPROFILE%\\Downloads",
    };

    const std::string lower_path = ToLowerAscii(path);
    for (const char* tmpl : kTemplates) {
        const std::string expanded = ToLowerAscii(ExpandEnv(tmpl));
        if (!expanded.empty() && lower_path.rfind(expanded, 0) == 0) {
            return true;
        }
    }
    return false;
}

} // namespace avcore
