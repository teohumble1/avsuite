#pragma once

#include <string_view>

namespace avcore {

enum class Severity {
    Info,
    Suspicious,
    Malicious,
};

constexpr std::string_view ToString(Severity s) noexcept {
    switch (s) {
        case Severity::Info: return "Info";
        case Severity::Suspicious: return "Suspicious";
        case Severity::Malicious: return "Malicious";
    }
    return "Unknown";
}

} // namespace avcore
