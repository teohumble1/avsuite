#pragma once

#include <memory>
#include <string>

#include <spdlog/spdlog.h>

namespace avlogging {

// Thin wrapper so the rest of the codebase depends on this header, not spdlog
// directly -- keeps the logging backend swappable to a single file.
class Logger {
public:
    static void Init(const std::string& log_file_path);
    static std::shared_ptr<spdlog::logger>& Get();
};

} // namespace avlogging

#define AVLOG_INFO(...) ::avlogging::Logger::Get()->info(__VA_ARGS__)
#define AVLOG_WARN(...) ::avlogging::Logger::Get()->warn(__VA_ARGS__)
#define AVLOG_ERROR(...) ::avlogging::Logger::Get()->error(__VA_ARGS__)
#define AVLOG_DEBUG(...) ::avlogging::Logger::Get()->debug(__VA_ARGS__)
