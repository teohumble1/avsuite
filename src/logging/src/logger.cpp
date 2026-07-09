#include "avlogging/logger.hpp"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace avlogging {

namespace {
std::shared_ptr<spdlog::logger> g_logger;
}

void Logger::Init(const std::string& log_file_path) {
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    sinks.push_back(std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file_path, /*truncate=*/false));

    g_logger = std::make_shared<spdlog::logger>("avsuite", sinks.begin(), sinks.end());
    g_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    g_logger->set_level(spdlog::level::info);
    g_logger->flush_on(spdlog::level::warn);
    spdlog::register_logger(g_logger);
}

std::shared_ptr<spdlog::logger>& Logger::Get() {
    if (!g_logger) {
        // Fallback so early/test code that forgets to call Init() doesn't crash.
        g_logger = spdlog::stdout_color_mt("avsuite");
    }
    return g_logger;
}

} // namespace avlogging
