#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace avbehavior {

// Normalized process-creation event. Produced either by the live ETW consumer
// (avetw) or by synthetic test fixtures -- rules and the process tree only
// ever see this type, never the raw ETW payload.
struct ProcessEvent {
    std::uint32_t process_id = 0;
    std::uint32_t parent_process_id = 0;
    std::string image_path;
    std::string command_line;
    std::chrono::system_clock::time_point start_time = std::chrono::system_clock::now();
};

} // namespace avbehavior
