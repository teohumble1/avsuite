#pragma once

#include <cstdint>
#include <string>

namespace avengine {

struct ProcessEvent {
    uint64_t process_id;
    uint64_t parent_process_id;
    uint64_t created_time;  // 100-nanosecond intervals since 1601
    std::wstring image_path;
    std::wstring command_line;
    bool is_32bit;
    bool is_privileged;  // System/Admin level
    bool is_trusted;     // Image signature verified
};

class ProcessMonitor {
public:
    ProcessMonitor();
    ~ProcessMonitor();

    bool Start();
    void Stop();
    bool IsRunning() const;

private:
    bool started_ = false;
};

}  // namespace avengine
