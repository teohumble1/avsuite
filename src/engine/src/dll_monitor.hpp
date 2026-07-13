#pragma once

#include <cstdint>
#include <string>

namespace avengine {

struct DllLoadEvent {
    uint64_t loader_process_id;
    std::wstring dll_path;
    uint64_t dll_base;  // Kernel address
    uint64_t image_size;
    bool is_signed;
    bool is_suspicious;  // Unsigned from %TEMP%
};

class DllMonitor {
public:
    DllMonitor();
    ~DllMonitor();

    bool Start();
    void Stop();
    bool IsRunning() const;

private:
    bool started_ = false;
};

}  // namespace avengine
