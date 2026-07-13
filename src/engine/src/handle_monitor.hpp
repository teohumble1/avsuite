#pragma once

#include <cstdint>
#include <string>

namespace avengine {

struct HandleOpenEvent {
    uint64_t requesting_process_id;
    uint64_t target_process_id;
    uint32_t desired_access;
    bool is_suspicious;  // PROCESS_VM_READ on lsass.exe = credential dump attempt
};

class HandleMonitor {
public:
    HandleMonitor();
    ~HandleMonitor();

    bool Start();
    void Stop();
    bool IsRunning() const;

private:
    bool started_ = false;
};

}  // namespace avengine
